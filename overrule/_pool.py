"""A fixed-size thread pool whose workers are daemon threads.

Policy code runs off the event loop so a pathological policy cannot block it, and
so the evaluation deadline is real. A Python thread cannot be interrupted, so a
policy that blows its deadline keeps its worker busy until it returns — possibly
forever.

``concurrent.futures.ThreadPoolExecutor`` is unusable for that: its workers are
non-daemon, and *both* ``concurrent.futures``' own ``atexit`` hook and
``threading._shutdown`` join every non-daemon thread at interpreter exit. One
genuinely stuck policy therefore prevented the process from ever exiting, and
``Guard.shutdown()`` could not reclaim the threads of a pool that had already been
retired. Daemon workers make process exit unconditional; a stuck worker is already
accounted for by pool retirement in :meth:`Guard._note_orphaned_policy_run`.
"""

from __future__ import annotations

import contextlib
import logging
import queue
import threading
from collections.abc import Callable
from concurrent.futures import Executor, Future
from typing import Any, Protocol

logger = logging.getLogger("overrule.pool")


class _Completable(Protocol):
    """The bit of the future protocol :class:`PolicyPool` needs.

    Satisfied by both ``asyncio.Future`` (the ``chat``/``stream`` paths) and
    ``concurrent.futures.Future`` (the synchronous LangChain callback).
    """

    def add_done_callback(self, fn: Any, /) -> Any: ...

    def exception(self, *args: Any) -> BaseException | None: ...


class DaemonThreadPool(Executor):
    """Minimal ``Executor`` backed by a bounded set of daemon worker threads.

    Threads are spawned lazily, up to ``max_workers``, and an idle worker is
    reused rather than growing the pool. ``submit`` raises ``RuntimeError`` after
    ``shutdown()``, matching ``ThreadPoolExecutor``.
    """

    def __init__(self, max_workers: int, thread_name_prefix: str = "overrule-worker") -> None:
        if max_workers <= 0:
            raise ValueError("max_workers must be greater than 0")
        self._max_workers = max_workers
        self._name = thread_name_prefix
        self._queue: queue.SimpleQueue[Any] = queue.SimpleQueue()
        self._threads: list[threading.Thread] = []
        self._idle = threading.Semaphore(0)
        self._lock = threading.Lock()
        self._is_shutdown = False

    def submit(self, fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Future[Any]:
        future: Future[Any] = Future()
        with self._lock:
            if self._is_shutdown:
                raise RuntimeError("cannot schedule new futures after shutdown")
            self._queue.put((future, fn, args, kwargs))
            self._ensure_worker()
        return future

    def _ensure_worker(self) -> None:
        """Spawn a worker unless one is idle or the pool is already at capacity."""
        if self._idle.acquire(blocking=False):
            return
        if len(self._threads) >= self._max_workers:
            return
        thread = threading.Thread(
            target=self._worker,
            name=f"{self._name}-{len(self._threads)}",
            daemon=True,
        )
        self._threads.append(thread)
        thread.start()

    def _worker(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:  # shutdown sentinel
                return
            future, fn, args, kwargs = item
            del item
            if future.set_running_or_notify_cancel():
                try:
                    future.set_result(fn(*args, **kwargs))
                except BaseException as exc:  # noqa: BLE001 - mirror stdlib behaviour
                    future.set_exception(exc)
            del future, fn, args, kwargs
            self._idle.release()

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        """Stop accepting work and wake every worker.

        ``wait=False`` returns immediately, which is what makes a retired pool
        holding a stuck policy harmless: its workers are daemons and nothing joins
        them at exit.
        """
        with self._lock:
            if self._is_shutdown:
                return
            self._is_shutdown = True
            threads = list(self._threads)

        if cancel_futures:
            while True:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                if item is not None:
                    item[0].cancel()

        for _ in threads:
            self._queue.put(None)
        if wait:
            for thread in threads:
                thread.join()

    @property
    def worker_count(self) -> int:
        """Number of worker threads this pool has spawned."""
        with self._lock:
            return len(self._threads)


class PolicyPool:
    """Owns the worker pool policies run on, with generation-scoped orphan tracking.

    A policy that blows its deadline cannot be interrupted, so its worker is lost
    for as long as the policy runs. Once every worker of a pool is lost, that pool
    is retired and replaced so evaluation stays available.

    Every run is tagged with the *generation* of the pool it was scheduled against.
    Retirement bumps the generation, so orphans belonging to the retired pool no
    longer count against — or retire — the fresh one. Without that, the
    "all workers stuck" condition stayed satisfied forever and every subsequent
    timeout churned out another whole pool.
    """

    def __init__(
        self, *, max_workers: int = 4, thread_name_prefix: str = "overrule-policy"
    ) -> None:
        self._max_workers = max_workers
        self._name = thread_name_prefix
        self._lock = threading.Lock()
        self._pool: DaemonThreadPool | None = None
        self._generation = 0
        self._orphans = 0

    @property
    def executor(self) -> DaemonThreadPool | None:
        """The live pool, or ``None`` if none has been created or it was retired."""
        with self._lock:
            return self._pool

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    @property
    def orphaned_runs(self) -> int:
        """Runs stuck against the *current* generation."""
        with self._lock:
            return self._orphans

    def acquire(self) -> tuple[Executor, int]:
        """Return ``(pool, generation)``, creating the pool lazily."""
        with self._lock:
            if self._pool is None:
                self._orphans = 0
                self._pool = DaemonThreadPool(
                    max_workers=self._max_workers, thread_name_prefix=self._name
                )
            return self._pool, self._generation

    def note_orphan(self, future: _Completable, generation: int) -> bool:
        """Record a run we can no longer wait for. True if the pool was retired.

        Also arranges for the future's result/exception to be retrieved whenever it
        eventually completes, so it is never reported as an unretrieved exception.
        """

        def _done(completed: _Completable) -> None:
            with self._lock:
                if generation == self._generation:
                    self._orphans = max(0, self._orphans - 1)
            # CancelledError is a BaseException, so suppress broadly here.
            with contextlib.suppress(BaseException):
                completed.exception()

        retiring: DaemonThreadPool | None = None
        stuck = 0
        with self._lock:
            if generation == self._generation:
                self._orphans += 1
                if self._orphans >= self._max_workers and self._pool is not None:
                    retiring = self._pool
                    stuck = self._orphans
                    self._pool = None
                    self._generation += 1
                    self._orphans = 0

        if retiring is not None:
            logger.warning(
                "Retiring policy thread pool: %d worker(s) stuck in policy code. "
                "Its threads are daemons, so they cannot delay interpreter exit.",
                stuck,
            )
            retiring.shutdown(wait=False)
        future.add_done_callback(_done)
        return retiring is not None

    def shutdown(self) -> None:
        """Retire the current pool without waiting for stuck workers."""
        with self._lock:
            pool, self._pool = self._pool, None
            if pool is not None:
                # Bumped so an in-flight orphan cannot be counted against, or retire,
                # a pool created after this shutdown.
                self._generation += 1
                self._orphans = 0
        if pool is not None:
            pool.shutdown(wait=False)
