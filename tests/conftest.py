"""Shared test fixtures and configuration."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator

import pytest

from overrule import Guard
from overrule import guard as guard_module


@pytest.fixture(autouse=True)
def _release_orphaned_reporters() -> Iterator[None]:
    """Drop reporters rescued from garbage-collected Guards after each test.

    ``Guard`` keeps a *strong* reference to the reporter of any Guard collected
    while it still held buffered events, so the ``atexit`` hook can persist them
    instead of losing them silently. In this suite those buffers are aimed at a
    dead endpoint, so draining them at interpreter exit only writes stderr noise
    long after the session has finished. Tests that care assert on
    ``_orphaned_reporters`` inside their own body.
    """
    yield
    with guard_module._active_guards_lock:
        guard_module._orphaned_reporters.clear()


@pytest.fixture(autouse=True)
def _isolate_reporter_side_effects(tmp_path, monkeypatch) -> Iterator[None]:
    """Give every test its own dead-letter queue and keep the suite off the network.

    Two reasons this is autouse:

    * `EventReporter.stop()` now persists unsent events to disk, and recovers them
      on the next `start()`. With a shared directory, events from one test are
      replayed into the next test's buffer.
    * Without an endpoint override, shutting a reporter down really does POST to
      https://overrule.dev/api, so the suite would depend on the network (and log a
      401 for every test).
    """
    monkeypatch.setenv("OVERRULE_DLQ_DIR", str(tmp_path / "dlq"))
    monkeypatch.setenv("OVERRULE_ENDPOINT", "http://127.0.0.1:1")
    yield


@pytest.fixture
async def make_guard() -> AsyncIterator[Callable[..., Guard]]:
    """Factory for Guards that are always shut down after the test.

    Guards left running leak `EventReporter._flush_loop` tasks, which surfaced as
    "Task was destroyed but it is pending!" noise on every test run.
    """
    created: list[Guard] = []

    def _factory(**kwargs: object) -> Guard:
        guard = Guard(**kwargs)  # type: ignore[arg-type]
        created.append(guard)
        return guard

    yield _factory
    for guard in created:
        await guard.shutdown()
