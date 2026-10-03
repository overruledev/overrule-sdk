"""Guard — the primary interface for the overrule SDK."""

from __future__ import annotations

import asyncio
import atexit
import contextlib
import functools
import inspect
import logging
import threading
import time
import weakref
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import Executor, ThreadPoolExecutor
from typing import TYPE_CHECKING, Any, Literal, TypeVar

from overrule._pool import PolicyPool
from overrule.exceptions import OverruleError, PolicyEvaluationError, ViolationError
from overrule.models.config import GuardConfig, PolicyAction, PolicyConfig
from overrule.models.event import EventStatus, EventType, InterceptEvent
from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies.base import BasePolicy, PolicyResult
from overrule.policies.registry import PolicyRegistry
from overrule.transport.reporter import EventReporter

if TYPE_CHECKING:
    from overrule.stream import StreamGuard

logger = logging.getLogger("overrule.guard")

F = TypeVar("F", bound=Callable[..., Any])

Direction = Literal["input", "output"]

#: Content is scanned in overlapping windows so nothing is left unscanned and no
#: pattern can straddle a window boundary.
#:
#: Measured cost for the three default policies is ~45ms per 100_000 characters of
#: ordinary text, rising to ~85ms when the input is dense in Cyrillic/Greek
#: confusables (which forces an extra normalisation variant). See the benchmark
#: table in README.md for the per-policy breakdown and conditions. This comment
#: said "~40ms" before confusable folding and candidate validation were added; it
#: was measured at 63ms/85ms on a slower reference box, so treat ~45-65ms as the
#: ordinary-text range.
#:
#: Cost is linear in input length (measured x2.01 per doubling), so the worst
#: realistic 1MB payload costs ~0.9s — roughly 6x under the per-policy deadline.
SCAN_CHUNK_SIZE = 100_000
SCAN_OVERLAP = 256


def iter_scan_windows(
    content: str,
    chunk_size: int = SCAN_CHUNK_SIZE,
    overlap: int = SCAN_OVERLAP,
) -> Iterator[tuple[int, str]]:
    """Yield ``(absolute_offset, window)`` pairs covering *all* of ``content``.

    Consecutive windows overlap by ``overlap`` characters so a pattern spanning a
    boundary is still seen whole by at least one window.
    """
    if len(content) <= chunk_size:
        yield 0, content
        return
    step = max(1, chunk_size - overlap)
    start = 0
    total = len(content)
    while start < total:
        yield start, content[start : start + chunk_size]
        if start + chunk_size >= total:
            break
        start += step


class _AttrDict(dict[str, Any]):
    """Dict subclass allowing attribute access for dot-notation convenience."""

    def __getattr__(self, name: str) -> Any:
        try:
            val = self[name]
        except KeyError:
            raise AttributeError(f"No attribute '{name}'") from None
        if isinstance(val, dict):
            return _AttrDict(val)
        if isinstance(val, list):
            return [_AttrDict(v) if isinstance(v, dict) else v for v in val]
        return val


class ChatResponse(_AttrDict):
    """Response from guard.chat() — supports both dict access and attribute access.

    Works with both patterns:
        response["choices"][0]["message"]["content"]
        response.choices[0].message.content

    ``response.violations`` and ``response.flagged`` are *always* present, including
    on the fail-open pass-through path, so callers that check them never silently
    see nothing. On a fail-open pass-through they carry everything that had been
    detected before the failure — not an empty list, which would report content
    already known to contain a violation as clean.
    """


#: Re-entrant on purpose: the weakref callback below acquires this lock and runs
#: at arbitrary garbage-collection points, potentially on a thread that already
#: holds it.
_active_guards_lock = threading.RLock()
_active_guards: list[weakref.ref[Guard]] = []

#: Reporters belonging to Guards that were garbage-collected without ``shutdown()``
#: while they still held buffered events. These are *strong* references: a weakref
#: registry alone meant the most idiomatic usage — a Guard created inside
#: ``async def main()`` and driven by ``asyncio.run(main())`` — was already collected
#: by the time ``atexit`` ran, so its buffered events were dropped with no warning
#: at all, contradicting the promise in ``EventReporter.stop()``.
_orphaned_reporters: list[EventReporter] = []

#: Bound on the above, so a program constructing Guards per request and never
#: shutting them down cannot grow this list without limit.
_MAX_ORPHANED_REPORTERS = 256

_sync_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="overrule-sync")


def _guard_collected(reporter: EventReporter, ref: weakref.ref[Guard]) -> None:
    """Weakref callback: prune the registry, rescuing unsent events if any.

    Runs when a Guard is garbage-collected. Two jobs:

    * drop the dead ref, so ``_active_guards`` does not grow without bound for
      callers that construct a Guard per request (it used to be pruned only inside
      ``shutdown()``);
    * if the guard's reporter still has buffered events, keep a strong reference to
      it so ``_atexit_flush`` can still persist them.
    """
    rescued = False
    dropped = 0
    with _active_guards_lock:
        # Already pruned by shutdown() — nothing to do.
        with contextlib.suppress(ValueError):
            _active_guards.remove(ref)
        try:
            pending = reporter.pending_count
        except Exception:  # pragma: no cover - defensive; never raise from a GC hook
            pending = 0
        if pending > 0:
            if len(_orphaned_reporters) < _MAX_ORPHANED_REPORTERS:
                _orphaned_reporters.append(reporter)
                rescued = True
            else:
                dropped = pending

    # Logged outside the lock: logging can re-enter arbitrary code.
    if rescued:
        logger.debug(
            "Guard garbage-collected without shutdown(); retaining its reporter so "
            "buffered events are flushed at exit"
        )
    elif dropped:
        logger.warning(
            "Guard garbage-collected without shutdown() with %d unsent event(s), and "
            "more than %d such reporters are already pending — these events are lost. "
            "Call `await guard.shutdown()` (or use `async with Guard(...)`).",
            dropped,
            _MAX_ORPHANED_REPORTERS,
        )


def _drain_reporter(reporter: EventReporter) -> None:
    """Run ``reporter.stop()`` on a throwaway loop. Never raises."""
    try:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(reporter.stop())
        finally:
            loop.close()
    except Exception as exc:
        logger.warning("atexit flush failed, some events may be lost: %s", exc)


def _atexit_flush() -> None:
    """Flush every live and orphaned reporter on process exit."""
    with _active_guards_lock:
        guards = [ref() for ref in _active_guards]
        orphans = list(_orphaned_reporters)
        _orphaned_reporters.clear()

    reporters: list[EventReporter] = [
        guard._reporter for guard in guards if guard is not None and guard._initialized
    ]
    for reporter in orphans:
        if reporter not in reporters:
            reporters.append(reporter)

    for reporter in reporters:
        _drain_reporter(reporter)


atexit.register(_atexit_flush)


class Guard:
    """Runtime AI governance guard.

    Intercepts LLM calls and tool executions, evaluates them against
    configured policies, and reports telemetry to the cloud platform.

    The SDK operates in fail-open mode by default: if an internal error
    occurs during policy evaluation or reporting, the operation proceeds
    unguarded rather than crashing the host application. Fail-open
    pass-throughs are reported as ``EventStatus.FAIL_OPEN`` events so the
    bypass is observable rather than silent.

    Usage:
        guard = Guard(api_key="sk-...")

        # As a context manager
        async with Guard(api_key="sk-...") as guard:
            response = await guard.chat(...)

        # Wrap an LLM call
        response = await guard.chat(
            model="gpt-4",
            messages=[{"role": "user", "content": "..."}],
            policies=["pii-detection", "injection-detection"],
        )

        # Protect a tool/function
        @guard.protect(policies=["injection-detection"])
        def query_database(sql: str) -> str:
            return db.execute(sql)
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        endpoint: str | None = None,
        default_policies: list[str] | None = None,
        default_action: PolicyAction | None = None,
        fail_open: bool | None = None,
        config: GuardConfig | None = None,
    ) -> None:
        self._config = config or GuardConfig.from_env(
            api_key=api_key,
            endpoint=endpoint,
            default_action=default_action,
            fail_open=fail_open,
        )
        self._registry = PolicyRegistry()
        self._reporter = EventReporter(
            endpoint=self._config.endpoint,
            api_key=self._config.api_key,
            batch_size=self._config.batch_size,
            flush_interval=self._config.flush_interval_seconds,
            max_retries=self._config.max_retries,
            circuit_break_threshold=self._config.circuit_break_threshold,
            circuit_break_cooldown=self._config.circuit_break_cooldown_seconds,
            environment=self._config.environment,
            send_match_preview=self._config.send_match_preview,
        )

        # GuardConfig.policies is honoured: disabled policies never run, per-policy
        # `parameters` reach the policy constructor, and per-policy `action` overrides
        # the global default_action for that policy's violations.
        self._policy_configs: dict[str, PolicyConfig] = {pc.id: pc for pc in self._config.policies}
        requested = default_policies or [
            "pii-detection",
            "injection-detection",
            "jailbreak-detection",
        ]
        self._default_policies = [pid for pid in requested if self._policy_enabled(pid)]
        skipped = [pid for pid in requested if pid not in self._default_policies]
        if skipped:
            logger.info("Policies disabled by configuration: %s", ", ".join(skipped))

        self._initialized = False
        self._init_lock = asyncio.Lock()
        self._openai_client: Any = None
        self._anthropic_client: Any = None

        # Bounded pool of *daemon* workers used to run policy evaluation off the event
        # loop so a pathological policy cannot block it (and so timeouts are real).
        self._pool = PolicyPool(
            max_workers=self._POLICY_POOL_WORKERS, thread_name_prefix="overrule-policy"
        )

        # The callback keeps a strong reference to the reporter only (never to the
        # guard), so it can both prune this registry and rescue unsent events.
        with _active_guards_lock:
            _active_guards.append(
                weakref.ref(self, functools.partial(_guard_collected, self._reporter))
            )

    # ─── Lifecycle ─────────────────────────────────────────────────────

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        async with self._init_lock:
            if not self._initialized:
                await self._reporter.start()
                self._initialized = True

    async def shutdown(self) -> None:
        """Gracefully shut down the guard, flushing pending events."""
        await self._reporter.stop()
        self._initialized = False
        if self._openai_client:
            await self._openai_client.close()
            self._openai_client = None
        if self._anthropic_client:
            await self._anthropic_client.close()
            self._anthropic_client = None
        self._pool.shutdown()
        with _active_guards_lock:
            _active_guards[:] = [r for r in _active_guards if r() is not None and r() is not self]
            # Already drained above; nothing left for the atexit hook to rescue.
            if self._reporter in _orphaned_reporters:
                _orphaned_reporters.remove(self._reporter)

    async def __aenter__(self) -> Guard:
        await self._ensure_initialized()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.shutdown()

    # ─── Public API ────────────────────────────────────────────────────

    def register_policy(self, policy_cls: type[BasePolicy]) -> None:
        """Register a custom policy implementation."""
        self._registry.register(policy_cls)

    def unregister_policy(self, policy_id: str) -> None:
        """Remove a registered policy by ID."""
        self._registry.unregister(policy_id)

    def reload_policies(self, policy_id: str | None = None) -> None:
        """Hot-reload policy instances without restarting the guard.

        If policy_id is given, only that policy is re-instantiated.
        If None, all cached instances are cleared and recreated on next use.
        Useful for updating policy parameters at runtime.
        """
        self._registry.reload(policy_id)

    async def evaluate(
        self,
        content: str,
        *,
        policies: list[str] | None = None,
        direction: Direction = "input",
    ) -> PolicyResult:
        """Evaluate content against policies without making an LLM call.

        Useful for standalone content checking (e.g., user input validation).
        The full content is scanned; ``max_content_length`` only caps what is
        stored on the reported event.
        """
        await self._ensure_initialized()
        active_policies = self._active_policies(policies)
        start = time.perf_counter()
        degraded: list[str] = []
        result = await self._evaluate_content(
            content, active_policies, direction=direction, degraded=degraded
        )

        status = (
            EventStatus.BLOCKED
            if self._should_block(result.violations)
            else (EventStatus.FLAGGED if result.violations else EventStatus.PASSED)
        )
        self._safe_report(
            event_type=EventType.LLM_CALL,
            status=status,
            input_content=self._truncate(content),
            policies_applied=active_policies,
            violations=result.violations,
            latency_ms=(time.perf_counter() - start) * 1000,
            metadata=self._degraded_metadata(degraded),
        )
        return result

    # ─── LLM Call Interception ─────────────────────────────────────────

    async def chat(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        policies: list[str] | None = None,
        provider: str = "openai",
        **kwargs: Any,
    ) -> ChatResponse:
        """Intercept and govern an LLM chat completion call.

        Evaluates input against policies before sending, evaluates output
        after receiving. Blocks or logs based on configured action.
        """
        await self._ensure_initialized()
        active_policies = self._active_policies(policies)
        start = time.perf_counter()

        # Validate input
        if not model:
            raise ValueError("model must be a non-empty string")
        if not messages:
            raise ValueError("messages must be a non-empty list")

        # Records whether the provider was already called, so the fail-open path
        # never bills the customer twice nor swaps an already-scanned response for
        # an unscanned one. ``violations`` accumulates everything detected before the
        # failure, so a fail-open pass-through reports what it found instead of
        # claiming `flagged=False`.
        call_state: dict[str, Any] = {"called": False, "response": None, "violations": []}

        try:
            return await self._guarded_chat(
                model=model,
                messages=messages,
                policies=active_policies,
                provider=provider,
                start=start,
                call_state=call_state,
                **kwargs,
            )
        except ViolationError:
            raise
        except OverruleError:
            raise
        except Exception as exc:
            if not self._config.fail_open:
                raise OverruleError(f"Internal SDK error: {exc}") from exc

            logger.error("Evaluation failed, passing through unguarded: %s", exc)
            self._safe_report(
                event_type=EventType.LLM_CALL,
                status=EventStatus.FAIL_OPEN,
                model=model,
                provider=provider,
                policies_applied=active_policies,
                latency_ms=(time.perf_counter() - start) * 1000,
                violations=list(call_state["violations"]),
                metadata={
                    "fail_open_reason": type(exc).__name__,
                    "fail_open_detail": str(exc)[:500],
                    "llm_called": call_state["called"],
                },
            )
            if call_state["called"]:
                # Already paid for (and already scanned) — never call the LLM twice.
                # Violations found before the failure are surfaced: reporting
                # `flagged=False` here would tell the caller the content was clean
                # when a card had already been detected in it.
                return self._as_chat_response(call_state["response"], call_state["violations"])
            response = await self._call_llm(
                model=model, messages=messages, provider=provider, **kwargs
            )
            return self._as_chat_response(response, call_state["violations"])

    async def _guarded_chat(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        policies: list[str],
        provider: str,
        start: float,
        call_state: dict[str, Any],
        **kwargs: Any,
    ) -> ChatResponse:
        """Core chat logic wrapped by fail-open handler."""
        degraded: list[str] = []
        input_content = self._extract_input_checked(messages)
        input_result = await self._evaluate_content(
            input_content, policies, direction="input", degraded=degraded
        )
        # Published as soon as they are known so a failure in any later step still
        # reports them rather than returning an empty violations list.
        call_state["violations"] = list(input_result.violations)

        if self._should_block(input_result.violations):
            # Enforcement is committed *before* telemetry is attempted: a reporter
            # failure must never turn a block into an unguarded pass-through.
            error = ViolationError(input_result.violations)
            self._safe_report(
                event_type=EventType.LLM_CALL,
                status=EventStatus.BLOCKED,
                input_content=self._truncate(input_content),
                model=model,
                provider=provider,
                policies_applied=policies,
                violations=input_result.violations,
                latency_ms=(time.perf_counter() - start) * 1000,
                metadata=self._degraded_metadata(degraded),
            )
            raise error

        response = await self._call_llm(model=model, messages=messages, provider=provider, **kwargs)
        call_state["called"] = True
        call_state["response"] = response

        output_parts = self._extract_output_parts(response)
        output_content = "\n".join(output_parts)
        output_result = await self._evaluate_content(
            output_content, policies, direction="output", degraded=degraded
        )

        all_violations = input_result.violations + output_result.violations
        call_state["violations"] = list(all_violations)

        # BLOCK is checked before REDACT: a violation that demands blocking
        # (e.g. prompt injection in the output) must not be quietly redacted.
        if self._should_block(output_result.violations):
            status = EventStatus.BLOCKED
        elif output_result.violations and self._should_redact(output_result.violations):
            status = EventStatus.FLAGGED
            # Only the violations whose *own* effective action is REDACT. Handing the
            # whole list over meant one REDACT policy silently redacted the matches of
            # every other policy, including ones explicitly configured to only LOG.
            to_redact = self._redactable(output_result.violations)
            redacted_parts = [self._apply_redaction(part, to_redact) for part in output_parts]
            response = self._replace_output(response, redacted_parts)
        elif all_violations:
            status = EventStatus.FLAGGED
        else:
            status = EventStatus.PASSED

        usage = self._extract_usage(response)
        latency_ms = (time.perf_counter() - start) * 1000

        if status == EventStatus.BLOCKED:
            error = ViolationError(output_result.violations)
            self._safe_report(
                event_type=EventType.LLM_CALL,
                status=status,
                input_content=self._truncate(input_content),
                output_content=self._truncate(output_content),
                model=model,
                provider=provider,
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                policies_applied=policies,
                violations=all_violations,
                latency_ms=latency_ms,
                metadata=self._degraded_metadata(degraded),
            )
            raise error

        self._safe_report(
            event_type=EventType.LLM_CALL,
            status=status,
            input_content=self._truncate(input_content),
            output_content=self._truncate(output_content),
            model=model,
            provider=provider,
            input_tokens=usage["input_tokens"],
            output_tokens=usage["output_tokens"],
            policies_applied=policies,
            violations=all_violations,
            latency_ms=latency_ms,
            metadata=self._degraded_metadata(degraded),
        )

        return self._as_chat_response(response, all_violations)

    # ─── Streaming Interception ─────────────────────────────────────────

    async def stream(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        policies: list[str] | None = None,
        provider: str = "openai",
        eval_interval: int = 10,
        **kwargs: Any,
    ) -> StreamGuard:
        """Intercept a streaming LLM call with token-by-token policy evaluation.

        Evaluates input policies before streaming starts. Output policies are
        evaluated incrementally (every `eval_interval` chunks) and at completion.
        A trailing window of characters is withheld from the caller so detection
        can still act on text that has not been emitted yet.

        Returns a StreamGuard async iterator that yields text chunks.

        REDACT is not supported while streaming (a token cannot be recalled once
        yielded) and raises ValueError — use non-streaming ``chat()`` instead.

        Usage:
            async with Guard() as guard:
                stream = await guard.stream(
                    model="gpt-4o",
                    messages=[{"role": "user", "content": "..."}],
                    policies=["pii-detection", "toxicity-detection"],
                )
                async for chunk in stream:
                    print(chunk, end="", flush=True)
        """
        from overrule.stream import StreamGuard

        if not model:
            raise ValueError("model must be a non-empty string")
        if not messages:
            raise ValueError("messages must be a non-empty list")

        await self._ensure_initialized()
        # Filtered here as well as in StreamGuard: a policy disabled in config must not
        # be evaluated, reported as applied, or veto the stream in the REDACT check below.
        active_policies = self._active_policies(policies)

        redact_policies = [
            pid for pid in active_policies if self._effective_action(pid) == PolicyAction.REDACT
        ]
        if redact_policies:
            raise ValueError(
                "PolicyAction.REDACT is not supported with stream(): tokens cannot be "
                "recalled once yielded, so redaction cannot be guaranteed. Use "
                f"guard.chat() for {redact_policies}, or configure BLOCK/WARN/LOG."
            )

        start = time.perf_counter()

        degraded: list[str] = []
        input_content = self._extract_input_checked(messages)
        input_result = await self._evaluate_content(
            input_content, active_policies, direction="input", degraded=degraded
        )

        if self._should_block(input_result.violations):
            error = ViolationError(input_result.violations)
            self._safe_report(
                event_type=EventType.LLM_CALL,
                status=EventStatus.BLOCKED,
                input_content=self._truncate(input_content),
                model=model,
                provider=provider,
                policies_applied=active_policies,
                violations=input_result.violations,
                latency_ms=(time.perf_counter() - start) * 1000,
                metadata={"streaming": True, **self._degraded_metadata(degraded)},
            )
            raise error

        raw_stream = await self._call_llm_stream(
            model=model, messages=messages, provider=provider, **kwargs
        )

        return StreamGuard(
            raw_stream=raw_stream,
            input_content=self._truncate(input_content),
            policies=active_policies,
            registry=self._registry,
            reporter=self._reporter,
            config_action=self._config.default_action,
            model=model,
            provider=provider,
            fail_open=self._config.fail_open,
            eval_interval=eval_interval,
            start_time=start,
            policy_params={
                pid: dict(self._policy_configs[pid].parameters)
                for pid in active_policies
                if pid in self._policy_configs and self._policy_configs[pid].parameters
            },
            policy_configs={
                pid: self._policy_configs[pid]
                for pid in active_policies
                if pid in self._policy_configs
            },
            max_content_length=self._config.max_content_length,
            # The *provider* is passed, not a pool: a cached executor became stale the
            # moment a pool was retired or the guard was shut down, and the next
            # streamed chunk raised "cannot schedule new futures after shutdown".
            pool_provider=self.acquire_policy_pool,
            on_orphaned_run=self._note_orphaned_policy_run,
            policy_timeout_ms=self._POLICY_TIMEOUT_MS,
        )

    # ─── Tool Call Protection ──────────────────────────────────────────

    def protect(
        self,
        *,
        policies: list[str] | None = None,
        action: PolicyAction | None = None,
    ) -> Callable[[F], F]:
        """Decorator to protect a function/tool call with governance policies.

        Usage:
            @guard.protect(policies=["injection-detection"])
            def query_database(sql: str) -> str:
                return db.execute(sql)
        """
        active_policies = self._active_policies(policies)
        effective_action = action or self._config.default_action

        def decorator(func: F) -> F:
            if inspect.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    await self._ensure_initialized()
                    return await self._execute_protected(
                        func, active_policies, effective_action, args, kwargs, is_async=True
                    )

                return async_wrapper  # type: ignore[return-value]

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None

                coro = self._execute_protected(
                    func,
                    active_policies,
                    effective_action,
                    args,
                    kwargs,
                    is_async=False,
                )

                if loop is not None and loop.is_running():
                    future = _sync_executor.submit(asyncio.run, coro)
                    return future.result()
                return asyncio.run(coro)

            return sync_wrapper  # type: ignore[return-value]

        return decorator

    async def _execute_protected(
        self,
        func: Callable[..., Any],
        policy_ids: list[str],
        action: PolicyAction,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        is_async: bool,
    ) -> Any:
        """Execute a protected function with policy evaluation."""
        await self._ensure_initialized()
        start = time.perf_counter()
        content = self._serialize_args(args, kwargs)

        degraded: list[str] = []
        try:
            result = await self._evaluate_content(
                content, policy_ids, direction="input", degraded=degraded
            )
        except Exception as exc:
            if self._config.fail_open:
                logger.error("Policy evaluation failed in protect(): %s", exc)
                self._safe_report(
                    event_type=EventType.TOOL_CALL,
                    status=EventStatus.FAIL_OPEN,
                    input_content=self._truncate(content),
                    policies_applied=policy_ids,
                    latency_ms=(time.perf_counter() - start) * 1000,
                    metadata={
                        "function": func.__name__,
                        "fail_open_reason": type(exc).__name__,
                        "fail_open_detail": str(exc)[:500],
                    },
                )
                if is_async:
                    return await func(*args, **kwargs)
                return func(*args, **kwargs)
            raise

        # A violation carrying blocked=True (prompt injection, SQL injection, …)
        # blocks regardless of the decorator's action, as documented.
        blocking = self._should_block(result.violations) or (
            action == PolicyAction.BLOCK and bool(result.violations)
        )
        if blocking:
            error = ViolationError(result.violations)
            self._safe_report(
                event_type=EventType.TOOL_CALL,
                status=EventStatus.BLOCKED,
                input_content=self._truncate(content),
                policies_applied=policy_ids,
                violations=result.violations,
                latency_ms=(time.perf_counter() - start) * 1000,
                metadata={"function": func.__name__, **self._degraded_metadata(degraded)},
            )
            raise error

        if is_async:
            output = await func(*args, **kwargs)
        else:
            output = func(*args, **kwargs)

        latency_ms = (time.perf_counter() - start) * 1000
        status = EventStatus.FLAGGED if result.violations else EventStatus.PASSED
        self._safe_report(
            event_type=EventType.TOOL_CALL,
            status=status,
            input_content=self._truncate(content),
            output_content=self._truncate(str(output)) if output is not None else None,
            policies_applied=policy_ids,
            violations=result.violations,
            latency_ms=latency_ms,
            metadata={"function": func.__name__, **self._degraded_metadata(degraded)},
        )
        return output

    # ─── Internal Methods ──────────────────────────────────────────────

    _POLICY_TIMEOUT_MS = 5000
    _POLICY_POOL_WORKERS = 4

    def acquire_policy_pool(self) -> tuple[Executor, int]:
        """Return ``(pool, generation)``, creating the pool lazily.

        The generation number identifies *which* pool a run was scheduled against;
        see :class:`overrule._pool.PolicyPool`.
        """
        return self._pool.acquire()

    def _get_policy_pool(self) -> Executor:
        """The bounded pool policies are evaluated on, creating it lazily."""
        return self._pool.acquire()[0]

    @property
    def _policy_pool(self) -> Executor | None:
        """The live policy pool, or None when none exists (or it was retired)."""
        return self._pool.executor

    @property
    def _policy_pool_generation(self) -> int:
        return self._pool.generation

    @property
    def _orphaned_policy_runs(self) -> int:
        return self._pool.orphaned_runs

    def _note_orphaned_policy_run(self, future: asyncio.Future[Any], generation: int) -> None:
        """Track a timed-out policy thread we can no longer wait for.

        A Python thread cannot be interrupted, so a policy that blew its deadline
        keeps burning a worker until it returns. Once every worker of a given pool
        is stuck, that pool is retired and replaced, keeping evaluation available.
        """
        self._pool.note_orphan(future, generation)

    async def _run_policy(
        self, policy: BasePolicy, content: str, direction: Direction
    ) -> PolicyResult:
        """Run one policy off the event loop under a real wall-clock deadline.

        ``asyncio.wait`` is used rather than ``asyncio.wait_for`` on purpose: a
        thread already executing cannot be cancelled, and ``wait_for`` would block
        until it finished — which is exactly the bug this replaces.
        """
        loop = asyncio.get_running_loop()
        call = functools.partial(policy.evaluate, content, direction=direction)
        pool, generation = self.acquire_policy_pool()
        future = loop.run_in_executor(pool, call)
        done, _pending = await asyncio.wait({future}, timeout=self._POLICY_TIMEOUT_MS / 1000)
        if future in done:
            return future.result()
        self._note_orphaned_policy_run(future, generation)
        raise TimeoutError(
            f"Policy '{policy.policy_id}' exceeded its {self._POLICY_TIMEOUT_MS}ms budget"
        )

    def _resolve_policies(self, policy_ids: Sequence[str]) -> list[BasePolicy]:
        """Resolve policy IDs to instances, dropping ones disabled by config.

        Per-policy ``parameters`` from :class:`GuardConfig` are passed through to
        the policy constructor.
        """
        resolved: list[BasePolicy] = []
        for pid in policy_ids:
            if not self._policy_enabled(pid):
                logger.debug("Skipping policy '%s': disabled by configuration", pid)
                continue
            cfg = self._policy_configs.get(pid)
            parameters = dict(cfg.parameters) if cfg and cfg.parameters else None
            resolved.append(self._registry.get(pid, parameters))
        return resolved

    async def _evaluate_content(
        self,
        content: str,
        policy_ids: Sequence[str],
        *,
        direction: Direction,
        degraded: list[str] | None = None,
    ) -> PolicyResult:
        """Run all specified policies against the *whole* of ``content``.

        Content is scanned in overlapping windows (``SCAN_CHUNK_SIZE`` with
        ``SCAN_OVERLAP`` characters of overlap) and the per-window violations are
        unioned and de-duplicated. Nothing is sampled or skipped: a payload of any
        size is scanned end to end at a measured cost of roughly 45ms per 100_000
        characters of ordinary text (~85ms for confusable-dense input), scaling
        linearly with length.

        De-duplication keys on ``(policy_id, raw_match, offset)`` when the match's
        offset within the window is known. When it is not — the match came from a
        normalisation variant and so is not present verbatim in the window — an
        occurrence ordinal is used instead. Keying purely on the offset there meant
        every violation in the window shared ``offset == base``, collided, and
        collapsed to a single reported violation per 100_000 characters.

        Each policy runs on a bounded thread pool under a real deadline, so a
        catastrophically backtracking pattern can neither block the event loop nor
        skip the remaining policies. A policy that blows its deadline (or crashes)
        under ``fail_open=True`` is skipped and its ID is appended to ``degraded``,
        so callers can record on the event that this content was only partially
        evaluated rather than reporting it as cleanly passed.

        Per-policy ``severity_override`` from :class:`GuardConfig` is applied to every
        violation as it is collected; the policy's own severity is retained as
        ``metadata["original_severity"]``.
        """
        all_violations: list[Violation] = []
        total_time = 0.0
        seen: set[tuple[str, str, int, int]] = set()
        #: Running count, across *all* windows, of matches whose offset could not be
        #: located. Must not reset per window, or window 2's ordinals would collide
        #: with window 1's and be discarded as duplicates.
        unlocated: dict[tuple[str, str], int] = {}
        multi_window = len(content) > SCAN_CHUNK_SIZE

        policies = self._resolve_policies(policy_ids)
        for policy in policies:
            override = self._severity_override(policy.policy_id)
            for base, window in iter_scan_windows(content):
                try:
                    result = await self._run_policy(policy, window, direction)
                except TimeoutError as exc:
                    if not self._config.fail_open:
                        raise PolicyEvaluationError(policy.policy_id, exc) from exc
                    logger.warning(
                        "Policy '%s' timed out (%s) — skipping it and continuing; "
                        "this content was NOT fully evaluated",
                        policy.policy_id,
                        exc,
                    )
                    if degraded is not None:
                        degraded.append(policy.policy_id)
                    break
                except (ViolationError, OverruleError):
                    raise
                except Exception as exc:
                    if not self._config.fail_open:
                        raise PolicyEvaluationError(policy.policy_id, exc) from exc
                    logger.error("Policy '%s' crashed: %s", policy.policy_id, exc)
                    if degraded is not None:
                        degraded.append(policy.policy_id)
                    break

                total_time += result.execution_time_ms
                occurrences: dict[tuple[str, str], int] = {}
                for violation in result.violations:
                    violation.metadata["direction"] = direction
                    self.apply_severity_override(violation, override)
                    offset, located = self._locate_match(violation, window, base, occurrences)
                    violation.metadata["offset"] = offset
                    if multi_window:
                        raw = self._raw_match(violation)
                        if not raw:
                            key = (violation.policy_id, violation.message, -1, 0)
                        elif located:
                            key = (violation.policy_id, raw, offset, 0)
                        else:
                            # No usable offset (the match came from a normalisation
                            # variant, so it is not present verbatim in this window).
                            # An ordinal keeps distinct occurrences distinct; without
                            # it every violation in the window shared `offset == base`
                            # and all but the first were discarded as duplicates.
                            # Cross-window de-duplication is approximate in this case:
                            # an occurrence sitting in the SCAN_OVERLAP region may be
                            # counted twice, which is a far smaller error than
                            # reporting one violation per 100_000 characters.
                            ordinal = unlocated.get((violation.policy_id, raw), 0) + 1
                            unlocated[(violation.policy_id, raw)] = ordinal
                            key = (violation.policy_id, raw, -1, ordinal)
                        if key in seen:
                            continue
                        seen.add(key)
                    all_violations.append(violation)

        return PolicyResult(
            passed=len(all_violations) == 0,
            violations=all_violations,
            execution_time_ms=total_time,
        )

    @staticmethod
    def _raw_match(violation: Violation) -> str:
        """The full matched string: ``metadata["raw_match"]``, else matched_content."""
        raw = violation.metadata.get("raw_match")
        if isinstance(raw, str) and raw:
            return raw
        return violation.matched_content or ""

    @classmethod
    def _locate_match(
        cls,
        violation: Violation,
        window: str,
        base: int,
        occurrences: dict[tuple[str, str], int],
    ) -> tuple[int, bool]:
        """``(absolute offset, located)`` for a violation within the full content.

        ``located`` is False when the offset could not actually be determined — the
        match came from a normalisation variant (confusable-folded or zero-width
        stripped) and so is not present verbatim in the window. Callers must not
        treat such an offset as identifying a specific occurrence: every violation in
        the window shares it, which silently collapsed a whole window's findings into
        one when it was used as a de-duplication key.
        """
        reported = violation.metadata.get("offset")
        if isinstance(reported, int) and not isinstance(reported, bool):
            return base + reported, True
        raw = cls._raw_match(violation)
        if not raw:
            return base, False
        key = (violation.policy_id, raw)
        found = window.find(raw, occurrences.get(key, 0))
        if found < 0:
            return base, False
        occurrences[key] = found + 1
        return base + found, True

    @classmethod
    def _absolute_offset(
        cls,
        violation: Violation,
        window: str,
        base: int,
        occurrences: dict[tuple[str, str], int],
    ) -> int:
        """Absolute character offset of a violation within the full content."""
        return cls._locate_match(violation, window, base, occurrences)[0]

    def _policy_enabled(self, policy_id: str) -> bool:
        cfg = self._policy_configs.get(policy_id)
        return True if cfg is None else cfg.enabled

    def _active_policies(self, policies: Sequence[str] | None) -> list[str]:
        """Resolve the requested policy IDs to the ones that will actually run.

        ``_default_policies`` is filtered at init, but an explicit ``policies=[...]``
        from the caller is not — so this is what keeps a policy disabled in config from
        being evaluated *or* reported in ``policies_applied`` on either path.
        """
        return [pid for pid in (policies or self._default_policies) if self._policy_enabled(pid)]

    def _severity_override(self, policy_id: str) -> ViolationSeverity | None:
        """Per-policy ``severity_override`` from config, if one is configured."""
        cfg = self._policy_configs.get(policy_id)
        return None if cfg is None else cfg.severity_override

    @staticmethod
    def apply_severity_override(
        violation: Violation, override: ViolationSeverity | None
    ) -> Violation:
        """Force ``violation.severity`` to ``override``, preserving the original.

        Mutates and returns the violation. The severity the policy itself assigned is
        kept as ``metadata["original_severity"]`` so the override is auditable rather
        than silently rewriting history. A no-op when ``override`` is None or already
        matches, so ``original_severity`` only appears where an override really fired.
        """
        if override is None or violation.severity == override:
            return violation
        violation.metadata["original_severity"] = violation.severity.value
        violation.severity = override
        return violation

    def _effective_action(self, policy_id: str) -> PolicyAction:
        """Per-policy action from config, falling back to the global default."""
        cfg = self._policy_configs.get(policy_id)
        return cfg.action if cfg is not None else self._config.default_action

    def _should_block(self, violations: Sequence[Violation]) -> bool:
        """Determine if violations warrant blocking.

        A violation with ``blocked=True`` always blocks (injection, jailbreak),
        regardless of the configured action.
        """
        for violation in violations:
            if violation.blocked:
                return True
            if self._effective_action(violation.policy_id) == PolicyAction.BLOCK:
                return True
        return False

    def _should_redact(self, violations: Sequence[Violation] = ()) -> bool:
        """Check if any of these violations should be redacted rather than logged."""
        if self._config.default_action == PolicyAction.REDACT:
            return True
        return any(self._effective_action(v.policy_id) == PolicyAction.REDACT for v in violations)

    def _redactable(self, violations: Sequence[Violation]) -> list[Violation]:
        """Just the violations whose own effective action is REDACT.

        A policy configured (or defaulted) to LOG/WARN must keep its match intact
        even when a *different* policy on the same response asks for redaction.
        """
        return [v for v in violations if self._effective_action(v.policy_id) == PolicyAction.REDACT]

    @classmethod
    def _apply_redaction(cls, content: str, violations: Sequence[Violation]) -> str:
        """Replace matched violation content with redaction tokens in the output.

        Uses ``metadata["raw_match"]`` (the full, untruncated match) when present,
        because ``matched_content`` may be masked for safe logging or clipped to a
        fixed length — redacting only the clipped prefix would leave the tail of a
        long match in the response. Every occurrence is replaced, not just the first.
        """
        redacted = content
        for violation in violations:
            raw = cls._raw_match(violation)
            if raw and raw in redacted:
                token = f"[{violation.policy_id.upper().replace('-', '_')}]"
                redacted = redacted.replace(raw, token)
        return redacted

    def _truncate(self, content: str) -> str:
        """Clip content for storage/reporting only.

        This is *not* a limit on what gets scanned — ``_evaluate_content`` always
        scans the full payload in overlapping windows. Sampling head/middle/tail
        (as this used to do) left the rest of a large payload unscanned and was
        trivially evadable.
        """
        max_len = self._config.max_content_length
        if len(content) <= max_len:
            return content
        logger.debug(
            "Content clipped from %d to %d chars for reporting (all %d were scanned)",
            len(content),
            max_len,
            len(content),
        )
        return content[:max_len]

    @staticmethod
    def _degraded_metadata(degraded: Sequence[str]) -> dict[str, Any]:
        """Event metadata recording policies that could not be fully evaluated.

        Without this, a policy skipped after blowing its deadline would leave an
        event indistinguishable from one that genuinely passed.
        """
        if not degraded:
            return {}
        return {"degraded_policies": sorted(set(degraded))}

    def _safe_report(self, **event_fields: Any) -> None:
        """Build and enqueue a telemetry event. Never raises.

        Telemetry is strictly observational: a failure to build or enqueue an event
        must never alter enforcement, so every failure is logged and swallowed here.
        """
        try:
            self._reporter.enqueue(self._build_event(**event_fields))
        except Exception as exc:
            logger.error("Failed to record governance event (ignored): %s", exc)

    @staticmethod
    def _as_chat_response(
        response: Any, violations: Sequence[Violation] | None = None
    ) -> ChatResponse:
        """Wrap a provider response so `.violations`/`.flagged` always exist."""
        chat_response = ChatResponse(response if isinstance(response, dict) else {})
        chat_response["violations"] = list(violations or [])
        chat_response["flagged"] = bool(violations)
        return chat_response

    @staticmethod
    def _replace_output(
        response: dict[str, Any], new_content: str | Sequence[str]
    ) -> dict[str, Any]:
        """Return a copy of the response with assistant content replaced.

        Every choice is replaced — with ``n>1`` the extra choices used to be left
        un-redacted. A sequence replaces choices positionally; a single string
        replaces all of them.
        """
        import copy

        modified = copy.deepcopy(response)
        choices = modified.get("choices", [])
        if not isinstance(choices, list):
            return modified
        for index, choice in enumerate(choices):
            if not isinstance(choice, dict):
                continue
            message = choice.get("message", {})
            if not isinstance(message, dict):
                continue
            if isinstance(new_content, str):
                message["content"] = new_content
            elif index < len(new_content):
                message["content"] = new_content[index]
        return modified

    # Keys that carry evaluable text (or nest it), in the order we walk them.
    _TEXT_KEYS: tuple[str, ...] = (
        "content",
        "text",
        "arguments",
        "input",
        "tool_calls",
        "function",
        "parts",
        "output",
        "output_text",
        "result",
        "message",
        "messages",
        "value",
    )
    # Structural/metadata keys that never contain user text worth scanning.
    _SKIP_KEYS: frozenset[str] = frozenset(
        {
            "role",
            "type",
            "id",
            "name",
            "index",
            "tool_use_id",
            "tool_call_id",
            "model",
            "cache_control",
            "source",
            "annotations",
            "refusal",
            "finish_reason",
            "logprobs",
            "created",
            "object",
            "usage",
            "status",
            "is_error",
        }
    )
    _MAX_EXTRACT_DEPTH = 8

    @classmethod
    def _extract_input(cls, messages: Sequence[Any]) -> str:
        """Extract every piece of evaluable text from chat messages.

        Deliberately permissive: silently extracting nothing means nothing is
        scanned and the request is reported as ``passed``. Handles plain strings,
        OpenAI multimodal blocks, OpenAI Responses ``input_text`` blocks, Anthropic
        ``tool_result``/``tool_use`` blocks with nested content, blocks with no
        ``type`` key, dict-valued ``content``, tool call arguments, and arbitrary
        message objects.
        """
        parts: list[str] = []
        seen: dict[int, Any] = {}
        for msg in messages:
            cls._collect_text(msg, parts, 0, seen)
        return "\n".join(part for part in parts if part)

    @classmethod
    def _collect_text(cls, node: Any, parts: list[str], depth: int, seen: dict[int, Any]) -> None:
        """Recursively collect text from an arbitrarily shaped message node."""
        if node is None or depth > cls._MAX_EXTRACT_DEPTH:
            return
        if isinstance(node, str):
            if node:
                parts.append(node)
            return
        if isinstance(node, bool):
            return
        if isinstance(node, (int, float)):
            parts.append(str(node))
            return
        if isinstance(node, bytes):
            parts.append(node.decode("utf-8", errors="replace"))
            return

        # Cycle guard. ``seen`` maps id -> node rather than being a set of ids: it
        # must hold a *strong reference* to every node it has recorded. A temporary
        # (e.g. the fresh dict returned by ``model_dump()``) is freed as soon as the
        # recursive call returns, and CPython promptly hands the same address to the
        # next allocation — so an id-only set reported the second message as "already
        # seen" and silently dropped every message after the first.
        identity = id(node)
        if identity in seen:
            return
        seen[identity] = node

        if isinstance(node, (list, tuple, set)):
            for item in node:
                cls._collect_text(item, parts, depth + 1, seen)
            return

        if isinstance(node, dict):
            recognised = [key for key in cls._TEXT_KEYS if key in node]
            if recognised:
                for key in recognised:
                    cls._collect_text(node[key], parts, depth + 1, seen)
            else:
                # Unrecognised block (e.g. parsed tool arguments): walk the values.
                for key, value in node.items():
                    if key in cls._SKIP_KEYS:
                        continue
                    cls._collect_text(value, parts, depth + 1, seen)
            return

        # Arbitrary objects: pydantic models, LangChain messages, dataclasses…
        dump = getattr(node, "model_dump", None)
        if callable(dump):
            try:
                cls._collect_text(dump(), parts, depth + 1, seen)
                return
            except Exception:  # noqa: S110 - fall through to str()
                pass
        content = getattr(node, "content", None)
        if content is not None:
            cls._collect_text(content, parts, depth + 1, seen)
            tool_calls = getattr(node, "tool_calls", None)
            if tool_calls is not None:
                cls._collect_text(tool_calls, parts, depth + 1, seen)
            return
        parts.append(str(node))

    def _extract_input_checked(self, messages: Sequence[Any]) -> str:
        """Extract input text, refusing to silently scan nothing.

        If messages were supplied but no text could be extracted, the shape is
        logged so the gap can be fixed, and with ``fail_open=False`` the call is
        failed rather than reported as ``passed``.
        """
        content = self._extract_input(messages)
        if messages and not content.strip():
            shapes = ", ".join(sorted({self._describe_shape(m) for m in messages}))
            logger.warning(
                "Extracted no evaluable text from %d message(s) — nothing was scanned. "
                "Unrecognised message shape(s): %s",
                len(messages),
                shapes,
            )
            if not self._config.fail_open:
                raise PolicyEvaluationError(
                    "input-extraction",
                    ValueError(f"No evaluable text in messages; shapes: {shapes}"),
                )
        return content

    @staticmethod
    def _describe_shape(message: Any) -> str:
        """Describe a message's structure (keys/types only, never its content)."""
        if isinstance(message, dict):
            return f"dict(keys={sorted(str(k) for k in message)})"
        if isinstance(message, (list, tuple)):
            return f"{type(message).__name__}(len={len(message)})"
        return type(message).__name__

    @classmethod
    def _extract_output_parts(cls, response: Any) -> list[str]:
        """Text of every choice in an LLM response (not just the first)."""
        if not isinstance(response, dict):
            return []
        choices = response.get("choices")
        if not isinstance(choices, list):
            return []
        parts: list[str] = []
        for choice in choices:
            if not isinstance(choice, dict):
                parts.append("")
                continue
            message = choice.get("message", {})
            if not isinstance(message, dict):
                parts.append("")
                continue
            content = message.get("content")
            if isinstance(content, str):
                parts.append(content)
            elif content is None:
                parts.append("")
            else:
                collected: list[str] = []
                cls._collect_text(content, collected, 0, {})
                parts.append("\n".join(collected))
        return parts

    @classmethod
    def _extract_output(cls, response: dict[str, Any]) -> str:
        """Extract text content from an LLM response, across all choices."""
        return "\n".join(cls._extract_output_parts(response))

    @staticmethod
    def _extract_usage(response: dict[str, Any]) -> dict[str, int | None]:
        """Extract token usage from an LLM response.

        ``is not None`` rather than truthiness: a genuine ``0`` token count must
        survive as ``0`` instead of collapsing to null on the wire.
        """
        usage = response.get("usage")
        if not usage or not isinstance(usage, dict):
            return {"input_tokens": None, "output_tokens": None}

        def _pick(*keys: str) -> int | None:
            for key in keys:
                value = usage.get(key)
                if value is not None:
                    return int(value)
            return None

        return {
            "input_tokens": _pick("input_tokens", "prompt_tokens"),
            "output_tokens": _pick("output_tokens", "completion_tokens"),
        }

    @staticmethod
    def _serialize_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
        """Serialize function arguments to a string for policy evaluation.

        Only serializes str/int/float/bool/list/dict primitives.
        Non-primitive objects are represented by their type name to prevent
        accidental leakage of credentials or connection strings via __str__.
        """

        def _safe_repr(obj: Any) -> str:
            if isinstance(obj, (str, int, float, bool)):
                return str(obj)
            if isinstance(obj, (list, tuple)):
                return " ".join(_safe_repr(item) for item in obj)
            if isinstance(obj, dict):
                return " ".join(f"{k}={_safe_repr(v)}" for k, v in obj.items())
            return f"<{type(obj).__name__}>"

        parts = [_safe_repr(a) for a in args]
        parts.extend(f"{k}={_safe_repr(v)}" for k, v in kwargs.items())
        return " ".join(parts)

    @staticmethod
    def _build_event(
        *,
        event_type: EventType,
        status: EventStatus,
        input_content: str | None = None,
        output_content: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        policies_applied: list[str] | None = None,
        violations: list[Violation] | None = None,
        latency_ms: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> InterceptEvent:
        """Construct an intercept event."""
        return InterceptEvent(
            event_type=event_type,
            status=status,
            input_content=input_content,
            output_content=output_content,
            model=model,
            provider=provider,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            policies_applied=list(policies_applied or []),
            violations=list(violations or []),
            latency_ms=latency_ms,
            metadata=metadata or {},
        )

    # ─── LLM Provider Calls ───────────────────────────────────────────

    async def _call_llm(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        provider: str = "openai",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Route LLM call to the appropriate provider."""
        if provider == "openai":
            return await self._call_openai(model=model, messages=messages, **kwargs)
        elif provider == "anthropic":
            return await self._call_anthropic(model=model, messages=messages, **kwargs)
        else:
            raise ValueError(f"Unsupported provider: '{provider}'")

    async def _call_openai(
        self, *, model: str, messages: list[dict[str, str]], **kwargs: Any
    ) -> dict[str, Any]:
        """Execute an OpenAI chat completion with cached client."""
        from openai import AsyncOpenAI

        if self._openai_client is None:
            self._openai_client = AsyncOpenAI()
        response = await self._openai_client.chat.completions.create(
            model=model, messages=messages, **kwargs
        )
        dumped: dict[str, Any] = response.model_dump()
        return dumped

    async def _call_anthropic(
        self, *, model: str, messages: list[dict[str, str]], **kwargs: Any
    ) -> dict[str, Any]:
        """Execute an Anthropic message completion with cached client."""
        from anthropic import AsyncAnthropic

        if self._anthropic_client is None:
            self._anthropic_client = AsyncAnthropic()

        system_msg = next((m["content"] for m in messages if m.get("role") == "system"), None)
        user_messages = [m for m in messages if m.get("role") != "system"]

        response = await self._anthropic_client.messages.create(
            model=model,
            messages=user_messages,
            system=system_msg or "",
            max_tokens=kwargs.get("max_tokens", 4096),
        )
        return {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": response.content[0].text if response.content else "",
                    }
                }
            ],
            "model": response.model,
            "usage": {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
        }

    # ─── Streaming LLM Provider Calls ────────────────────────────────────

    async def _call_llm_stream(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        provider: str = "openai",
        **kwargs: Any,
    ) -> Any:
        """Route streaming LLM call to the appropriate provider."""
        if provider == "openai":
            return await self._call_openai_stream(model=model, messages=messages, **kwargs)
        elif provider == "anthropic":
            return await self._call_anthropic_stream(model=model, messages=messages, **kwargs)
        else:
            raise ValueError(f"Unsupported provider: '{provider}'")

    async def _call_openai_stream(
        self, *, model: str, messages: list[dict[str, str]], **kwargs: Any
    ) -> Any:
        """Execute a streaming OpenAI chat completion."""
        from openai import AsyncOpenAI

        if self._openai_client is None:
            self._openai_client = AsyncOpenAI()
        return await self._openai_client.chat.completions.create(
            model=model, messages=messages, stream=True, **kwargs
        )

    async def _call_anthropic_stream(
        self, *, model: str, messages: list[dict[str, str]], **kwargs: Any
    ) -> Any:
        """Execute a streaming Anthropic message completion."""
        from anthropic import AsyncAnthropic

        if self._anthropic_client is None:
            self._anthropic_client = AsyncAnthropic()

        system_msg = next((m["content"] for m in messages if m.get("role") == "system"), None)
        user_messages = [m for m in messages if m.get("role") != "system"]

        return await self._anthropic_client.messages.create(
            model=model,
            messages=user_messages,
            system=system_msg or "",
            max_tokens=kwargs.get("max_tokens", 4096),
            stream=True,
        )
