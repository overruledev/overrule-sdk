"""LangChain callback handler for Overrule governance.

Provides automatic policy enforcement on every LangChain LLM call.

Usage:
    from overrule.integrations import OverruleCallback

    callback = OverruleCallback(
        policies=["pii-detection", "injection-detection", "toxicity-detection"],
    )

    llm = ChatOpenAI(model="gpt-4o", callbacks=[callback])
    result = llm.invoke("Hello, world")
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
import time
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any
from uuid import UUID

from overrule._pool import PolicyPool
from overrule.exceptions import PolicyEvaluationError, ViolationError
from overrule.guard import Guard
from overrule.models.config import GuardConfig, PolicyAction, PolicyConfig
from overrule.models.event import EventStatus, EventType, InterceptEvent
from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies.base import BasePolicy, PolicyResult
from overrule.policies.registry import PolicyRegistry
from overrule.transport.reporter import EventReporter

logger = logging.getLogger("overrule.integrations.langchain")

#: Same defaults as Guard, so switching to LangChain does not silently drop a policy.
DEFAULT_POLICIES = ["pii-detection", "injection-detection", "jailbreak-detection"]


class OverruleCallback:
    """LangChain callback handler that enforces Overrule governance policies.

    Drop-in governance for any LangChain chain, agent, or LLM call.
    Evaluates input policies before LLM calls and output policies after, and
    records an audit event for both directions.

    Violations carrying ``blocked=True`` (prompt injection, SQL injection,
    jailbreak) always block, regardless of ``action`` — matching ``Guard``.

    Works with both LangChain's sync and async interfaces.

    Every :class:`PolicyConfig` field supplied via ``config`` is honoured here too:
    ``enabled=False`` policies never run and are not reported as applied,
    ``parameters`` reach the policy constructor, ``severity_override`` is applied to
    every violation, and a per-policy ``action=BLOCK`` blocks even when the
    callback's own action is only LOG/WARN. Each policy also runs on a bounded pool
    of daemon workers under the same 5s deadline as ``Guard``, so a pathological
    policy cannot hang the LangChain thread forever.

    Args:
        api_key: Overrule API key (or set OVERRULE_API_KEY env var)
        policies: List of policy IDs to enforce
        action: What to do on violations (BLOCK, LOG, WARN, REDACT)
        fail_open: If True, governance errors never crash your chain
        config: Full :class:`GuardConfig`, including per-policy ``PolicyConfig``.
            Takes precedence over ``api_key``/``action``/``fail_open``, matching
            ``Guard(config=...)``.
        on_violation: Optional callback invoked with violations list
    """

    _POLICY_TIMEOUT_MS = 5000
    _POLICY_POOL_WORKERS = 4

    def __init__(
        self,
        *,
        api_key: str | None = None,
        policies: list[str] | None = None,
        action: PolicyAction | None = None,
        fail_open: bool | None = None,
        config: GuardConfig | None = None,
        on_violation: Any | None = None,
    ) -> None:
        self._config = config or GuardConfig.from_env(
            api_key=api_key,
            # LOG has always been this integration's documented default, unlike
            # GuardConfig's WARN; preserved so behaviour does not shift silently.
            default_action=action or PolicyAction.LOG,
            fail_open=fail_open,
        )
        self._policy_configs: dict[str, PolicyConfig] = {pc.id: pc for pc in self._config.policies}

        requested = policies or list(DEFAULT_POLICIES)
        self._policies = [pid for pid in requested if self._policy_enabled(pid)]
        skipped = [pid for pid in requested if pid not in self._policies]
        if skipped:
            logger.info("Policies disabled by configuration: %s", ", ".join(skipped))

        self._action = self._config.default_action
        self._fail_open = self._config.fail_open
        self._on_violation = on_violation
        self._pool = PolicyPool(
            max_workers=self._POLICY_POOL_WORKERS,
            thread_name_prefix="overrule-langchain-policy",
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
        self._started = False
        self._run_starts: dict[str, float] = {}
        self._max_tracked_runs = 1000  # prevent unbounded dict growth
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

    def _ensure_started(self) -> None:
        """Start the reporter on a loop that will outlive this callback.

        LangChain callbacks are invoked synchronously, so the reporter gets its own
        background event loop thread. Running it on a throwaway loop (as this used
        to do) left the flush task pending on a closed loop.
        """
        if self._started:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            loop.create_task(self._reporter.start())
        else:
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(
                target=self._loop.run_forever, daemon=True, name="overrule-langchain"
            )
            self._thread.start()
            with contextlib.suppress(Exception):
                asyncio.run_coroutine_threadsafe(self._reporter.start(), self._loop).result(
                    timeout=5
                )
        self._started = True

    def shutdown(self) -> None:
        """Flush pending events and release resources."""
        if not self._started:
            return
        if self._loop is not None:
            with contextlib.suppress(Exception):
                asyncio.run_coroutine_threadsafe(self._reporter.stop(), self._loop).result(
                    timeout=10
                )
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread is not None:
                self._thread.join(timeout=5.0)
            with contextlib.suppress(Exception):
                self._loop.close()
            self._loop = None
            self._thread = None
        else:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is not None and loop.is_running():
                loop.create_task(self._reporter.stop())
        self._started = False
        self._run_starts.clear()
        self._pool.shutdown()

    def _gc_run_starts(self) -> None:
        """Evict stale run entries to prevent memory leak."""
        if len(self._run_starts) > self._max_tracked_runs:
            cutoff = time.perf_counter() - 300  # 5 minute TTL
            stale = [k for k, v in self._run_starts.items() if v < cutoff]
            for k in stale:
                del self._run_starts[k]

    def _policy_enabled(self, policy_id: str) -> bool:
        """Mirror of :meth:`Guard._policy_enabled` — unconfigured policies are enabled."""
        cfg = self._policy_configs.get(policy_id)
        return True if cfg is None else cfg.enabled

    def _severity_override(self, policy_id: str) -> ViolationSeverity | None:
        """Per-policy ``severity_override`` from config, if one is configured."""
        cfg = self._policy_configs.get(policy_id)
        return None if cfg is None else cfg.severity_override

    def _effective_action(self, policy_id: str) -> PolicyAction:
        """Mirror of :meth:`Guard._effective_action` — per-policy action, else default."""
        cfg = self._policy_configs.get(policy_id)
        return self._action if cfg is None else cfg.action

    def _resolve_policy(self, policy_id: str) -> BasePolicy:
        """Instantiate a policy, passing its configured ``parameters`` through.

        ``registry.resolve()`` was used here, which calls ``get(pid)`` with
        ``parameters=None`` — so every per-policy ``parameters`` value was ignored on
        this path even though ``Guard`` honoured them.
        """
        cfg = self._policy_configs.get(policy_id)
        parameters = dict(cfg.parameters) if cfg and cfg.parameters else None
        return self._registry.get(policy_id, parameters)

    def _run_policy(self, policy: BasePolicy, content: str, direction: str) -> PolicyResult:
        """Run one policy on a daemon worker under a real wall-clock deadline.

        Evaluation used to run inline on the LangChain thread with no deadline, so a
        pathological policy blocked the caller's chain indefinitely.
        """
        pool, generation = self._pool.acquire()
        future = pool.submit(policy.evaluate, content, direction=direction)
        try:
            result: PolicyResult = future.result(timeout=self._POLICY_TIMEOUT_MS / 1000)
        except FutureTimeoutError as exc:
            self._pool.note_orphan(future, generation)
            raise TimeoutError(
                f"Policy '{policy.policy_id}' exceeded its {self._POLICY_TIMEOUT_MS}ms budget"
            ) from exc
        return result

    def _evaluate(
        self, content: str, direction: str, degraded: list[str] | None = None
    ) -> PolicyResult:
        all_violations: list[Violation] = []
        total_time = 0.0

        for policy_id in self._policies:
            try:
                policy = self._resolve_policy(policy_id)
                result = self._run_policy(policy, content, direction)
                override = self._severity_override(policy_id)
                for violation in result.violations:
                    violation.metadata["direction"] = direction
                    Guard.apply_severity_override(violation, override)
                all_violations.extend(result.violations)
                total_time += result.execution_time_ms
            except TimeoutError as exc:
                if not self._fail_open:
                    raise PolicyEvaluationError(policy_id, exc) from exc
                logger.warning(
                    "Policy '%s' timed out in LangChain callback (%s) — skipping it and "
                    "continuing; this content was NOT fully evaluated",
                    policy_id,
                    exc,
                )
                if degraded is not None:
                    degraded.append(policy_id)
            except Exception as exc:
                if not self._fail_open:
                    raise
                logger.error("Policy '%s' crashed in LangChain callback: %s", policy_id, exc)
                if degraded is not None:
                    degraded.append(policy_id)

        return PolicyResult(
            passed=len(all_violations) == 0,
            violations=all_violations,
            execution_time_ms=total_time,
        )

    def _should_block(self, violations: list[Violation]) -> bool:
        """Blocking violations always block, whatever the configured action is.

        A per-policy ``PolicyConfig(action=BLOCK)`` blocks too, matching ``Guard``.
        """
        if not violations:
            return False
        return any(
            v.blocked or self._effective_action(v.policy_id) == PolicyAction.BLOCK
            for v in violations
        )

    def _safe_enqueue(self, event: InterceptEvent) -> None:
        """Record an audit event. Never raises: telemetry cannot affect enforcement."""
        try:
            self._reporter.enqueue(event)
        except Exception as exc:
            logger.error("Failed to record LangChain governance event (ignored): %s", exc)

    @staticmethod
    def _degraded_metadata(degraded: list[str]) -> dict[str, Any]:
        """Record policies that could not be fully evaluated, as ``Guard`` does."""
        if not degraded:
            return {}
        return {"degraded_policies": sorted(set(degraded))}

    def _report_input(
        self,
        content: str,
        violations: list[Violation],
        status: EventStatus,
        start: float,
        degraded: list[str] | None = None,
    ) -> None:
        self._safe_enqueue(
            InterceptEvent(
                event_type=EventType.LLM_CALL,
                status=status,
                input_content=content[: self._config.max_content_length],
                policies_applied=self._policies,
                violations=violations,
                latency_ms=(time.perf_counter() - start) * 1000,
                metadata={
                    "integration": "langchain",
                    "direction": "input",
                    **self._degraded_metadata(degraded or []),
                },
            )
        )

    def _handle_input(self, input_content: str, start: float) -> None:
        """Shared input path for on_llm_start / on_chat_model_start."""
        degraded: list[str] = []
        try:
            result = self._evaluate(input_content, direction="input", degraded=degraded)
            blocking = self._should_block(result.violations)
            if result.violations:
                if self._on_violation:
                    self._on_violation(result.violations)
                status = EventStatus.BLOCKED if blocking else EventStatus.FLAGGED
            else:
                status = EventStatus.PASSED

            # Audit record first: a blocked input must leave a trace.
            self._report_input(input_content, result.violations, status, start, degraded)

            if blocking:
                raise ViolationError(result.violations)
        except ViolationError:
            raise
        except Exception as exc:
            if not self._fail_open:
                raise
            logger.error("LangChain input eval failed (fail-open): %s", exc)
            self._safe_enqueue(
                InterceptEvent(
                    event_type=EventType.LLM_CALL,
                    status=EventStatus.FAIL_OPEN,
                    input_content=input_content[: self._config.max_content_length],
                    policies_applied=self._policies,
                    latency_ms=(time.perf_counter() - start) * 1000,
                    metadata={
                        "integration": "langchain",
                        "direction": "input",
                        "fail_open_reason": type(exc).__name__,
                    },
                )
            )

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Evaluate input policies before an LLM call."""
        self._ensure_started()
        self._gc_run_starts()
        run_key = str(run_id) if run_id else "default"
        start = time.perf_counter()
        self._run_starts[run_key] = start

        self._handle_input("\n".join(prompts), start)

    def on_chat_model_start(
        self,
        serialized: dict[str, Any],
        messages: list[list[Any]],
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Evaluate input policies before a chat model call."""
        self._ensure_started()
        self._gc_run_starts()
        run_key = str(run_id) if run_id else "default"
        start = time.perf_counter()
        self._run_starts[run_key] = start

        parts: list[str] = []
        for message_list in messages:
            for msg in message_list:
                if hasattr(msg, "content"):
                    parts.append(str(msg.content))
                elif isinstance(msg, dict):
                    parts.append(str(msg.get("content", "")))

        self._handle_input("\n".join(parts), start)

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        """Evaluate output policies after an LLM call completes."""
        run_key = str(run_id) if run_id else "default"
        start = self._run_starts.pop(run_key, time.perf_counter())

        output_content = ""
        if hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    if hasattr(gen, "text"):
                        output_content += gen.text

        if not output_content:
            return

        degraded: list[str] = []
        try:
            result = self._evaluate(output_content, direction="output", degraded=degraded)
            violations = result.violations
            status = EventStatus.PASSED
            blocking = self._should_block(violations)

            if violations:
                if self._on_violation:
                    self._on_violation(violations)
                status = EventStatus.BLOCKED if blocking else EventStatus.FLAGGED

            latency_ms = (time.perf_counter() - start) * 1000
            self._safe_enqueue(
                InterceptEvent(
                    event_type=EventType.LLM_CALL,
                    status=status,
                    output_content=output_content[: self._config.max_content_length],
                    policies_applied=self._policies,
                    violations=violations,
                    latency_ms=latency_ms,
                    metadata={
                        "integration": "langchain",
                        "direction": "output",
                        **self._degraded_metadata(degraded),
                    },
                )
            )

            if blocking:
                raise ViolationError(violations)

        except ViolationError:
            raise
        except Exception as exc:
            if not self._fail_open:
                raise
            logger.error("LangChain output eval failed (fail-open): %s", exc)

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        """Clean up run state on LLM error."""
        run_key = str(kwargs.get("run_id", "default"))
        self._run_starts.pop(run_key, None)

    def on_chain_start(
        self, serialized: dict[str, Any], inputs: dict[str, Any], **kwargs: Any
    ) -> None:
        pass

    def on_chain_end(self, outputs: dict[str, Any], **kwargs: Any) -> None:
        pass

    def on_chain_error(self, error: BaseException, **kwargs: Any) -> None:
        pass

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        pass

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        pass

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        pass
