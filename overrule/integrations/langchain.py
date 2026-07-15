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
import logging
import time
from typing import Any
from uuid import UUID

from overrule.exceptions import ViolationError
from overrule.models.config import GuardConfig, PolicyAction
from overrule.models.event import EventStatus, EventType, InterceptEvent
from overrule.models.violation import Violation
from overrule.policies.base import PolicyResult
from overrule.policies.registry import PolicyRegistry
from overrule.transport.reporter import EventReporter

logger = logging.getLogger("overrule.integrations.langchain")


class OverruleCallback:
    """LangChain callback handler that enforces Overrule governance policies.

    Drop-in governance for any LangChain chain, agent, or LLM call.
    Evaluates input policies before LLM calls and output policies after.

    Works with both LangChain's sync and async interfaces.

    Args:
        api_key: Overrule API key (or set OVERRULE_API_KEY env var)
        policies: List of policy IDs to enforce
        action: What to do on violations (BLOCK, LOG, WARN, REDACT)
        fail_open: If True, governance errors never crash your chain
        on_violation: Optional callback invoked with violations list
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        policies: list[str] | None = None,
        action: PolicyAction = PolicyAction.LOG,
        fail_open: bool = True,
        on_violation: Any | None = None,
    ) -> None:
        self._config = GuardConfig.from_env(api_key=api_key, default_action=action, fail_open=fail_open)
        self._policies = policies or ["pii-detection", "injection-detection"]
        self._action = action
        self._fail_open = fail_open
        self._on_violation = on_violation

        self._registry = PolicyRegistry()
        self._reporter = EventReporter(
            endpoint=self._config.endpoint,
            api_key=self._config.api_key,
            batch_size=self._config.batch_size,
            flush_interval=self._config.flush_interval_seconds,
            max_retries=self._config.max_retries,
            circuit_break_threshold=self._config.circuit_break_threshold,
            circuit_break_cooldown=self._config.circuit_break_cooldown_seconds,
        )
        self._started = False
        self._run_starts: dict[str, float] = {}
        self._max_tracked_runs = 1000  # prevent unbounded dict growth

    def _ensure_started(self) -> None:
        if not self._started:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._reporter.start())
            except RuntimeError:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(self._reporter.start())
                loop.close()
            self._started = True

    def shutdown(self) -> None:
        """Flush pending events and release resources."""
        if self._started:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._reporter.stop())
            except RuntimeError:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(self._reporter.stop())
                loop.close()
            self._started = False
            self._run_starts.clear()

    def _gc_run_starts(self) -> None:
        """Evict stale run entries to prevent memory leak."""
        if len(self._run_starts) > self._max_tracked_runs:
            cutoff = time.perf_counter() - 300  # 5 minute TTL
            stale = [k for k, v in self._run_starts.items() if v < cutoff]
            for k in stale:
                del self._run_starts[k]

    def _evaluate(self, content: str, direction: str) -> PolicyResult:
        all_violations: list[Violation] = []
        total_time = 0.0

        policies = self._registry.resolve(self._policies)
        for policy in policies:
            try:
                result = policy.evaluate(content, direction=direction)
                all_violations.extend(result.violations)
                total_time += result.execution_time_ms
            except Exception as exc:
                if self._fail_open:
                    logger.error("Policy '%s' crashed in LangChain callback: %s", policy.policy_id, exc)
                else:
                    raise

        return PolicyResult(
            passed=len(all_violations) == 0,
            violations=all_violations,
            execution_time_ms=total_time,
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
        self._run_starts[run_key] = time.perf_counter()

        input_content = "\n".join(prompts)
        try:
            result = self._evaluate(input_content, direction="input")
            if result.violations:
                if self._on_violation:
                    self._on_violation(result.violations)
                if self._action == PolicyAction.BLOCK:
                    raise ViolationError(result.violations)
        except ViolationError:
            raise
        except Exception as exc:
            if not self._fail_open:
                raise
            logger.error("LangChain input eval failed (fail-open): %s", exc)

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
        self._run_starts[run_key] = time.perf_counter()

        parts: list[str] = []
        for message_list in messages:
            for msg in message_list:
                if hasattr(msg, "content"):
                    parts.append(str(msg.content))
                elif isinstance(msg, dict):
                    parts.append(str(msg.get("content", "")))

        input_content = "\n".join(parts)
        try:
            result = self._evaluate(input_content, direction="input")
            if result.violations:
                if self._on_violation:
                    self._on_violation(result.violations)
                if self._action == PolicyAction.BLOCK:
                    raise ViolationError(result.violations)
        except ViolationError:
            raise
        except Exception as exc:
            if not self._fail_open:
                raise
            logger.error("LangChain chat input eval failed (fail-open): %s", exc)

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

        try:
            result = self._evaluate(output_content, direction="output")
            violations = result.violations
            status = EventStatus.PASSED

            if violations:
                if self._on_violation:
                    self._on_violation(violations)
                if self._action == PolicyAction.BLOCK:
                    status = EventStatus.BLOCKED
                else:
                    status = EventStatus.FLAGGED

            latency_ms = (time.perf_counter() - start) * 1000
            event = InterceptEvent(
                event_type=EventType.LLM_CALL,
                status=status,
                output_content=output_content[:self._config.max_content_length],
                violations=violations,
                latency_ms=latency_ms,
                metadata={"integration": "langchain"},
            )
            self._reporter.enqueue(event)

            if status == EventStatus.BLOCKED:
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

    def on_chain_start(self, serialized: dict[str, Any], inputs: dict[str, Any], **kwargs: Any) -> None:
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
