"""Guard — the primary interface for the overrule SDK."""

from __future__ import annotations

import asyncio
import atexit
import functools
import inspect
import logging
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TypeVar

from overrule.exceptions import OverruleError, PolicyEvaluationError, ViolationError
from overrule.models.config import GuardConfig, PolicyAction
from overrule.models.event import EventStatus, EventType, InterceptEvent
from overrule.models.violation import Violation
from overrule.policies.base import BasePolicy, PolicyResult
from overrule.policies.registry import PolicyRegistry
from overrule.transport.reporter import EventReporter

logger = logging.getLogger("overrule.guard")

F = TypeVar("F", bound=Callable[..., Any])

import threading
import weakref

_active_guards_lock = threading.Lock()
_active_guards: list[weakref.ref[Guard]] = []
_sync_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="overrule-sync")


def _atexit_flush() -> None:
    """Flush all active guards on process exit."""
    import asyncio

    with _active_guards_lock:
        guards_snapshot = list(_active_guards)

    for ref in guards_snapshot:
        guard = ref()
        if guard is not None and guard._initialized:
            try:
                loop = asyncio.new_event_loop()
                loop.run_until_complete(guard._reporter.stop())
                loop.close()
            except Exception:
                pass


atexit.register(_atexit_flush)


class Guard:
    """Runtime AI governance guard.

    Intercepts LLM calls and tool executions, evaluates them against
    configured policies, and reports telemetry to the cloud platform.

    The SDK operates in fail-open mode by default: if an internal error
    occurs during policy evaluation or reporting, the operation proceeds
    unguarded rather than crashing the host application.

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
        )
        self._default_policies = default_policies or [
            "pii-detection",
            "injection-detection",
        ]
        self._initialized = False
        self._init_lock = asyncio.Lock()
        self._openai_client: Any = None
        self._anthropic_client: Any = None
        with _active_guards_lock:
            _active_guards.append(weakref.ref(self))

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
        with _active_guards_lock:
            _active_guards[:] = [r for r in _active_guards if r() is not None and r() is not self]

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
        direction: str = "input",
    ) -> PolicyResult:
        """Evaluate content against policies without making an LLM call.

        Useful for standalone content checking (e.g., user input validation).
        """
        await self._ensure_initialized()
        active_policies = policies or self._default_policies
        content = self._truncate(content)
        start = time.perf_counter()
        result = self._evaluate_content(content, active_policies, direction=direction)

        status = EventStatus.BLOCKED if self._should_block(result.violations) else (
            EventStatus.FLAGGED if result.violations else EventStatus.PASSED
        )
        event = self._build_event(
            event_type=EventType.LLM_CALL,
            status=status,
            input_content=content,
            policies_applied=active_policies,
            violations=result.violations,
            latency_ms=(time.perf_counter() - start) * 1000,
        )
        self._reporter.enqueue(event)
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
    ) -> dict[str, Any]:
        """Intercept and govern an LLM chat completion call.

        Evaluates input against policies before sending, evaluates output
        after receiving. Blocks or logs based on configured action.
        """
        await self._ensure_initialized()
        active_policies = policies or self._default_policies
        start = time.perf_counter()

        # Validate input
        if not model:
            raise ValueError("model must be a non-empty string")
        if not messages:
            raise ValueError("messages must be a non-empty list")

        try:
            return await self._guarded_chat(
                model=model,
                messages=messages,
                policies=active_policies,
                provider=provider,
                start=start,
                **kwargs,
            )
        except ViolationError:
            raise
        except OverruleError:
            raise
        except Exception as exc:
            if self._config.fail_open:
                logger.error(
                    "Evaluation failed, passing through unguarded: %s", exc
                )
                return await self._call_llm(
                    model=model, messages=messages, provider=provider, **kwargs
                )
            raise OverruleError(f"Internal SDK error: {exc}") from exc

    async def _guarded_chat(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        policies: list[str],
        provider: str,
        start: float,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Core chat logic wrapped by fail-open handler."""
        input_content = self._extract_input(messages)
        input_content = self._truncate(input_content)
        input_result = self._evaluate_content(input_content, policies, direction="input")

        if self._should_block(input_result.violations):
            event = self._build_event(
                event_type=EventType.LLM_CALL,
                status=EventStatus.BLOCKED,
                input_content=input_content,
                model=model,
                provider=provider,
                policies_applied=policies,
                violations=input_result.violations,
                latency_ms=(time.perf_counter() - start) * 1000,
            )
            self._reporter.enqueue(event)
            raise ViolationError(input_result.violations)

        response = await self._call_llm(
            model=model, messages=messages, provider=provider, **kwargs
        )

        output_content = self._extract_output(response)
        output_content = self._truncate(output_content)
        output_result = self._evaluate_content(
            output_content, policies, direction="output"
        )

        all_violations = input_result.violations + output_result.violations

        if self._should_redact() and output_result.violations:
            status = EventStatus.FLAGGED
            redacted_output = self._apply_redaction(output_content, output_result.violations)
            response = self._replace_output(response, redacted_output)
        elif self._should_block(output_result.violations):
            status = EventStatus.BLOCKED
        elif all_violations:
            status = EventStatus.FLAGGED
        else:
            status = EventStatus.PASSED

        usage = self._extract_usage(response)
        latency_ms = (time.perf_counter() - start) * 1000
        event = self._build_event(
            event_type=EventType.LLM_CALL,
            status=status,
            input_content=input_content,
            output_content=output_content,
            model=model,
            provider=provider,
            input_tokens=usage.get("input_tokens"),
            output_tokens=usage.get("output_tokens"),
            policies_applied=policies,
            violations=all_violations,
            latency_ms=latency_ms,
        )
        self._reporter.enqueue(event)

        if status == EventStatus.BLOCKED:
            raise ViolationError(output_result.violations)

        return response

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
    ) -> "StreamGuard":
        """Intercept a streaming LLM call with token-by-token policy evaluation.

        Evaluates input policies before streaming starts. Output policies are
        evaluated incrementally (every `eval_interval` chunks) and at completion.

        Returns a StreamGuard async iterator that yields text chunks.

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
        active_policies = policies or self._default_policies
        start = time.perf_counter()

        input_content = self._extract_input(messages)
        input_content = self._truncate(input_content)
        input_result = self._evaluate_content(input_content, active_policies, direction="input")

        if self._should_block(input_result.violations):
            event = self._build_event(
                event_type=EventType.LLM_CALL,
                status=EventStatus.BLOCKED,
                input_content=input_content,
                model=model,
                provider=provider,
                policies_applied=active_policies,
                violations=input_result.violations,
                latency_ms=(time.perf_counter() - start) * 1000,
                metadata={"streaming": True},
            )
            self._reporter.enqueue(event)
            raise ViolationError(input_result.violations)

        raw_stream = await self._call_llm_stream(
            model=model, messages=messages, provider=provider, **kwargs
        )

        return StreamGuard(
            raw_stream=raw_stream,
            input_content=input_content,
            policies=active_policies,
            registry=self._registry,
            reporter=self._reporter,
            config_action=self._config.default_action,
            model=model,
            provider=provider,
            fail_open=self._config.fail_open,
            eval_interval=eval_interval,
            start_time=start,
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
        active_policies = policies or self._default_policies
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
            else:

                @functools.wraps(func)
                def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                    import asyncio

                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        loop = None

                    coro = self._execute_protected(
                        func, active_policies, effective_action,
                        args, kwargs, is_async=False,
                    )

                    if loop and loop.is_running():
                        future = _sync_executor.submit(asyncio.run, coro)
                        return future.result()
                    else:
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
        content = self._truncate(content)

        try:
            result = self._evaluate_content(content, policy_ids, direction="input")
        except Exception as exc:
            if self._config.fail_open:
                logger.error("Policy evaluation failed in protect(): %s", exc)
                if is_async:
                    return await func(*args, **kwargs)
                return func(*args, **kwargs)
            raise

        if action == PolicyAction.BLOCK and result.violations:
            event = self._build_event(
                event_type=EventType.TOOL_CALL,
                status=EventStatus.BLOCKED,
                input_content=content,
                policies_applied=policy_ids,
                violations=result.violations,
                latency_ms=(time.perf_counter() - start) * 1000,
                metadata={"function": func.__name__},
            )
            self._reporter.enqueue(event)
            raise ViolationError(result.violations)

        if is_async:
            output = await func(*args, **kwargs)
        else:
            output = func(*args, **kwargs)

        latency_ms = (time.perf_counter() - start) * 1000
        status = EventStatus.FLAGGED if result.violations else EventStatus.PASSED
        event = self._build_event(
            event_type=EventType.TOOL_CALL,
            status=status,
            input_content=content,
            output_content=self._truncate(str(output)) if output is not None else None,
            policies_applied=policy_ids,
            violations=result.violations,
            latency_ms=latency_ms,
            metadata={"function": func.__name__},
        )
        self._reporter.enqueue(event)
        return output

    # ─── Internal Methods ──────────────────────────────────────────────

    def _evaluate_content(
        self, content: str, policy_ids: list[str], *, direction: str
    ) -> PolicyResult:
        """Run all specified policies against content."""
        all_violations: list[Violation] = []
        total_time = 0.0

        policies = self._registry.resolve(policy_ids)
        for policy in policies:
            try:
                result = policy.evaluate(content, direction=direction)
                for v in result.violations:
                    v.metadata["direction"] = direction
                all_violations.extend(result.violations)
                total_time += result.execution_time_ms
            except Exception as exc:
                if self._config.fail_open:
                    logger.error("Policy '%s' crashed: %s", policy.policy_id, exc)
                else:
                    raise PolicyEvaluationError(policy.policy_id, exc) from exc

        return PolicyResult(
            passed=len(all_violations) == 0,
            violations=all_violations,
            execution_time_ms=total_time,
        )

    def _should_block(self, violations: list[Violation]) -> bool:
        """Determine if violations warrant blocking based on configured action."""
        if self._config.default_action == PolicyAction.BLOCK and violations:
            return True
        return any(v.blocked for v in violations)

    def _should_redact(self) -> bool:
        """Check if the configured action is REDACT."""
        return self._config.default_action == PolicyAction.REDACT

    @staticmethod
    def _apply_redaction(content: str, violations: list[Violation]) -> str:
        """Replace matched violation content with redaction tokens in the output.

        Uses raw_match from violation metadata if available (policies may store
        a redacted form in matched_content for safe logging). Falls back to
        matched_content if no raw_match is present.
        """
        redacted = content
        for violation in violations:
            raw = violation.metadata.get("raw_match") or violation.matched_content
            if raw and raw in redacted:
                token = f"[{violation.policy_id.upper().replace('-', '_')}]"
                redacted = redacted.replace(raw, token, 1)
        return redacted

    def _truncate(self, content: str) -> str:
        """Truncate content to configured max length.

        To prevent bypass via padding (attacker pushes payload past the limit),
        we keep both the head and tail of oversized content so policies scan both ends.
        """
        max_len = self._config.max_content_length
        if len(content) <= max_len:
            return content
        logger.warning(
            "Content truncated from %d to %d chars — scanning head + tail",
            len(content),
            max_len,
        )
        half = max_len // 2
        return content[:half] + content[-half:]

    @staticmethod
    def _replace_output(response: dict[str, Any], new_content: str) -> dict[str, Any]:
        """Return a copy of the response with the assistant content replaced."""
        import copy

        modified = copy.deepcopy(response)
        choices = modified.get("choices", [])
        if choices and isinstance(choices, list):
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message", {})
                if isinstance(message, dict):
                    message["content"] = new_content
        return modified

    @staticmethod
    def _extract_input(messages: list[dict[str, str]]) -> str:
        """Extract evaluable content from chat messages.

        Handles both simple string content and OpenAI multimodal format
        (list of {"type": "text", "text": "..."} blocks).
        """
        parts: list[str] = []
        for msg in messages:
            if isinstance(msg, dict):
                content = msg.get("content")
                if content and isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            text = block.get("text", "")
                            if text:
                                parts.append(text)
        return "\n".join(parts)

    @staticmethod
    def _extract_output(response: dict[str, Any]) -> str:
        """Extract text content from an LLM response."""
        choices = response.get("choices", [])
        if choices and isinstance(choices, list):
            first = choices[0]
            if isinstance(first, dict):
                message = first.get("message", {})
                if isinstance(message, dict):
                    return message.get("content", "") or ""
        return ""

    @staticmethod
    def _extract_usage(response: dict[str, Any]) -> dict[str, int | None]:
        """Extract token usage from an LLM response."""
        usage = response.get("usage")
        if not usage or not isinstance(usage, dict):
            return {"input_tokens": None, "output_tokens": None}
        return {
            "input_tokens": usage.get("input_tokens") or usage.get("prompt_tokens"),
            "output_tokens": usage.get("output_tokens") or usage.get("completion_tokens"),
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
            policies_applied=policies_applied or [],
            violations=violations or [],
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
            model=model, messages=messages, **kwargs  # type: ignore[arg-type]
        )
        return response.model_dump()

    async def _call_anthropic(
        self, *, model: str, messages: list[dict[str, str]], **kwargs: Any
    ) -> dict[str, Any]:
        """Execute an Anthropic message completion with cached client."""
        from anthropic import AsyncAnthropic

        if self._anthropic_client is None:
            self._anthropic_client = AsyncAnthropic()

        system_msg = next(
            (m["content"] for m in messages if m.get("role") == "system"), None
        )
        user_messages = [m for m in messages if m.get("role") != "system"]

        response = await self._anthropic_client.messages.create(
            model=model,
            messages=user_messages,  # type: ignore[arg-type]
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
            model=model, messages=messages, stream=True, **kwargs  # type: ignore[arg-type]
        )

    async def _call_anthropic_stream(
        self, *, model: str, messages: list[dict[str, str]], **kwargs: Any
    ) -> Any:
        """Execute a streaming Anthropic message completion."""
        from anthropic import AsyncAnthropic

        if self._anthropic_client is None:
            self._anthropic_client = AsyncAnthropic()

        system_msg = next(
            (m["content"] for m in messages if m.get("role") == "system"), None
        )
        user_messages = [m for m in messages if m.get("role") != "system"]

        return await self._anthropic_client.messages.create(
            model=model,
            messages=user_messages,  # type: ignore[arg-type]
            system=system_msg or "",
            max_tokens=kwargs.get("max_tokens", 4096),
            stream=True,
        )
