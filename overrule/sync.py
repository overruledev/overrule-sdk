"""Synchronous wrapper for the overrule Guard.

Provides a blocking API for applications that don't use asyncio.
Internally manages a dedicated background thread with its own event loop.
"""

from __future__ import annotations

import asyncio
import functools
import threading
from collections.abc import Callable
from typing import Any, TypeVar

from overrule.guard import Guard
from overrule.models.config import GuardConfig, PolicyAction
from overrule.policies.base import PolicyResult

F = TypeVar("F", bound=Callable[..., Any])


class SyncGuard:
    """Synchronous interface to the overrule governance engine.

    Usage:
        guard = SyncGuard(api_key="sk-...")

        # As context manager
        with SyncGuard(api_key="sk-...") as guard:
            response = guard.chat(model="gpt-4", messages=[...])

        # Protect a function
        @guard.protect(policies=["pii-detection"])
        def my_tool(input: str) -> str:
            return process(input)
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        endpoint: str | None = None,
        default_policies: list[str] | None = None,
        default_action: PolicyAction = PolicyAction.LOG,
        fail_open: bool = True,
        config: GuardConfig | None = None,
    ) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, daemon=True, name="overrule-sync-loop"
        )
        self._thread.start()

        self._guard = Guard(
            api_key=api_key,
            endpoint=endpoint,
            default_policies=default_policies,
            default_action=default_action,
            fail_open=fail_open,
            config=config,
        )

        # Initialize the async guard in the background loop
        self._run(self._guard._ensure_initialized())

    def _run(self, coro: Any, timeout: float = 30.0) -> Any:
        """Run a coroutine in the background event loop and block until done."""
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    def chat(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        policies: list[str] | None = None,
        provider: str = "openai",
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Synchronous LLM call with governance policies applied."""
        return self._run(
            self._guard.chat(
                model=model,
                messages=messages,
                policies=policies,
                provider=provider,
                **kwargs,
            )
        )

    def evaluate(
        self,
        content: str,
        *,
        policies: list[str] | None = None,
        direction: str = "input",
    ) -> PolicyResult:
        """Synchronously evaluate content against policies."""
        return self._run(
            self._guard.evaluate(content, policies=policies, direction=direction)
        )

    def protect(
        self,
        *,
        policies: list[str] | None = None,
        action: PolicyAction | None = None,
    ) -> Callable[[F], F]:
        """Decorator to protect a function with governance policies (sync).

        Unlike the async Guard.protect(), this runs policy evaluation and
        event reporting through the background event loop for full telemetry.
        """
        effective_action = action

        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                return self._run(
                    self._guard._execute_protected(
                        func,
                        policies or self._guard._default_policies,
                        effective_action or self._guard._config.default_action,
                        args,
                        kwargs,
                        is_async=False,
                    )
                )

            return wrapper  # type: ignore[return-value]

        return decorator

    def register_policy(self, policy_cls: type) -> None:
        """Register a custom policy implementation."""
        self._guard.register_policy(policy_cls)

    def shutdown(self) -> None:
        """Shut down the guard and background thread."""
        import contextlib

        with contextlib.suppress(Exception):
            self._run(self._guard.shutdown(), timeout=10.0)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5.0)

    def __enter__(self) -> SyncGuard:
        return self

    def __exit__(self, *_: Any) -> None:
        self.shutdown()
