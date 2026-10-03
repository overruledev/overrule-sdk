"""Streaming interception — token-by-token policy evaluation for streamed LLM responses."""

from __future__ import annotations

import asyncio
import functools
import logging
import time
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from concurrent.futures import Executor
from typing import Any

from overrule._pool import DaemonThreadPool
from overrule.exceptions import PolicyEvaluationError, ViolationError
from overrule.guard import Guard, iter_scan_windows
from overrule.models.config import PolicyAction, PolicyConfig
from overrule.models.event import EventStatus, EventType, InterceptEvent
from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies.registry import PolicyRegistry
from overrule.transport.reporter import EventReporter

logger = logging.getLogger("overrule.stream")

#: Characters withheld from the caller so detection can still act on text that has
#: not been emitted yet.
DEFAULT_HOLDBACK_CHARS = 256

#: Size of the sliding window re-scanned on each incremental evaluation. Bounded so
#: incremental evaluation stays linear overall rather than re-scanning the whole
#: buffer every interval.
DEFAULT_EVAL_WINDOW_CHARS = 8_192


class StreamGuard:
    """Wraps a streaming LLM response and evaluates policies on streamed content.

    Policies are evaluated on a bounded sliding window at configurable intervals
    (by chunk count and by volume of unscanned text), and a final evaluation runs
    over the retained content when the stream completes.

    A trailing window of ``holdback_chars`` characters is withheld from the caller
    until the stream ends, so a violation detected in the final tokens can still be
    blocked before those tokens are emitted. Everything before the holdback window
    has already been handed to the caller and cannot be recalled — for strict
    enforcement use non-streaming ``guard.chat()`` with ``default_action=BLOCK``.

    ``PolicyAction.REDACT`` cannot be honoured while streaming and is rejected
    up-front by ``Guard.stream()``.

    Per-policy :class:`PolicyConfig` is honoured on the streaming path exactly as it
    is on ``chat()``/``evaluate()``: policies with ``enabled=False`` are dropped,
    ``severity_override`` is applied to every violation the policy emits, and a
    per-policy ``action=BLOCK`` stops the stream even when the global
    ``default_action`` is only WARN/LOG.

    Usage:
        async with Guard() as guard:
            stream = await guard.stream(
                model="gpt-4o",
                messages=[{"role": "user", "content": "..."}],
                policies=["pii-detection", "toxicity-detection"],
            )
            async for chunk in stream:
                print(chunk, end="", flush=True)

            # After iteration completes, check for violations:
            if stream.violations:
                print(f"\\nWarning: {len(stream.violations)} violation(s) detected")
    """

    def __init__(
        self,
        *,
        raw_stream: AsyncIterator[Any],
        input_content: str,
        policies: list[str],
        registry: PolicyRegistry,
        reporter: EventReporter,
        config_action: PolicyAction,
        model: str,
        provider: str = "openai",
        fail_open: bool,
        eval_interval: int = 10,
        start_time: float,
        policy_params: dict[str, dict[str, Any]] | None = None,
        policy_configs: dict[str, PolicyConfig] | None = None,
        max_content_length: int = 100_000,
        holdback_chars: int = DEFAULT_HOLDBACK_CHARS,
        eval_window_chars: int = DEFAULT_EVAL_WINDOW_CHARS,
        pool_provider: Callable[[], tuple[Executor, int]] | None = None,
        on_orphaned_run: Callable[[asyncio.Future[Any], int], None] | None = None,
        policy_timeout_ms: int = 5000,
    ) -> None:
        self._raw_stream = raw_stream
        self._input_content = input_content
        self._policy_configs = policy_configs or {}
        # A policy the caller disabled via PolicyConfig(enabled=False) must not run
        # against streamed output either. Guard._default_policies is already filtered,
        # so without this an explicit `policies=[...]` passed to stream() would revive
        # disabled policies. Filtering here also keeps the reported `policies_applied`
        # honest about what actually ran.
        self._policies = [pid for pid in policies if self._policy_enabled(pid)]
        self._registry = registry
        self._reporter = reporter
        self._config_action = config_action
        self._model = model
        self._provider = provider
        self._fail_open = fail_open
        self._eval_interval = max(1, eval_interval)
        self._start_time = start_time
        self._policy_params = policy_params or {}
        self._holdback = max(0, holdback_chars)
        self._eval_window = max(256, eval_window_chars)
        # Resolved per evaluation rather than captured once: a pool retired mid-stream
        # (or a Guard.shutdown()) invalidated a cached executor and every later chunk
        # raised RuntimeError("cannot schedule new futures after shutdown").
        self._pool_provider = pool_provider
        self._on_orphaned_run = on_orphaned_run
        self._fallback_pool: Executor | None = None
        self._policy_timeout_ms = policy_timeout_ms

        self._buffer: list[str] = []
        self._chunk_count = 0
        self._accumulated_length = 0
        # Cap on retained content: `max_content_length` bounds what is stored and
        # reported. Text beyond it is still scanned incrementally as it streams.
        self._max_buffer_chars = min(max(max_content_length, 1_000), 1_000_000)
        self._retained_length = 0
        self._scan_tail = ""
        self._chars_since_eval = 0
        self._pending = ""
        self._violations: list[Violation] = []
        self._seen: set[tuple[str, str, int]] = set()
        self._finished = False
        self._event_reported = False

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
        return self._config_action if cfg is None else cfg.action

    @property
    def accumulated_content(self) -> str:
        return "".join(self._buffer)

    @property
    def violations(self) -> list[Violation]:
        return list(self._violations)

    async def __aiter__(self) -> AsyncIterator[str]:
        """Yield text chunks while evaluating policies incrementally."""
        had_exception = False
        try:
            async for raw_chunk in self._raw_stream:
                text = self._extract_chunk_text(raw_chunk)
                if not text:
                    continue

                self._append(text)
                self._chunk_count += 1

                if self._should_evaluate():
                    await self._incremental_eval()

                if self._blocking_violations():
                    self._report_event(EventStatus.BLOCKED)
                    raise ViolationError(self._violations)

                for emitted in self._release():
                    yield emitted

            # Stream exhausted: evaluate everything before releasing the holdback,
            # so a violation in the final tokens can still block them.
            await self._finalize()
            tail = self._pending
            self._pending = ""
            if tail:
                yield tail

        except ViolationError:
            had_exception = True
            raise
        except GeneratorExit:
            raise
        except Exception as exc:
            had_exception = True
            if not self._fail_open:
                raise
            logger.error("Stream evaluation error, yielding remaining: %s", exc)
            tail = self._pending
            self._pending = ""
            if tail:
                yield tail
        finally:
            if not self._finished:
                try:
                    await self._finalize()
                except ViolationError:
                    if not had_exception:
                        raise

    def _append(self, text: str) -> None:
        """Record streamed text into the retained buffer, scan tail, and holdback."""
        self._accumulated_length += len(text)
        room = self._max_buffer_chars - self._retained_length
        if room > 0:
            kept = text[:room]
            self._buffer.append(kept)
            self._retained_length += len(kept)
        self._scan_tail = (self._scan_tail + text)[-self._eval_window :]
        self._chars_since_eval += len(text)
        self._pending += text

    def _should_evaluate(self) -> bool:
        """Evaluate on the chunk interval, or sooner if a lot of text is unscanned."""
        if self._chunk_count % self._eval_interval == 0:
            return True
        return self._chars_since_eval >= self._eval_window // 2

    def _release(self) -> Iterator[str]:
        """Yield everything except the trailing holdback window."""
        if len(self._pending) <= self._holdback:
            return
        cut = len(self._pending) - self._holdback
        emitted = self._pending[:cut]
        self._pending = self._pending[cut:]
        yield emitted

    def _blocking_violations(self) -> bool:
        """True when the detected violations must stop the stream.

        A per-policy ``PolicyConfig(action=BLOCK)`` blocks the stream exactly as it
        blocks ``chat()``. Testing only the global ``default_action`` here meant a
        policy explicitly configured to BLOCK was reduced to WARN while streaming.
        """
        if not self._violations:
            return False
        # Injection/jailbreak violations block regardless of the configured action.
        return any(
            v.blocked or self._effective_action(v.policy_id) == PolicyAction.BLOCK
            for v in self._violations
        )

    async def _finalize(self) -> None:
        """Final evaluation on the complete retained output."""
        self._finished = True
        full_content = self.accumulated_content

        if not full_content:
            self._report_event(EventStatus.PASSED)
            return

        try:
            self._merge(await self._evaluate(full_content, origin=0))
        except Exception as exc:
            if not self._fail_open:
                raise
            logger.error("Final stream eval failed: %s", exc)

        if self._violations:
            if self._blocking_violations():
                self._report_event(EventStatus.BLOCKED)
                raise ViolationError(self._violations)
            self._report_event(EventStatus.FLAGGED)
        else:
            self._report_event(EventStatus.PASSED)

    async def _incremental_eval(self) -> None:
        """Evaluate the bounded sliding window of recently streamed content."""
        window = self._scan_tail
        origin = max(0, self._accumulated_length - len(window))
        self._chars_since_eval = 0
        try:
            self._merge(await self._evaluate(window, origin=origin))
        except Exception as exc:
            if not self._fail_open:
                raise
            logger.debug("Incremental eval failed: %s", exc)

    def _merge(self, violations: Sequence[Violation]) -> None:
        """Union new findings into the violation list, de-duplicating repeats."""
        for violation in violations:
            raw = Guard._raw_match(violation)
            offset = violation.metadata.get("offset")
            if raw:
                key = (violation.policy_id, raw, offset if isinstance(offset, int) else -1)
            else:
                key = (violation.policy_id, violation.message, -1)
            if key in self._seen:
                continue
            self._seen.add(key)
            self._violations.append(violation)

    def _acquire_pool(self) -> tuple[Executor, int]:
        """The pool to run this evaluation on, plus its generation number.

        Fetched fresh for every policy run so a pool retired mid-stream is replaced
        transparently. Falls back to a private pool when no provider was supplied
        (``StreamGuard`` constructed directly, e.g. in tests).
        """
        if self._pool_provider is not None:
            return self._pool_provider()
        if self._fallback_pool is None:
            self._fallback_pool = DaemonThreadPool(
                max_workers=4, thread_name_prefix="overrule-stream"
            )
        return self._fallback_pool, 0

    async def _evaluate(self, content: str, *, origin: int) -> list[Violation]:
        """Run policies against content off the event loop, under a real deadline.

        ``origin`` is the absolute offset of ``content`` within the stream, so
        violation offsets stay comparable between incremental and final passes.
        """
        loop = asyncio.get_running_loop()
        found: list[Violation] = []

        for policy_id in self._policies:
            policy = self._registry.get(policy_id, self._policy_params.get(policy_id))
            override = self._severity_override(policy_id)
            for base, window in iter_scan_windows(content):
                call = functools.partial(policy.evaluate, window, direction="output")
                pool, generation = self._acquire_pool()
                future = loop.run_in_executor(pool, call)
                done, _pending = await asyncio.wait(
                    {future}, timeout=self._policy_timeout_ms / 1000
                )
                if future not in done:
                    # Report the orphan to the owning Guard so a stuck streaming
                    # policy is counted toward pool retirement (and its exception is
                    # retrieved) exactly like one on the chat()/evaluate() path.
                    # Without this, streaming timeouts starved the shared pool
                    # invisibly.
                    if self._on_orphaned_run is not None:
                        self._on_orphaned_run(future, generation)
                    message = (
                        f"Policy '{policy_id}' exceeded its {self._policy_timeout_ms}ms "
                        "budget while streaming"
                    )
                    if not self._fail_open:
                        raise PolicyEvaluationError(policy_id, TimeoutError(message))
                    logger.warning("%s — skipping it and continuing", message)
                    break

                result = future.result()
                occurrences: dict[tuple[str, str], int] = {}
                for violation in result.violations:
                    violation.metadata["direction"] = "output"
                    Guard.apply_severity_override(violation, override)
                    violation.metadata["offset"] = origin + Guard._absolute_offset(
                        violation, window, base, occurrences
                    )
                    found.append(violation)

        return found

    def _report_event(self, status: EventStatus) -> None:
        """Ship the governance event to the reporter. Only reports once."""
        if self._event_reported:
            return
        self._event_reported = True
        latency_ms = (time.perf_counter() - self._start_time) * 1000
        try:
            event = InterceptEvent(
                event_type=EventType.LLM_CALL,
                status=status,
                input_content=self._input_content,
                output_content=self.accumulated_content or None,
                model=self._model,
                provider=self._provider,
                policies_applied=self._policies,
                violations=self._violations,
                latency_ms=latency_ms,
                metadata={
                    "streaming": True,
                    "chunks": self._chunk_count,
                    "streamed_chars": self._accumulated_length,
                },
            )
            self._reporter.enqueue(event)
        except Exception as exc:
            # Telemetry must never affect stream control flow.
            logger.error("Failed to record streaming governance event (ignored): %s", exc)

    @staticmethod
    def _extract_chunk_text(chunk: Any) -> str | None:
        """Extract text content from a streaming chunk (OpenAI + Anthropic formats)."""
        # OpenAI dict format
        if isinstance(chunk, dict):
            choices = chunk.get("choices", [])
            if choices:
                delta = choices[0].get("delta", {})
                content = delta.get("content")
                return content if isinstance(content, str) else None
            # Anthropic dict format (content_block_delta)
            if chunk.get("type") == "content_block_delta":
                text = chunk.get("delta", {}).get("text")
                return text if isinstance(text, str) else None
            return None
        # OpenAI object format
        if hasattr(chunk, "choices") and chunk.choices:
            content = getattr(chunk.choices[0].delta, "content", None)
            return content if isinstance(content, str) else None
        # Anthropic object format (RawContentBlockDeltaEvent)
        if getattr(chunk, "type", None) == "content_block_delta":
            text = getattr(getattr(chunk, "delta", None), "text", None)
            return text if isinstance(text, str) else None
        return None
