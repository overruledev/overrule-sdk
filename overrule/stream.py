"""Streaming interception — token-by-token policy evaluation for streamed LLM responses."""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from typing import Any

from overrule.exceptions import ViolationError
from overrule.models.config import PolicyAction
from overrule.models.event import EventStatus, EventType, InterceptEvent
from overrule.models.violation import Violation
from overrule.policies.base import PolicyResult
from overrule.policies.registry import PolicyRegistry
from overrule.transport.reporter import EventReporter

logger = logging.getLogger("overrule.stream")


class StreamGuard:
    """Wraps a streaming LLM response and evaluates policies on accumulated content.

    Evaluates policies at configurable intervals (by chunk count) during streaming,
    and performs a final full evaluation when the stream completes.

    IMPORTANT: Tokens yielded before a violation is detected CANNOT be recalled.
    For strict enforcement where no violating content may reach the user, use
    non-streaming guard.chat() with default_action=BLOCK instead.

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
    ) -> None:
        self._raw_stream = raw_stream
        self._input_content = input_content
        self._policies = policies
        self._registry = registry
        self._reporter = reporter
        self._config_action = config_action
        self._model = model
        self._provider = provider
        self._fail_open = fail_open
        self._eval_interval = eval_interval
        self._start_time = start_time

        self._buffer: list[str] = []
        self._chunk_count = 0
        self._accumulated_length = 0
        self._max_buffer_chars = 1_000_000  # 1MB cap to prevent OOM on huge streams
        self._violations: list[Violation] = []
        self._finished = False
        self._event_reported = False

    @property
    def accumulated_content(self) -> str:
        return "".join(self._buffer)

    @property
    def violations(self) -> list[Violation]:
        return list(self._violations)

    async def __aiter__(self) -> AsyncIterator[str]:
        """Yield text chunks while evaluating policies incrementally."""
        _had_exception = False
        try:
            async for raw_chunk in self._raw_stream:
                text = self._extract_chunk_text(raw_chunk)
                if not text:
                    continue

                self._accumulated_length += len(text)
                if self._accumulated_length <= self._max_buffer_chars:
                    self._buffer.append(text)
                self._chunk_count += 1

                if self._chunk_count % self._eval_interval == 0:
                    self._incremental_eval()

                if self._config_action == PolicyAction.BLOCK and self._violations:
                    self._report_event(EventStatus.BLOCKED)
                    raise ViolationError(self._violations)

                yield text

        except ViolationError:
            _had_exception = True
            raise
        except Exception as exc:
            _had_exception = True
            if self._fail_open:
                logger.error("Stream evaluation error, yielding remaining: %s", exc)
            else:
                raise
        finally:
            if not self._finished:
                try:
                    await self._finalize()
                except ViolationError:
                    if not _had_exception:
                        raise

    async def _finalize(self) -> None:
        """Final evaluation on the complete accumulated output."""
        self._finished = True
        full_content = self.accumulated_content

        if not full_content:
            self._report_event(EventStatus.PASSED)
            return

        try:
            result = self._evaluate(full_content)
            self._violations = result.violations
        except Exception as exc:
            if not self._fail_open:
                raise
            logger.error("Final stream eval failed: %s", exc)

        if self._violations:
            if self._config_action == PolicyAction.BLOCK:
                self._report_event(EventStatus.BLOCKED)
                raise ViolationError(self._violations)
            self._report_event(EventStatus.FLAGGED)
        else:
            self._report_event(EventStatus.PASSED)

    def _incremental_eval(self) -> None:
        """Evaluate accumulated content so far."""
        try:
            result = self._evaluate(self.accumulated_content)
            self._violations = result.violations
        except Exception as exc:
            if not self._fail_open:
                raise
            logger.debug("Incremental eval failed: %s", exc)

    def _evaluate(self, content: str) -> PolicyResult:
        """Run policies against content."""
        all_violations: list[Violation] = []
        total_time = 0.0

        policies = self._registry.resolve(self._policies)
        for policy in policies:
            result = policy.evaluate(content, direction="output")
            all_violations.extend(result.violations)
            total_time += result.execution_time_ms

        return PolicyResult(
            passed=len(all_violations) == 0,
            violations=all_violations,
            execution_time_ms=total_time,
        )

    def _report_event(self, status: EventStatus) -> None:
        """Ship the governance event to the reporter. Only reports once."""
        if self._event_reported:
            return
        self._event_reported = True
        latency_ms = (time.perf_counter() - self._start_time) * 1000
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
            metadata={"streaming": True, "chunks": self._chunk_count},
        )
        self._reporter.enqueue(event)

    @staticmethod
    def _extract_chunk_text(chunk: Any) -> str | None:
        """Extract text content from a streaming chunk (OpenAI + Anthropic formats)."""
        # OpenAI dict format
        if isinstance(chunk, dict):
            choices = chunk.get("choices", [])
            if choices:
                delta = choices[0].get("delta", {})
                return delta.get("content")
            # Anthropic dict format (content_block_delta)
            if chunk.get("type") == "content_block_delta":
                delta = chunk.get("delta", {})
                return delta.get("text")
            return None
        # OpenAI object format
        if hasattr(chunk, "choices") and chunk.choices:
            delta = chunk.choices[0].delta
            if hasattr(delta, "content"):
                return delta.content
        # Anthropic object format (RawContentBlockDeltaEvent)
        if hasattr(chunk, "type") and chunk.type == "content_block_delta":
            if hasattr(chunk, "delta") and hasattr(chunk.delta, "text"):
                return chunk.delta.text
        return None
