"""Regression tests for the fail-open path (F2, F9).

Telemetry failures used to disable enforcement, the fail-open handler used to
re-invoke the LLM (billing the customer twice and replacing an already-scanned
response with an unscanned one), and the pass-through returned a bare dict with no
`flagged`/`violations` attributes. Fail-open bypasses were also invisible.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from overrule import Guard
from overrule.exceptions import OverruleError, ViolationError
from overrule.models.config import PolicyAction
from overrule.models.event import EventStatus
from tests.fakes import ExplodingReporter, RecordingReporter

CLEAN_RESPONSE = {
    "choices": [{"message": {"role": "assistant", "content": "all good"}}],
    "model": "gpt-4o",
    "usage": {"prompt_tokens": 0, "completion_tokens": 0},
}


def _guard(**kwargs: object) -> Guard:
    guard = Guard(api_key="test", **kwargs)  # type: ignore[arg-type]
    guard._initialized = True
    return guard


class TestTelemetryCannotDisableEnforcement:
    @pytest.mark.asyncio
    async def test_blocked_input_still_raises_when_reporter_explodes(self) -> None:
        guard = _guard(default_action=PolicyAction.BLOCK)
        guard._reporter = ExplodingReporter()  # type: ignore[assignment]
        llm = AsyncMock(return_value=CLEAN_RESPONSE)
        guard._call_llm = llm  # type: ignore[method-assign]

        with pytest.raises(ViolationError):
            await guard.chat(
                model="gpt-4o",
                messages=[{"role": "user", "content": "My SSN is 123-45-6789"}],
                policies=["pii-detection"],
            )

        assert llm.await_count == 0, "blocked request must never reach the provider"

    @pytest.mark.asyncio
    async def test_blocked_output_still_raises_when_reporter_explodes(self) -> None:
        guard = _guard(default_action=PolicyAction.BLOCK)
        guard._reporter = ExplodingReporter()  # type: ignore[assignment]
        llm = AsyncMock(
            return_value={
                "choices": [{"message": {"role": "assistant", "content": "SSN 123-45-6789"}}]
            }
        )
        guard._call_llm = llm  # type: ignore[method-assign]

        with pytest.raises(ViolationError):
            await guard.chat(
                model="gpt-4o",
                messages=[{"role": "user", "content": "hello"}],
                policies=["pii-detection"],
            )

        assert llm.await_count == 1

    @pytest.mark.asyncio
    async def test_clean_call_succeeds_when_reporter_explodes(self) -> None:
        guard = _guard(default_action=PolicyAction.BLOCK)
        guard._reporter = ExplodingReporter()  # type: ignore[assignment]
        guard._call_llm = AsyncMock(return_value=CLEAN_RESPONSE)  # type: ignore[method-assign]

        response = await guard.chat(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=["pii-detection"],
        )
        assert response["choices"][0]["message"]["content"] == "all good"
        assert response.flagged is False

    def test_protect_blocks_when_reporter_explodes(self) -> None:
        guard = _guard(default_action=PolicyAction.BLOCK)
        guard._reporter = ExplodingReporter()  # type: ignore[assignment]

        @guard.protect(policies=["pii-detection"], action=PolicyAction.BLOCK)
        def send(body: str) -> str:  # pragma: no cover - must not execute
            raise AssertionError("executed despite a violation")

        with pytest.raises(ViolationError):
            send("SSN 123-45-6789")


class TestFailOpenDoesNotCallLlmTwice:
    @pytest.mark.asyncio
    async def test_error_after_llm_call_returns_original_response(self) -> None:
        guard = _guard()
        reporter = RecordingReporter()
        guard._reporter = reporter  # type: ignore[assignment]
        llm = AsyncMock(return_value=CLEAN_RESPONSE)
        guard._call_llm = llm  # type: ignore[method-assign]

        real_evaluate = guard._evaluate_content

        async def flaky(content, policy_ids, *, direction, **_kwargs):
            if direction == "output":
                raise RuntimeError("boom during output evaluation")
            return await real_evaluate(content, policy_ids, direction=direction)

        guard._evaluate_content = flaky  # type: ignore[method-assign]

        response = await guard.chat(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=["pii-detection"],
        )

        assert llm.await_count == 1, "fail-open must not re-invoke the provider"
        assert response["choices"][0]["message"]["content"] == "all good"
        # Asserting only the content here is what let S5 through: the response shape
        # was right while `flagged`/`violations` silently lied.
        assert response.flagged is False
        assert response.violations == []

    @pytest.mark.asyncio
    async def test_error_before_llm_call_calls_provider_once(self) -> None:
        guard = _guard()
        guard._reporter = RecordingReporter()  # type: ignore[assignment]
        llm = AsyncMock(return_value=CLEAN_RESPONSE)
        guard._call_llm = llm  # type: ignore[method-assign]

        async def broken(content, policy_ids, *, direction, **_kwargs):
            raise RuntimeError("boom during input evaluation")

        guard._evaluate_content = broken  # type: ignore[method-assign]

        response = await guard.chat(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=["pii-detection"],
        )
        assert llm.await_count == 1
        assert response["choices"][0]["message"]["content"] == "all good"

    @pytest.mark.asyncio
    async def test_fail_open_disabled_raises_instead(self) -> None:
        guard = _guard(fail_open=False)
        guard._reporter = RecordingReporter()  # type: ignore[assignment]
        llm = AsyncMock(return_value=CLEAN_RESPONSE)
        guard._call_llm = llm  # type: ignore[method-assign]

        async def broken(content, policy_ids, *, direction, **_kwargs):
            raise RuntimeError("boom")

        guard._evaluate_content = broken  # type: ignore[method-assign]

        with pytest.raises(OverruleError):
            await guard.chat(
                model="gpt-4o",
                messages=[{"role": "user", "content": "hello"}],
                policies=["pii-detection"],
            )
        assert llm.await_count == 0


class TestFailOpenResponseShape:
    @pytest.mark.asyncio
    async def test_pass_through_is_a_chat_response(self) -> None:
        guard = _guard()
        guard._reporter = RecordingReporter()  # type: ignore[assignment]
        guard._call_llm = AsyncMock(return_value=CLEAN_RESPONSE)  # type: ignore[method-assign]

        async def broken(content, policy_ids, *, direction, **_kwargs):
            raise RuntimeError("boom")

        guard._evaluate_content = broken  # type: ignore[method-assign]

        response = await guard.chat(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=["pii-detection"],
        )

        assert response.violations == []
        assert response.flagged is False
        assert response["violations"] == []
        assert response["flagged"] is False


class TestFailOpenIsObservable:
    @pytest.mark.asyncio
    async def test_emits_a_fail_open_event(self) -> None:
        guard = _guard()
        reporter = RecordingReporter()
        guard._reporter = reporter  # type: ignore[assignment]
        guard._call_llm = AsyncMock(return_value=CLEAN_RESPONSE)  # type: ignore[method-assign]

        async def broken(content, policy_ids, *, direction, **_kwargs):
            raise RuntimeError("boom")

        guard._evaluate_content = broken  # type: ignore[method-assign]

        await guard.chat(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=["pii-detection"],
        )

        assert EventStatus.FAIL_OPEN.value in reporter.statuses()
        event = next(e for e in reporter.events if e.status == EventStatus.FAIL_OPEN)
        assert event.metadata["fail_open_reason"] == "RuntimeError"
        assert event.model == "gpt-4o"

    def test_protect_emits_a_fail_open_event(self) -> None:
        guard = _guard()
        reporter = RecordingReporter()
        guard._reporter = reporter  # type: ignore[assignment]

        async def broken(content, policy_ids, *, direction, **_kwargs):
            raise RuntimeError("boom")

        guard._evaluate_content = broken  # type: ignore[method-assign]

        @guard.protect(policies=["pii-detection"], action=PolicyAction.BLOCK)
        def tool(value: str) -> str:
            return value

        assert tool("anything") == "anything"
        assert EventStatus.FAIL_OPEN.value in reporter.statuses()

    def test_fail_open_events_are_distinguishable_from_clean_passes(self) -> None:
        """Replaces a tautology (`EventStatus("fail_open") is EventStatus.FAIL_OPEN`).

        What actually matters is that a bypass is *reported* as its own status and
        never as PASSED, and that the wire value is the one the server expects.
        """
        assert EventStatus.FAIL_OPEN.value == "fail_open"
        assert EventStatus.FAIL_OPEN is not EventStatus.PASSED
        assert EventStatus.FAIL_OPEN.value not in {
            EventStatus.PASSED.value,
            EventStatus.FLAGGED.value,
            EventStatus.BLOCKED.value,
        }


class TestFailOpenStillReportsWhatItFound:
    """S5: the post-LLM fail-open path reported `flagged=False`, `violations=[]`.

    Everything detected before the failure was thrown away, so a response whose
    input already contained a card came back looking clean. Any post-LLM helper
    failure reaches this — the reproduction used a provider returning a
    non-numeric token count, which makes `_extract_usage` raise.
    """

    LEAKY_RESPONSE = {
        "choices": [{"message": {"role": "assistant", "content": "leak 4111111111111111"}}],
        # int("not-a-number") raises inside _extract_usage, after the LLM call.
        "usage": {"prompt_tokens": "not-a-number"},
    }

    @pytest.mark.asyncio
    async def test_violations_found_before_the_failure_are_surfaced(self) -> None:
        guard = _guard()
        reporter = RecordingReporter()
        guard._reporter = reporter  # type: ignore[assignment]
        llm = AsyncMock(return_value=self.LEAKY_RESPONSE)
        guard._call_llm = llm  # type: ignore[method-assign]

        response = await guard.chat(
            model="gpt-4o",
            messages=[{"role": "user", "content": "my card is 4111111111111111"}],
            policies=["pii-detection"],
        )

        assert llm.await_count == 1
        assert response.flagged is True, "reported clean despite a detected card"
        assert response.violations
        assert any(v.metadata.get("raw_match") == "4111111111111111" for v in response.violations)

    @pytest.mark.asyncio
    async def test_the_fail_open_event_carries_the_violations_too(self) -> None:
        guard = _guard()
        reporter = RecordingReporter()
        guard._reporter = reporter  # type: ignore[assignment]
        guard._call_llm = AsyncMock(return_value=self.LEAKY_RESPONSE)  # type: ignore[method-assign]

        await guard.chat(
            model="gpt-4o",
            messages=[{"role": "user", "content": "my card is 4111111111111111"}],
            policies=["pii-detection"],
        )

        event = next(e for e in reporter.events if e.status == EventStatus.FAIL_OPEN)
        assert event.violations, "a fail-open event must not hide known violations"

    @pytest.mark.asyncio
    async def test_a_clean_call_still_reports_clean(self) -> None:
        guard = _guard()
        guard._reporter = RecordingReporter()  # type: ignore[assignment]
        guard._call_llm = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "choices": [{"message": {"content": "all good"}}],
                "usage": {"prompt_tokens": "not-a-number"},
            }
        )

        response = await guard.chat(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=["pii-detection"],
        )
        assert response.flagged is False
        assert response.violations == []
