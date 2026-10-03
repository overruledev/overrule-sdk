"""Tests for streaming interception (guard.stream())."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock

import pytest

from overrule import Guard, PolicyAction
from overrule.exceptions import ViolationError
from overrule.models.config import GuardConfig, PolicyConfig
from overrule.models.violation import ViolationSeverity
from overrule.policies.base import BasePolicy, PolicyResult
from overrule.stream import StreamGuard


class FakeChunk:
    """Mimics an OpenAI streaming chunk."""

    def __init__(self, content: str | None) -> None:
        self.choices = [FakeDelta(content)]


class FakeDelta:
    def __init__(self, content: str | None) -> None:
        self.delta = FakeDeltaContent(content)


class FakeDeltaContent:
    def __init__(self, content: str | None) -> None:
        self.content = content


async def fake_stream(chunks: list[str]):
    """Create an async iterator mimicking OpenAI streaming."""
    for text in chunks:
        yield FakeChunk(text)


async def fake_stream_with_pii(include_ssn: bool = True):
    """Stream that contains PII in accumulated content."""
    yield FakeChunk("Hello, ")
    yield FakeChunk("my SSN is ")
    if include_ssn:
        yield FakeChunk("123-45-6789")
    yield FakeChunk(" and that's it.")


@pytest.fixture
async def guard():
    g = Guard(api_key="test", fail_open=True)
    yield g
    await g.shutdown()


async def test_stream_guard_yields_text(guard: Guard):
    """StreamGuard yields text chunks correctly."""
    await guard._ensure_initialized()

    stream = StreamGuard(
        raw_stream=fake_stream(["Hello", " world", "!"]),
        holdback_chars=0,  # assert raw chunk pass-through
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.LOG,
        model="gpt-4o",
        fail_open=True,
        eval_interval=5,
        start_time=0.0,
    )

    result = []
    async for chunk in stream:
        result.append(chunk)

    assert result == ["Hello", " world", "!"]
    assert stream.accumulated_content == "Hello world!"


async def test_stream_guard_detects_violations(guard: Guard):
    """StreamGuard detects PII in accumulated output."""
    await guard._ensure_initialized()

    stream = StreamGuard(
        raw_stream=fake_stream_with_pii(),
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.LOG,
        model="gpt-4o",
        fail_open=True,
        eval_interval=2,
        start_time=0.0,
    )

    result = []
    async for chunk in stream:
        result.append(chunk)

    assert len(stream.violations) > 0
    assert any("pii-detection" in v.policy_id for v in stream.violations)


async def test_stream_guard_blocks_on_violation(guard: Guard):
    """StreamGuard raises ViolationError when action is BLOCK."""
    await guard._ensure_initialized()

    stream = StreamGuard(
        raw_stream=fake_stream_with_pii(),
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.BLOCK,
        model="gpt-4o",
        fail_open=True,
        eval_interval=2,
        start_time=0.0,
    )

    with pytest.raises(ViolationError):
        async for _ in stream:
            pass


async def test_stream_guard_no_violations_clean_content(guard: Guard):
    """StreamGuard passes cleanly with no violations."""
    await guard._ensure_initialized()

    stream = StreamGuard(
        raw_stream=fake_stream(["The weather ", "is nice ", "today."]),
        holdback_chars=0,  # assert raw chunk pass-through
        input_content="test",
        policies=["pii-detection", "injection-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.BLOCK,
        model="gpt-4o",
        fail_open=True,
        eval_interval=5,
        start_time=0.0,
    )

    result = []
    async for chunk in stream:
        result.append(chunk)

    assert result == ["The weather ", "is nice ", "today."]
    assert stream.violations == []


async def test_stream_guard_handles_empty_chunks(guard: Guard):
    """StreamGuard skips chunks with no content."""
    await guard._ensure_initialized()

    async def stream_with_empty():
        yield FakeChunk(None)
        yield FakeChunk("Hello")
        yield FakeChunk(None)
        yield FakeChunk(" world")

    stream = StreamGuard(
        raw_stream=stream_with_empty(),
        holdback_chars=0,  # assert raw chunk pass-through
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.LOG,
        model="gpt-4o",
        fail_open=True,
        eval_interval=5,
        start_time=0.0,
    )

    result = []
    async for chunk in stream:
        result.append(chunk)

    assert result == ["Hello", " world"]


async def test_stream_guard_dict_chunk_format(guard: Guard):
    """StreamGuard handles dict-format chunks (raw API response)."""
    await guard._ensure_initialized()

    async def dict_stream():
        yield {"choices": [{"delta": {"content": "Hello"}}]}
        yield {"choices": [{"delta": {"content": " there"}}]}

    stream = StreamGuard(
        raw_stream=dict_stream(),
        holdback_chars=0,  # assert raw chunk pass-through
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.LOG,
        model="gpt-4o",
        fail_open=True,
        eval_interval=5,
        start_time=0.0,
    )

    result = []
    async for chunk in stream:
        result.append(chunk)

    assert result == ["Hello", " there"]


async def test_stream_guard_incremental_eval_interval(guard: Guard):
    """StreamGuard evaluates at configured interval."""
    await guard._ensure_initialized()

    chunks = [f"chunk{i} " for i in range(15)]
    stream = StreamGuard(
        raw_stream=fake_stream(chunks),
        holdback_chars=0,  # assert raw chunk pass-through
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.LOG,
        model="gpt-4o",
        fail_open=True,
        eval_interval=5,
        start_time=0.0,
    )

    result = []
    async for chunk in stream:
        result.append(chunk)

    assert len(result) == 15
    assert stream.accumulated_content == "".join(chunks)


async def test_stream_holds_back_trailing_window(guard: Guard):
    """A trailing window is withheld so detection can still act on it (F12)."""
    await guard._ensure_initialized()

    emitted: list[str] = []
    stream = StreamGuard(
        raw_stream=fake_stream(["A" * 300, "B" * 10]),
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.LOG,
        model="gpt-4o",
        fail_open=True,
        eval_interval=1,
        start_time=0.0,
        holdback_chars=256,
    )

    async for chunk in stream:
        emitted.append(chunk)

    assert "".join(emitted) == "A" * 300 + "B" * 10
    # First release withheld the trailing 256 chars of what had arrived.
    assert len(emitted[0]) == 300 - 256


async def test_stream_blocks_violation_inside_holdback_before_emitting(guard: Guard):
    """PII in the final tokens is blocked before those tokens reach the caller."""
    await guard._ensure_initialized()

    emitted: list[str] = []
    stream = StreamGuard(
        raw_stream=fake_stream(["Filler text. ", "SSN 123-45-6789"]),
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.BLOCK,
        model="gpt-4o",
        fail_open=True,
        eval_interval=1,
        start_time=0.0,
        holdback_chars=256,
    )

    with pytest.raises(ViolationError):
        async for chunk in stream:
            emitted.append(chunk)

    assert "123-45-6789" not in "".join(emitted)


async def test_stream_rejects_redact_action():
    """REDACT cannot be honoured on a stream, so it is refused up front (F12)."""
    guard = Guard(api_key="test", default_action=PolicyAction.REDACT)
    try:
        with pytest.raises(ValueError, match="REDACT is not supported"):
            await guard.stream(
                model="gpt-4o",
                messages=[{"role": "user", "content": "hello"}],
                policies=["pii-detection"],
            )
    finally:
        await guard.shutdown()


async def test_stream_incremental_eval_is_bounded(guard: Guard):
    """Incremental evaluation re-scans a bounded window, not the whole buffer."""
    await guard._ensure_initialized()

    stream = StreamGuard(
        raw_stream=fake_stream(["x" * 5_000 for _ in range(10)]),
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.LOG,
        model="gpt-4o",
        fail_open=True,
        eval_interval=1,
        start_time=0.0,
        eval_window_chars=1024,
    )

    async for _ in stream:
        pass

    assert stream._accumulated_length == 50_000
    assert len(stream._scan_tail) == 1024


async def test_stream_respects_max_content_length(guard: Guard):
    """Retained/reported content is capped by max_content_length."""
    await guard._ensure_initialized()

    stream = StreamGuard(
        raw_stream=fake_stream(["y" * 2_000 for _ in range(5)]),
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.LOG,
        model="gpt-4o",
        fail_open=True,
        eval_interval=5,
        start_time=0.0,
        max_content_length=1_000,
    )

    async for _ in stream:
        pass

    assert stream._accumulated_length == 10_000
    assert len(stream.accumulated_content) == 1_000


async def test_stream_survives_throwing_reporter(guard: Guard):
    """A reporter that raises cannot break the stream (F2)."""
    await guard._ensure_initialized()

    class ExplodingReporter:
        def enqueue(self, event):
            raise RuntimeError("telemetry down")

    stream = StreamGuard(
        raw_stream=fake_stream(["all ", "clear"]),
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=ExplodingReporter(),  # type: ignore[arg-type]
        config_action=PolicyAction.LOG,
        model="gpt-4o",
        fail_open=True,
        eval_interval=5,
        start_time=0.0,
        holdback_chars=0,
    )

    result = [chunk async for chunk in stream]
    assert "".join(result) == "all clear"


async def test_stream_guard_toxicity_detection(guard: Guard):
    """StreamGuard detects toxicity in streaming content."""
    await guard._ensure_initialized()

    async def toxic_stream():
        yield FakeChunk("You should ")
        yield FakeChunk("kill yourself")
        yield FakeChunk(" right now")

    stream = StreamGuard(
        raw_stream=toxic_stream(),
        input_content="test",
        policies=["toxicity-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.LOG,
        model="gpt-4o",
        fail_open=True,
        eval_interval=2,
        start_time=0.0,
    )

    result = []
    async for chunk in stream:
        result.append(chunk)

    assert len(stream.violations) > 0


# ─── Per-policy PolicyConfig on the streaming path ──────────────────────
#
# `stream.py` used to call `registry.get()` with no enabled-check at all, so a policy
# the customer had explicitly switched off in config still ran against streamed
# output. `Guard._default_policies` is filtered at init, which hid the bug unless the
# caller passed an explicit `policies=[...]` to `stream()`. `severity_override` was
# likewise read by nothing.


def _pii_stream_guard(guard: Guard, **kwargs) -> StreamGuard:
    """A StreamGuard over content containing an SSN, with overridable config."""
    return StreamGuard(
        raw_stream=fake_stream_with_pii(),
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.LOG,
        model="gpt-4o",
        fail_open=True,
        eval_interval=2,
        start_time=0.0,
        **kwargs,
    )


async def test_stream_skips_a_policy_disabled_in_config(guard: Guard):
    """PolicyConfig(enabled=False) must be honoured on streamed output too."""
    await guard._ensure_initialized()

    stream = _pii_stream_guard(
        guard,
        policy_configs={"pii-detection": PolicyConfig(id="pii-detection", enabled=False)},
    )

    async for _ in stream:
        pass

    assert stream.violations == []
    # ...and it is not claimed as applied on the reported event either.
    assert stream._policies == []


async def test_stream_still_runs_a_policy_enabled_in_config(guard: Guard):
    """Control for the test above: the same stream does violate when enabled."""
    await guard._ensure_initialized()

    stream = _pii_stream_guard(
        guard,
        policy_configs={"pii-detection": PolicyConfig(id="pii-detection", enabled=True)},
    )

    async for _ in stream:
        pass

    assert stream.violations
    assert stream._policies == ["pii-detection"]


async def test_stream_treats_unconfigured_policies_as_enabled(guard: Guard):
    """No PolicyConfig at all means the policy runs — same default as Guard."""
    await guard._ensure_initialized()

    stream = _pii_stream_guard(guard, policy_configs={})

    async for _ in stream:
        pass

    assert stream.violations


async def test_stream_applies_severity_override(guard: Guard):
    """severity_override rewrites the severity of streamed violations."""
    await guard._ensure_initialized()

    stream = _pii_stream_guard(
        guard,
        policy_configs={
            "pii-detection": PolicyConfig(id="pii-detection", severity_override="info")
        },
    )

    async for _ in stream:
        pass

    assert stream.violations
    for violation in stream.violations:
        assert violation.severity == ViolationSeverity.INFO
        assert violation.metadata["original_severity"] != "info"


async def test_stream_without_override_keeps_the_policy_severity(guard: Guard):
    """Control for the test above."""
    await guard._ensure_initialized()

    stream = _pii_stream_guard(guard)

    async for _ in stream:
        pass

    assert stream.violations
    assert all(v.severity != ViolationSeverity.INFO for v in stream.violations)
    assert all("original_severity" not in v.metadata for v in stream.violations)


async def test_guard_stream_does_not_revive_a_disabled_policy():
    """End-to-end: an explicit `policies=[...]` cannot resurrect a disabled policy.

    This is the path the bug actually reached production through — `stream()` passed
    the caller's list straight through without filtering it.
    """
    guard = Guard(
        config=GuardConfig(
            api_key="test",
            policies=[PolicyConfig(id="pii-detection", enabled=False)],
        )
    )
    try:
        guard._call_llm_stream = AsyncMock(  # type: ignore[method-assign]
            return_value=fake_stream_with_pii()
        )
        stream = await guard.stream(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=["pii-detection"],
        )

        async for _ in stream:
            pass

        assert stream.violations == []
        assert stream._policies == []
    finally:
        await guard.shutdown()


async def test_guard_stream_passes_severity_override_through():
    """End-to-end: severity_override configured on the Guard reaches StreamGuard."""
    guard = Guard(
        config=GuardConfig(
            api_key="test",
            policies=[PolicyConfig(id="pii-detection", severity_override="info")],
        )
    )
    try:
        guard._call_llm_stream = AsyncMock(  # type: ignore[method-assign]
            return_value=fake_stream_with_pii()
        )
        stream = await guard.stream(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=["pii-detection"],
        )

        async for _ in stream:
            pass

        assert stream.violations
        assert all(v.severity == ViolationSeverity.INFO for v in stream.violations)
    finally:
        await guard.shutdown()


async def test_stream_ignores_redact_on_a_disabled_policy():
    """A disabled REDACT policy must not veto stream() — it was never going to run."""
    guard = Guard(
        config=GuardConfig(
            api_key="test",
            default_action=PolicyAction.LOG,
            policies=[PolicyConfig(id="pii-detection", enabled=False, action=PolicyAction.REDACT)],
        )
    )
    try:
        guard._call_llm_stream = AsyncMock(  # type: ignore[method-assign]
            return_value=fake_stream_with_pii()
        )
        stream = await guard.stream(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=["pii-detection"],
        )
        assert stream._policies == []
    finally:
        await guard.shutdown()


# ─── Per-policy action=BLOCK on the streaming path (S3) ──────────────────
#
# `_blocking_violations` tested only the *global* `config_action`, even though
# `_effective_action()` was consulted two lines earlier for the REDACT check. With
# `default_action=WARN` plus `PolicyConfig(id="pii-detection", action=BLOCK)`,
# `chat()` blocked but `stream()` happily yielded the card — while StreamGuard's
# docstring promised per-policy config was honoured "exactly as on chat()".


async def _drain(stream) -> str:
    emitted = ""
    async for chunk in stream:
        emitted += chunk
    return emitted


async def test_stream_blocks_on_a_per_policy_block_action(guard: Guard):
    await guard._ensure_initialized()

    stream = _pii_stream_guard(
        guard,
        policy_configs={
            "pii-detection": PolicyConfig(id="pii-detection", action=PolicyAction.BLOCK)
        },
    )

    with pytest.raises(ViolationError):
        await _drain(stream)


async def test_stream_does_not_block_on_a_per_policy_log_action(guard: Guard):
    """Control: the same stream only flags when the policy's action is LOG."""
    await guard._ensure_initialized()

    stream = _pii_stream_guard(
        guard,
        policy_configs={"pii-detection": PolicyConfig(id="pii-detection", action=PolicyAction.LOG)},
    )

    await _drain(stream)
    assert stream.violations


async def test_a_per_policy_log_action_overrides_a_global_block(guard: Guard):
    """Per-policy action wins over the global default, as it does on chat()."""
    await guard._ensure_initialized()

    stream = StreamGuard(
        raw_stream=fake_stream_with_pii(),
        input_content="test",
        policies=["pii-detection"],
        registry=guard._registry,
        reporter=guard._reporter,
        config_action=PolicyAction.BLOCK,
        model="gpt-4o",
        fail_open=True,
        eval_interval=2,
        start_time=0.0,
        policy_configs={"pii-detection": PolicyConfig(id="pii-detection", action=PolicyAction.LOG)},
    )

    await _drain(stream)
    assert stream.violations


async def test_guard_stream_honours_a_per_policy_block_end_to_end():
    """The reproduction: chat() blocked, stream() yielded the card verbatim."""
    guard = Guard(
        config=GuardConfig(
            api_key="test",
            default_action=PolicyAction.WARN,
            policies=[PolicyConfig(id="pii-detection", action=PolicyAction.BLOCK)],
        )
    )

    async def card_stream():
        for text in ("card ", "4111111111111111", " bye"):
            yield {"choices": [{"delta": {"content": text}}]}

    try:
        guard._call_llm_stream = AsyncMock(return_value=card_stream())  # type: ignore[method-assign]
        stream = await guard.stream(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=["pii-detection"],
        )

        emitted = ""
        with pytest.raises(ViolationError):
            async for chunk in stream:
                emitted += chunk
        assert "4111111111111111" not in emitted
    finally:
        await guard.shutdown()


# ─── Pool handling on the streaming path (S9c) ───────────────────────────
#
# `StreamGuard` captured `executor=` once at `stream()` time and never reported a
# timed-out run back to the Guard. So streaming timeouts starved the shared pool
# invisibly (and never retrieved `future.exception()`), and once the pool had been
# retired — or `Guard.shutdown()` had run — the next chunk raised
# `RuntimeError: cannot schedule new futures after shutdown`.


class _StuckPolicy(BasePolicy):
    policy_id = "stuck-stream-policy"
    description = "never returns in time"

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        time.sleep(3.0)
        return PolicyResult(passed=True, violations=[])


async def test_stream_survives_a_pool_retirement_mid_stream():
    """The pool is re-fetched per evaluation instead of being cached.

    The retirement deliberately happens *after* several evaluations have already
    used the pool, so a pool captured at `stream()` time — or cached on first use —
    is genuinely stale by the time the next chunk arrives.
    """
    guard = Guard(api_key="test", fail_open=True)

    async def retiring_stream():
        for index in range(6):
            yield {"choices": [{"delta": {"content": f"early{index} "}}]}
        # Simulate the pool being retired while the stream is still running.
        guard._pool.shutdown()
        for index in range(30):
            yield {"choices": [{"delta": {"content": f"chunk{index} "}}]}
        yield {"choices": [{"delta": {"content": "card 4111111111111111 "}}]}

    try:
        guard._call_llm_stream = AsyncMock(return_value=retiring_stream())  # type: ignore[method-assign]
        stream = await guard.stream(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=["pii-detection"],
            eval_interval=2,
        )
        emitted = await _drain(stream)
        assert "chunk29" in emitted, "the stream stopped after the pool was retired"
        # A stale executor raises RuntimeError on every later submit; under
        # fail_open that is swallowed, so the only visible symptom is that
        # governance silently stops working for the rest of the stream.
        assert stream.violations, "no policy ran after the pool was retired"
        assert any(v.metadata.get("raw_match") == "4111111111111111" for v in stream.violations)
    finally:
        await guard.shutdown()


async def test_stream_reports_a_timed_out_run_to_the_guard():
    """A streaming timeout must count toward pool retirement like any other."""
    guard = Guard(api_key="test", fail_open=True)
    guard.register_policy(_StuckPolicy)
    guard._POLICY_TIMEOUT_MS = 200

    async def slow_stream():
        for index in range(4):
            yield {"choices": [{"delta": {"content": f"chunk{index} "}}]}

    try:
        guard._call_llm_stream = AsyncMock(return_value=slow_stream())  # type: ignore[method-assign]
        stream = await guard.stream(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=[_StuckPolicy.policy_id],
            eval_interval=1,
        )
        before = guard._policy_pool_generation, guard._orphaned_policy_runs
        await _drain(stream)
        after = guard._policy_pool_generation, guard._orphaned_policy_runs
        assert after != before, "streaming timeouts were invisible to the Guard's pool"
    finally:
        await guard.shutdown()


async def test_stream_guard_without_a_provider_uses_its_own_pool(guard: Guard):
    """Constructing StreamGuard directly (as these tests do) must still work."""
    await guard._ensure_initialized()
    stream = _pii_stream_guard(guard, policy_configs={})
    await _drain(stream)
    assert stream.violations
    assert stream._fallback_pool is not None


async def test_guard_stream_still_only_warns_without_a_per_policy_block():
    """Control for the end-to-end test: WARN everywhere must not block."""
    guard = Guard(
        config=GuardConfig(api_key="test", default_action=PolicyAction.WARN),
    )

    async def card_stream():
        for text in ("card ", "4111111111111111", " bye"):
            yield {"choices": [{"delta": {"content": text}}]}

    try:
        guard._call_llm_stream = AsyncMock(return_value=card_stream())  # type: ignore[method-assign]
        stream = await guard.stream(
            model="gpt-4o",
            messages=[{"role": "user", "content": "hello"}],
            policies=["pii-detection"],
        )
        emitted = await _drain(stream)
        assert "4111111111111111" in emitted
        assert stream.violations
    finally:
        await guard.shutdown()
