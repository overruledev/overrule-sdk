"""Tests for streaming interception (guard.stream())."""

from __future__ import annotations

import pytest

from overrule import Guard, PolicyAction
from overrule.exceptions import ViolationError
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
def guard():
    return Guard(api_key="test", fail_open=True)


async def test_stream_guard_yields_text(guard: Guard):
    """StreamGuard yields text chunks correctly."""
    await guard._ensure_initialized()

    stream = StreamGuard(
        raw_stream=fake_stream(["Hello", " world", "!"]),
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
