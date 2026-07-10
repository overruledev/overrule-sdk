"""Tests for the EventReporter with retry, backoff, and circuit breaker."""


import pytest

from overrule.models.event import EventStatus, EventType, InterceptEvent
from overrule.transport.reporter import EventReporter


@pytest.fixture
def reporter() -> EventReporter:
    return EventReporter(
        endpoint="http://localhost:9999",
        api_key="test-key",
        batch_size=5,
        flush_interval=1.0,
        max_retries=2,
        circuit_break_threshold=3,
        circuit_break_cooldown=1.0,
    )


def _make_event() -> InterceptEvent:
    return InterceptEvent(
        event_type=EventType.LLM_CALL,
        status=EventStatus.PASSED,
        input_content="test",
    )


class TestEnqueue:
    def test_enqueue_adds_to_buffer(self, reporter: EventReporter) -> None:
        event = _make_event()
        reporter.enqueue(event)
        assert reporter.pending_count == 1

    def test_enqueue_multiple(self, reporter: EventReporter) -> None:
        for _ in range(10):
            reporter.enqueue(_make_event())
        assert reporter.pending_count == 10

    def test_enqueue_never_raises(self, reporter: EventReporter) -> None:
        # Even with bizarre scenarios, enqueue should never crash
        reporter.enqueue(_make_event())
        assert reporter.pending_count >= 0


class TestMetrics:
    def test_initial_metrics(self, reporter: EventReporter) -> None:
        metrics = reporter.metrics
        assert metrics["events_sent"] == 0
        assert metrics["events_dropped"] == 0
        assert metrics["events_pending"] == 0
        assert metrics["consecutive_failures"] == 0


class TestCircuitBreaker:
    def test_circuit_starts_closed(self, reporter: EventReporter) -> None:
        assert not reporter._is_circuit_open()

    def test_circuit_opens_after_threshold(self, reporter: EventReporter) -> None:
        import time

        reporter._consecutive_failures = 3
        reporter._circuit_open_until = time.monotonic() + 100
        assert reporter._is_circuit_open()

    def test_circuit_closes_after_cooldown(self, reporter: EventReporter) -> None:
        import time

        reporter._consecutive_failures = 3
        reporter._circuit_open_until = time.monotonic() - 1  # Already expired
        assert not reporter._is_circuit_open()
        assert reporter._consecutive_failures == 0  # Reset


class TestBufferLimits:
    def test_buffer_respects_maxlen(self) -> None:
        reporter = EventReporter(
            endpoint="http://localhost:9999",
            buffer_max_size=5,
        )
        for _ in range(10):
            reporter.enqueue(_make_event())
        assert reporter.pending_count == 5


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_stop(self, reporter: EventReporter) -> None:
        await reporter.start()
        assert reporter._running
        await reporter.stop()
        assert not reporter._running

    @pytest.mark.asyncio
    async def test_double_start_is_safe(self, reporter: EventReporter) -> None:
        await reporter.start()
        await reporter.start()  # Should not raise
        await reporter.stop()

    @pytest.mark.asyncio
    async def test_stop_without_start(self, reporter: EventReporter) -> None:
        await reporter.stop()  # Should not raise
