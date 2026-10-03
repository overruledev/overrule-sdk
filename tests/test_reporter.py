"""Tests for the EventReporter with retry, backoff, and circuit breaker."""

import logging

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
    """Buffer overflow used to be the one event-loss path invisible in `metrics`.

    `deque(maxlen=...)` evicts the oldest entry on append without telling anyone, so
    `events_dropped` stayed at 0 while events were being thrown away.
    """

    @staticmethod
    def _reporter(buffer_max_size: int = 5) -> EventReporter:
        return EventReporter(
            endpoint="http://localhost:9999",
            buffer_max_size=buffer_max_size,
        )

    def test_buffer_respects_maxlen(self) -> None:
        reporter = self._reporter()
        for _ in range(10):
            reporter.enqueue(_make_event())
        assert reporter.pending_count == 5

    def test_overflow_increments_events_dropped(self) -> None:
        reporter = self._reporter()
        for _ in range(10):
            reporter.enqueue(_make_event())
        # 5 fit, the next 5 each evicted an older event.
        assert reporter.metrics["events_dropped"] == 5
        assert reporter.metrics["buffer_overflows"] == 5

    def test_filling_the_buffer_exactly_drops_nothing(self) -> None:
        reporter = self._reporter()
        for _ in range(5):
            reporter.enqueue(_make_event())
        assert reporter.pending_count == 5
        assert reporter.metrics["events_dropped"] == 0
        assert reporter.metrics["buffer_overflows"] == 0

    def test_sent_plus_dropped_plus_pending_accounts_for_every_event(self) -> None:
        """The accounting identity the withdrawn 'zero event loss' claim relied on."""
        reporter = self._reporter()
        for _ in range(23):
            reporter.enqueue(_make_event())
        metrics = reporter.metrics
        total = metrics["events_sent"] + metrics["events_dropped"] + metrics["events_pending"]
        assert total == 23

    def test_overflow_keeps_the_newest_events(self) -> None:
        """Drop-oldest is deliberate: under backpressure the newest events matter most."""
        reporter = self._reporter(buffer_max_size=2)
        events = [_make_event() for _ in range(4)]
        for event in events:
            reporter.enqueue(event)
        buffered_ids = [payload["id"] for payload in reporter._buffer]
        assert buffered_ids == [events[2].id, events[3].id]

    def test_overflow_warning_is_throttled(self, caplog: pytest.LogCaptureFixture) -> None:
        """A saturated buffer overflows on every enqueue; warning each time is its own outage."""
        reporter = self._reporter(buffer_max_size=1)
        with caplog.at_level(logging.WARNING, logger="overrule.transport"):
            for _ in range(50):
                reporter.enqueue(_make_event())
        overflow_warnings = [r for r in caplog.records if "Event buffer full" in r.message]
        assert len(overflow_warnings) == 1
        assert reporter.metrics["buffer_overflows"] == 49

    def test_metrics_expose_the_buffer_capacity(self) -> None:
        assert self._reporter(buffer_max_size=7).metrics["buffer_capacity"] == 7

    def test_a_serialisation_failure_is_also_counted(self) -> None:
        """The other previously-silent enqueue loss path."""
        reporter = self._reporter()

        class Unserialisable:
            def __getattr__(self, name: str) -> object:
                raise RuntimeError("boom")

        reporter.enqueue(Unserialisable())  # type: ignore[arg-type]
        assert reporter.pending_count == 0
        assert reporter.metrics["events_dropped"] == 1


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
