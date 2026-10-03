"""Reporter error-handling tests (F8, F10).

F8: 4xx responses were treated as retryable transport failures — a 401 or a 422 was
retried 3x, burned the circuit breaker (5 failures → 30s open → all reporting
stops) and dead-lettered. Nothing in the SDK ever parsed a response body, which is
why a schema-mismatch 422 was invisible in production.
F10: stop() pushed events under the retry cap back into the in-memory deque, where
they were discarded at process exit despite the promise of disk persistence.
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest

from overrule.models.event import EventStatus, EventType, InterceptEvent
from overrule.transport.dead_letter import DeadLetterQueue
from overrule.transport.reporter import EventReporter


def _event() -> InterceptEvent:
    return InterceptEvent(
        event_type=EventType.LLM_CALL,
        status=EventStatus.PASSED,
        input_content="test",
        latency_ms=1.0,
    )


def _make_reporter(handler, tmp_path, **kwargs) -> EventReporter:
    defaults: dict[str, object] = {
        "batch_size": 5,
        "max_retries": 2,
        "circuit_break_threshold": 3,
        "circuit_break_cooldown": 30.0,
    }
    defaults.update(kwargs)
    reporter = EventReporter(endpoint="http://test.local", **defaults)  # type: ignore[arg-type]
    reporter._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="http://test.local"
    )
    reporter._flush_lock = asyncio.Lock()
    reporter._running = True
    reporter._dlq = DeadLetterQueue(directory=str(tmp_path))
    return reporter


def _status_handler(status_code: int, body: object = None, headers=None):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            content=json.dumps(body) if body is not None else b"",
            headers={"Content-Type": "application/json", **(headers or {})},
        )

    return handler


class TestPermanent4xxIsNotRetried:
    @pytest.mark.parametrize("status_code", [400, 401, 403, 422])
    @pytest.mark.asyncio
    async def test_dead_letters_immediately(self, status_code, tmp_path) -> None:
        reporter = _make_reporter(
            _status_handler(status_code, {"error": "nope", "code": "BAD"}), tmp_path
        )
        for _ in range(3):
            reporter.enqueue(_event())

        await reporter._flush()

        assert reporter.pending_count == 0, "must not be requeued for retry"
        # Recorded in rejected.jsonl, NOT the recoverable dead-letter file: a
        # permanent rejection must not come back on the next start().
        assert reporter._dlq.rejected_count == 3
        assert reporter._dlq.count == 0
        assert reporter.metrics["events_dropped"] == 3

    @pytest.mark.asyncio
    async def test_does_not_count_toward_the_circuit_breaker(self, tmp_path) -> None:
        reporter = _make_reporter(_status_handler(422, {"error": "schema"}), tmp_path)
        for _ in range(10):
            reporter.enqueue(_event())

        for _ in range(5):
            await reporter._flush()

        assert reporter._consecutive_failures == 0
        assert not reporter._is_circuit_open()
        assert reporter._circuit_open_until == 0.0

    @pytest.mark.asyncio
    async def test_a_422_does_not_stop_later_reporting(self, tmp_path) -> None:
        responses = [httpx.Response(422, json={"error": "schema"})]

        def handler(request: httpx.Request) -> httpx.Response:
            if responses:
                return responses.pop()
            return httpx.Response(200, json={"accepted": 1})

        reporter = _make_reporter(handler, tmp_path)
        reporter.enqueue(_event())
        await reporter._flush()
        reporter.enqueue(_event())
        await reporter._flush()

        assert reporter.metrics["events_sent"] == 1

    @pytest.mark.asyncio
    async def test_does_not_sleep_a_backoff(self, tmp_path) -> None:
        reporter = _make_reporter(_status_handler(401, {"error": "bad key"}), tmp_path)
        reporter.enqueue(_event())
        started = time.perf_counter()
        await reporter._flush()
        assert (time.perf_counter() - started) < 1.0

    @pytest.mark.asyncio
    async def test_logs_the_parsed_error_body(self, tmp_path, caplog) -> None:
        body = {
            "error": "Invalid event payload",
            "code": "VALIDATION_ERROR",
            "details": [{"path": ["events", 0, "model"], "message": "Expected string"}],
        }
        reporter = _make_reporter(_status_handler(422, body), tmp_path)
        reporter.enqueue(_event())

        with caplog.at_level("ERROR", logger="overrule.transport"):
            await reporter._flush()

        assert "Invalid event payload" in caplog.text
        assert "VALIDATION_ERROR" in caplog.text
        assert "Expected string" in caplog.text

    @pytest.mark.asyncio
    async def test_handles_a_non_json_error_body(self, tmp_path, caplog) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(422, content=b"<html>nope</html>")

        reporter = _make_reporter(handler, tmp_path)
        reporter.enqueue(_event())
        with caplog.at_level("ERROR", logger="overrule.transport"):
            await reporter._flush()
        assert reporter._dlq.rejected_count == 1


class TestPermanentRejectionIsNotAPoisonPill:
    """S4: permanent 4xx → DLQ → recover() on next start = infinite loop.

    `_handle_status_error` wrote permanently-rejected events to the *recoverable*
    dead-letter file, and `start()` calls `self._dlq.recover()` unconditionally. So
    every process restart re-POSTed the same rejected batch, got the same 401/422,
    wrote it back to disk and re-counted `events_dropped` — forever. That is worse
    than the bug it replaced, which dropped them exactly once.
    """

    @pytest.mark.parametrize("status_code", [400, 401, 403, 422])
    @pytest.mark.asyncio
    async def test_rejected_events_are_never_recovered(self, status_code, tmp_path) -> None:
        handler = _status_handler(status_code, {"error": "nope"})

        first = _make_reporter(handler, tmp_path)
        for _ in range(3):
            first.enqueue(_event())
        await first._flush()
        assert first._dlq.rejected_count == 3

        # A fresh process against the same directory must not pick them back up.
        for restart in range(3):
            later = _make_reporter(handler, tmp_path)
            recovered = later._dlq.recover()
            assert len(recovered) == 0, f"poison pill recovered on restart {restart + 1}"
            assert later.metrics["events_dropped"] == 0
            assert later.pending_count == 0

    @pytest.mark.asyncio
    async def test_rejected_events_are_still_retained_for_inspection(self, tmp_path) -> None:
        """Dropped from the retry path, not from disk: they remain diagnosable."""
        reporter = _make_reporter(_status_handler(401, {"error": "bad key"}), tmp_path)
        reporter.enqueue(_event())
        await reporter._flush()

        assert reporter._dlq.rejected_path.exists()
        lines = [
            json.loads(line)
            for line in reporter._dlq.rejected_path.read_text().splitlines()
            if line.strip()
        ]
        assert len(lines) == 1
        assert lines[0]["event_type"] == EventType.LLM_CALL.value
        assert "__retry_count" not in lines[0]

    @pytest.mark.asyncio
    async def test_a_transient_failure_is_still_recovered(self, tmp_path) -> None:
        """The retryable path must keep working — only permanent ones are excluded."""
        reporter = _make_reporter(_status_handler(500, {"error": "boom"}), tmp_path, max_retries=0)
        reporter._running = False  # skip the backoff sleep
        reporter.enqueue(_event())
        await reporter._flush()
        assert reporter._dlq.count == 1
        assert reporter._dlq.rejected_count == 0

        later = _make_reporter(_status_handler(500, {"error": "boom"}), tmp_path)
        assert len(later._dlq.recover()) == 1


class TestTransientFailuresStillRetry:
    @pytest.mark.asyncio
    async def test_500_is_requeued(self, tmp_path) -> None:
        reporter = _make_reporter(_status_handler(500, {"error": "boom"}), tmp_path)
        reporter._running = False  # skip the backoff sleep for the test
        reporter.enqueue(_event())

        await reporter._flush()

        assert reporter.pending_count == 1
        assert reporter._consecutive_failures == 1
        assert reporter._dlq.count == 0

    @pytest.mark.asyncio
    async def test_network_error_is_requeued(self, tmp_path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        reporter = _make_reporter(handler, tmp_path)
        reporter._running = False
        reporter.enqueue(_event())

        await reporter._flush()

        assert reporter.pending_count == 1
        assert reporter._consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_circuit_opens_after_repeated_5xx(self, tmp_path) -> None:
        reporter = _make_reporter(_status_handler(503), tmp_path)
        reporter._running = False
        reporter.enqueue(_event())

        for _ in range(3):
            await reporter._flush()

        assert reporter._consecutive_failures >= 3
        assert reporter._is_circuit_open()

    @pytest.mark.asyncio
    async def test_dead_letters_after_max_retries(self, tmp_path) -> None:
        reporter = _make_reporter(_status_handler(500), tmp_path, max_retries=1)
        reporter._running = False
        reporter.enqueue(_event())

        for _ in range(3):
            reporter._circuit_open_until = 0.0
            await reporter._flush()

        assert reporter._dlq.count == 1
        assert reporter.pending_count == 0


class TestRateLimiting:
    @pytest.mark.asyncio
    async def test_honours_retry_after(self, tmp_path, monkeypatch) -> None:
        slept: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            slept.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)
        reporter = _make_reporter(
            _status_handler(429, {"error": "slow down"}, {"Retry-After": "7"}), tmp_path
        )
        reporter.enqueue(_event())

        await reporter._flush()

        assert slept == [7.0]
        assert reporter.pending_count == 1  # still retryable

    @pytest.mark.asyncio
    async def test_falls_back_to_backoff_without_retry_after(self, tmp_path, monkeypatch) -> None:
        slept: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            slept.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)
        reporter = _make_reporter(_status_handler(429, {"error": "slow"}), tmp_path)
        reporter.enqueue(_event())

        await reporter._flush()

        assert len(slept) == 1
        assert slept[0] > 0

    @pytest.mark.asyncio
    async def test_ignores_a_garbage_retry_after(self, tmp_path, monkeypatch) -> None:
        slept: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            slept.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)
        reporter = _make_reporter(
            _status_handler(429, {}, {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
            tmp_path,
        )
        reporter.enqueue(_event())
        await reporter._flush()
        assert len(slept) == 1


class TestSuccessBodyIsParsed:
    @pytest.mark.asyncio
    async def test_uses_the_server_accepted_count(self, tmp_path) -> None:
        reporter = _make_reporter(_status_handler(200, {"accepted": 2}), tmp_path)
        for _ in range(3):
            reporter.enqueue(_event())

        await reporter._flush()

        assert reporter.metrics["events_sent"] == 2

    @pytest.mark.asyncio
    async def test_falls_back_to_batch_size_without_a_body(self, tmp_path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(204)

        reporter = _make_reporter(handler, tmp_path)
        for _ in range(3):
            reporter.enqueue(_event())

        await reporter._flush()

        assert reporter.metrics["events_sent"] == 3

    @pytest.mark.asyncio
    async def test_ignores_a_nonsense_accepted_count(self, tmp_path) -> None:
        reporter = _make_reporter(_status_handler(200, {"accepted": 99}), tmp_path)
        reporter.enqueue(_event())
        await reporter._flush()
        assert reporter.metrics["events_sent"] == 1

    @pytest.mark.asyncio
    async def test_partial_acceptance_is_logged(self, tmp_path, caplog) -> None:
        reporter = _make_reporter(_status_handler(200, {"accepted": 1}), tmp_path)
        for _ in range(3):
            reporter.enqueue(_event())
        with caplog.at_level("WARNING", logger="overrule.transport"):
            await reporter._flush()
        assert "accepted 1 of 3" in caplog.text


class TestShutdownPersistsBufferedEvents:
    @pytest.mark.asyncio
    async def test_pending_events_reach_the_dead_letter_queue(self, tmp_path) -> None:
        reporter = _make_reporter(_status_handler(500), tmp_path)
        for _ in range(5):
            reporter.enqueue(_event())

        await reporter.stop()

        assert reporter.pending_count == 0
        assert reporter._dlq.count == 5, "README promises failed events are persisted"

    @pytest.mark.asyncio
    async def test_events_beyond_one_batch_are_persisted(self, tmp_path) -> None:
        reporter = _make_reporter(_status_handler(503), tmp_path, batch_size=2)
        for _ in range(7):
            reporter.enqueue(_event())

        await reporter.stop()

        assert reporter._dlq.count == 7

    @pytest.mark.asyncio
    async def test_stop_does_not_wait_out_a_backoff(self, tmp_path) -> None:
        reporter = _make_reporter(_status_handler(500), tmp_path)
        reporter._consecutive_failures = 4  # backoff would be ~16-17s
        for _ in range(3):
            reporter.enqueue(_event())

        started = time.perf_counter()
        await reporter.stop()
        elapsed = time.perf_counter() - started

        assert elapsed < 2.0, f"shutdown blocked for {elapsed:.1f}s on a backoff sleep"

    @pytest.mark.asyncio
    async def test_successful_shutdown_sends_instead_of_dead_lettering(self, tmp_path) -> None:
        reporter = _make_reporter(_status_handler(200, {"accepted": 3}), tmp_path)
        for _ in range(3):
            reporter.enqueue(_event())

        await reporter.stop()

        assert reporter._dlq.count == 0
        assert reporter.metrics["events_sent"] == 3

    @pytest.mark.asyncio
    async def test_recovered_events_round_trip(self, tmp_path) -> None:
        reporter = _make_reporter(_status_handler(500), tmp_path)
        reporter.enqueue(_event())
        await reporter.stop()

        recovered = reporter._dlq.recover()
        assert len(recovered) == 1
        assert "__retry_count" not in recovered[0]
        assert recovered[0]["event_type"] == "llm_call"
