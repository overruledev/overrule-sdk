"""Async event reporter — batches and ships events with retry and circuit breaking."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import time
from collections import deque
from typing import Any

import httpx

import overrule
from overrule.models.event import InterceptEvent

logger = logging.getLogger("overrule.transport")

_RETRY_KEY = "__retry_count"


class EventReporter:
    """Asynchronous, batched event reporter with resilience patterns.

    Collects events in memory and flushes them to the cloud platform
    on a configurable interval or when the batch threshold is reached.

    Resilience:
        - Exponential backoff with jitter on failures
        - Circuit breaker pauses reporting after consecutive failures
        - Dead-letter drop after max retries per event
        - Non-blocking enqueue on the hot path
    """

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str | None = None,
        batch_size: int = 50,
        flush_interval: float = 5.0,
        max_retries: int = 3,
        circuit_break_threshold: int = 5,
        circuit_break_cooldown: float = 30.0,
        buffer_max_size: int = 10_000,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_retries = max_retries
        self._circuit_break_threshold = circuit_break_threshold
        self._circuit_break_cooldown = circuit_break_cooldown

        self._buffer: deque[dict[str, Any]] = deque(maxlen=buffer_max_size)
        self._client: httpx.AsyncClient | None = None
        self._flush_task: asyncio.Task[None] | None = None
        self._flush_lock: asyncio.Lock | None = None
        self._running = False

        # Circuit breaker state
        self._consecutive_failures = 0
        self._circuit_open_until: float = 0.0

        # Metrics
        self._events_sent = 0
        self._events_dropped = 0

    async def start(self) -> None:
        """Initialize the HTTP client and start the flush loop."""
        if self._running:
            return
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": f"overrule-python/{overrule.__version__}",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        self._client = httpx.AsyncClient(
            base_url=self._endpoint,
            headers=headers,
            timeout=httpx.Timeout(10.0, connect=5.0),
        )
        self._flush_lock = asyncio.Lock()
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        """Flush remaining events and shut down cleanly."""
        self._running = False
        if self._flush_task:
            self._flush_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._flush_task
        # Final flush attempt
        await self._flush()
        if self._client:
            await self._client.aclose()
            self._client = None

    def enqueue(self, event: InterceptEvent) -> None:
        """Add an event to the send buffer. Non-blocking, never raises."""
        try:
            self._buffer.append(event.model_dump(mode="json"))
        except Exception:
            logger.debug("Failed to enqueue event, dropping silently")

    @property
    def pending_count(self) -> int:
        """Number of events waiting to be sent."""
        return len(self._buffer)

    @property
    def metrics(self) -> dict[str, int]:
        """Reporter health metrics."""
        return {
            "events_sent": self._events_sent,
            "events_dropped": self._events_dropped,
            "events_pending": len(self._buffer),
            "consecutive_failures": self._consecutive_failures,
        }

    # ─── Internal ─────────────────────────────────────────────────────

    async def _flush_loop(self) -> None:
        """Periodically flush buffered events."""
        while self._running:
            await asyncio.sleep(self._flush_interval)
            await self._flush()

    async def _flush(self) -> None:
        """Send buffered events to the platform with retry logic."""
        if not self._buffer or not self._client:
            return
        if self._flush_lock is None:
            return

        if self._is_circuit_open():
            logger.debug(
                "Circuit breaker open, skipping flush (cooldown %.1fs remaining)",
                self._circuit_open_until - time.monotonic(),
            )
            return

        needs_backoff = False

        async with self._flush_lock:
            batch: list[dict[str, Any]] = []
            while self._buffer and len(batch) < self._batch_size:
                batch.append(self._buffer.popleft())

            if not batch:
                return

            try:
                response = await self._client.post(
                    "/v1/events", json={"events": batch}
                )
                response.raise_for_status()
                self._consecutive_failures = 0
                self._events_sent += len(batch)
                logger.debug("Flushed %d events successfully", len(batch))
            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                self._consecutive_failures += 1
                logger.warning(
                    "Failed to flush events (attempt %d): %s",
                    self._consecutive_failures,
                    exc,
                )

                if self._consecutive_failures >= self._circuit_break_threshold:
                    self._circuit_open_until = (
                        time.monotonic() + self._circuit_break_cooldown
                    )
                    logger.warning(
                        "Circuit breaker opened for %.1fs after %d consecutive failures",
                        self._circuit_break_cooldown,
                        self._consecutive_failures,
                    )

                for event in reversed(batch):
                    retry_count = event.get(_RETRY_KEY, 0) + 1
                    if retry_count <= self._max_retries:
                        event[_RETRY_KEY] = retry_count
                        self._buffer.appendleft(event)
                    else:
                        self._events_dropped += 1
                        logger.debug(
                            "Event dropped after %d retries", self._max_retries
                        )

                needs_backoff = True

        if needs_backoff:
            backoff = min(
                2**self._consecutive_failures + random.uniform(0, 1),  # noqa: S311
                30.0,
            )
            await asyncio.sleep(backoff)

    def _is_circuit_open(self) -> bool:
        """Check if the circuit breaker is currently open."""
        if self._circuit_open_until <= 0:
            return False
        if time.monotonic() >= self._circuit_open_until:
            # Cooldown expired, half-open: allow one attempt
            self._circuit_open_until = 0.0
            self._consecutive_failures = 0
            return False
        return True
