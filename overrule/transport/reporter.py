"""Async event reporter — batches and ships events with retry and circuit breaking."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import random
import re
import time
from collections import deque
from typing import Any

import httpx

import overrule
from overrule.models.event import InterceptEvent
from overrule.models.violation import Violation
from overrule.transport.dead_letter import DeadLetterQueue

logger = logging.getLogger("overrule.transport")

_RETRY_KEY = "__retry_count"

#: Server-side limits. Exceeding either makes the server reject the whole batch
#: (there is also a DB CHECK constraint at 50 policies).
_MAX_POLICIES_PER_EVENT = 50
_MAX_VIOLATIONS_PER_EVENT = 100

#: 4xx statuses that will never succeed on retry. Retrying them burns the circuit
#: breaker and stops all reporting, so they are dead-lettered immediately.
_PERMANENT_STATUSES = frozenset({400, 401, 403, 422})

_ALNUM_RE = re.compile(r"[^\W_]", re.UNICODE)
_MASK_PREVIEW_CHARS = 64

#: Minimum gap between "buffer full" warnings. Once the buffer is saturated every
#: single enqueue overflows, so an unthrottled warning would itself become the outage.
_OVERFLOW_WARN_INTERVAL_SECONDS = 60.0


class EventReporter:
    """Asynchronous, batched event reporter with resilience patterns.

    Collects events in memory and flushes them to the cloud platform
    on a configurable interval or when the batch threshold is reached.

    Privacy: prompts and completions never leave your infrastructure. Neither
    ``input_content``/``output_content`` nor ``violation.metadata`` (which holds
    the full ``raw_match``) is serialised. Each violation is reported as a length
    plus a truncated SHA-256 of the match, so findings can be correlated and
    de-duplicated server-side without shipping the text itself. A *masked*,
    shape-only preview is included only when ``send_match_preview`` is enabled.

    Resilience:
        - Exponential backoff with jitter on transient failures
        - Circuit breaker pauses reporting after consecutive transient failures
        - Permanent 4xx responses are written to ``rejected.jsonl`` immediately and
          never retried — not even after a restart, so a bad key or a schema
          mismatch cannot become a poison pill that is re-POSTed forever
        - Dead-letter drop after max retries per event
        - Non-blocking enqueue on the hot path
        - Every event-loss path is counted in ``metrics["events_dropped"]``, including
          buffer overflow — the send buffer sheds its oldest event once full, so a
          saturated buffer is visible in metrics rather than silent
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
        environment: str | None = None,
        send_match_preview: bool = False,
    ) -> None:
        self._endpoint = endpoint.rstrip("/")
        self._api_key = api_key
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_retries = max_retries
        self._circuit_break_threshold = circuit_break_threshold
        self._circuit_break_cooldown = circuit_break_cooldown
        self._environment = environment
        self._send_match_preview = send_match_preview

        self._buffer: deque[dict[str, Any]] = deque(maxlen=buffer_max_size)
        self._client: httpx.AsyncClient | None = None
        self._flush_task: asyncio.Task[None] | None = None
        self._flush_lock: asyncio.Lock | None = None
        self._running = False

        # Circuit breaker state
        self._consecutive_failures = 0
        self._circuit_open_until: float = 0.0

        # Dead-letter queue for dropped events
        self._dlq = DeadLetterQueue()

        # Metrics
        self._events_sent = 0
        self._events_dropped = 0
        self._buffer_overflows = 0
        self._last_overflow_warning: float = 0.0

    async def start(self) -> None:
        """Initialize the HTTP client and start the flush loop."""
        if self._running:
            return
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": f"overrule-sdk/{overrule.__version__}",
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

        # Recover dead-letter events from previous runs
        recovered = self._dlq.recover()
        for event in recovered:
            self._append_bounded(event)

        self._flush_task = asyncio.create_task(self._flush_loop())

    async def stop(self) -> None:
        """Flush remaining events and shut down cleanly.

        Anything still buffered after the final flush attempt (a failed flush, or
        more events than one batch) is written to the dead-letter queue instead of
        being discarded at process exit — there is no further retry after this.
        """
        self._running = False
        task = self._flush_task
        self._flush_task = None
        if task is not None:
            # RuntimeError when the loop this task belongs to is already closed —
            # exactly the case when `atexit` drains a reporter whose Guard was
            # created inside `asyncio.run(main())`. It must not abort the drain below.
            try:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            except RuntimeError as exc:
                logger.debug("Flush task could not be awaited during stop: %s", exc)

        # Final flush attempts: drain as many full batches as we can make progress on.
        for _ in range(3):
            pending_before = len(self._buffer)
            if pending_before == 0:
                break
            try:
                await self._flush()
            except Exception as exc:
                # Anything unexpected here (e.g. an HTTP client bound to a closed
                # loop) must still fall through to the dead-letter drain rather than
                # discarding the buffer.
                logger.debug("Final flush attempt failed: %s", exc)
                break
            if len(self._buffer) >= pending_before:
                break  # no progress (failure or circuit open) — stop trying

        drained = 0
        while self._buffer:
            event = self._buffer.popleft()
            event.pop(_RETRY_KEY, None)
            self._dlq.write(event)
            drained += 1
        if drained:
            logger.warning(
                "Persisted %d unsent event(s) to the dead-letter queue on shutdown", drained
            )

        if self._client:
            client, self._client = self._client, None
            with contextlib.suppress(Exception):
                await client.aclose()

    def enqueue(self, event: InterceptEvent) -> None:
        """Add an event to the send buffer. Non-blocking, never raises."""
        try:
            self._append_bounded(self.serialize(event))
        except Exception as exc:
            self._events_dropped += 1
            logger.debug("Failed to enqueue event, dropping it: %s", exc)

    def _append_bounded(self, payload: dict[str, Any]) -> None:
        """Append to the send buffer, *accounting for* any event this evicts.

        ``deque(maxlen=...)`` silently discards the oldest entry once it is full, which
        made this the one event-loss path that never showed up in :attr:`metrics`. The
        drop-oldest behaviour is kept deliberately — under sustained backpressure the
        newest governance events are the useful ones — but it is now counted in
        ``events_dropped`` and warned about, so loss is observable rather than invisible.

        The warning is throttled and no dead-letter write happens here on purpose:
        ``enqueue`` sits on the caller's request path and must stay non-blocking.
        """
        maxlen = self._buffer.maxlen
        if maxlen is not None and len(self._buffer) >= maxlen:
            self._events_dropped += 1
            self._buffer_overflows += 1
            self._warn_overflow(maxlen)
        self._buffer.append(payload)

    def _warn_overflow(self, maxlen: int) -> None:
        """Warn that the buffer is shedding events, at most once per interval."""
        now = time.monotonic()
        if now - self._last_overflow_warning < _OVERFLOW_WARN_INTERVAL_SECONDS:
            return
        self._last_overflow_warning = now
        logger.warning(
            "Event buffer full (%d events): discarding the oldest event to make room. "
            "%d event(s) dropped this way so far — the platform is unreachable or "
            "events are being produced faster than they can be flushed.",
            maxlen,
            self._buffer_overflows,
        )

    def serialize(self, event: InterceptEvent) -> dict[str, Any]:
        """Build the wire payload for an event.

        Optional fields are *omitted* when unset rather than sent as JSON ``null``
        (the server's schema uses ``.optional()``, which rejects ``null`` and with
        it the entire batch of up to 50 events).
        """
        payload: dict[str, Any] = {
            # `id` lets the server dedupe retried batches; without it a lost
            # response double-counts the customer's quota.
            "id": event.id,
            # `timestamp` preserves when the event happened — otherwise every event
            # is stamped at ingest time, skewing time series after a DLQ recovery.
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type.value,
            "status": event.status.value,
            "model": event.model,
            "provider": event.provider,
            "input_tokens": event.input_tokens,
            "output_tokens": event.output_tokens,
            # `is not None`: a legitimate 0.0 must not collapse to null.
            "latency_ms": round(event.latency_ms) if event.latency_ms is not None else None,
            "policies_applied": event.policies_applied[:_MAX_POLICIES_PER_EVENT],
            "violations": [
                self._serialize_violation(v) for v in event.violations[:_MAX_VIOLATIONS_PER_EVENT]
            ],
            "metadata": event.metadata,
            "environment": self._environment,
        }
        if len(event.policies_applied) > _MAX_POLICIES_PER_EVENT:
            logger.warning(
                "Event %s lists %d policies; truncated to the server limit of %d",
                event.id,
                len(event.policies_applied),
                _MAX_POLICIES_PER_EVENT,
            )
        if len(event.violations) > _MAX_VIOLATIONS_PER_EVENT:
            logger.warning(
                "Event %s carries %d violations; truncated to the server limit of %d",
                event.id,
                len(event.violations),
                _MAX_VIOLATIONS_PER_EVENT,
            )
        return {k: v for k, v in payload.items() if v is not None}

    def _serialize_violation(self, violation: Violation) -> dict[str, Any]:
        """Serialize a violation without shipping the customer's text."""
        raw = violation.metadata.get("raw_match")
        if not isinstance(raw, str) or not raw:
            raw = violation.matched_content or ""

        payload: dict[str, Any] = {
            "policy_id": violation.policy_id,
            "severity": violation.severity.value,
            "description": violation.message,
            # Clamped: the server field is z.enum(["input","output"]) and an
            # unexpected value destroys the whole batch.
            "direction": ("output" if violation.metadata.get("direction") == "output" else "input"),
            "match_len": len(raw),
            "match_sha256": (
                hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16] if raw else None
            ),
            "match_type": self._match_label(violation),
        }
        if self._send_match_preview and raw:
            # Opt-in only, and shape-preserving rather than verbatim.
            payload["matched_content"] = self._mask_preview(raw)
        return {k: v for k, v in payload.items() if v is not None}

    @staticmethod
    def _match_label(violation: Violation) -> str | None:
        """The pattern/type label a policy attached, e.g. "ssn" or "sql_injection"."""
        for key in ("type", "pattern", "category", "rule"):
            value = violation.metadata.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _mask_preview(raw: str) -> str:
        """Mask a match so only its shape survives (``123-45-6789`` → ``***-**-****``)."""
        return _ALNUM_RE.sub("*", raw[:_MASK_PREVIEW_CHARS])

    @property
    def pending_count(self) -> int:
        """Number of events waiting to be sent."""
        return len(self._buffer)

    @property
    def metrics(self) -> dict[str, int]:
        """Reporter health metrics.

        ``events_dropped`` counts *every* event-loss path: permanent 4xx rejections,
        retry exhaustion, serialisation failures, and buffer overflow.
        ``buffer_overflows`` breaks out just the overflow share of that total.
        """
        return {
            "events_sent": self._events_sent,
            "events_dropped": self._events_dropped,
            "events_pending": len(self._buffer),
            "buffer_overflows": self._buffer_overflows,
            "buffer_capacity": self._buffer.maxlen or 0,
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

        backoff: float | None = None

        async with self._flush_lock:
            batch: list[dict[str, Any]] = []
            while self._buffer and len(batch) < self._batch_size:
                batch.append(self._buffer.popleft())

            if not batch:
                return

            try:
                clean_batch = [{k: v for k, v in e.items() if k != _RETRY_KEY} for e in batch]
                response = await self._client.post("/v1/events", json={"events": clean_batch})
                response.raise_for_status()
                self._consecutive_failures = 0
                accepted = self._parse_accepted(response, len(batch))
                self._events_sent += accepted
                if accepted != len(batch):
                    logger.warning("Server accepted %d of %d events in batch", accepted, len(batch))
                else:
                    logger.debug("Flushed %d events successfully", accepted)
            except httpx.HTTPStatusError as exc:
                backoff = self._handle_status_error(exc, batch)
            except httpx.RequestError as exc:
                backoff = self._handle_transient_failure(f"network error: {exc}", batch)

        # Never sleep out a backoff during shutdown — it delays process exit by up
        # to 30s and there is nothing left to retry against.
        if backoff is not None and self._running:
            await asyncio.sleep(backoff)

    def _handle_status_error(
        self, exc: httpx.HTTPStatusError, batch: list[dict[str, Any]]
    ) -> float | None:
        """Branch on the response status: permanent vs. retryable."""
        status_code = exc.response.status_code
        body = self._parse_error_body(exc.response)

        if status_code in _PERMANENT_STATUSES:
            logger.error(
                "Event ingest rejected permanently (HTTP %d): error=%s code=%s details=%s. "
                "Recording %d event(s) in %s without retry — check the API key and the "
                "event schema.",
                status_code,
                body.get("error"),
                body.get("code"),
                body.get("details"),
                len(batch),
                self._dlq.rejected_path,
            )
            for event in batch:
                event.pop(_RETRY_KEY, None)
                # `permanent=True`: kept for inspection but never recovered. Writing
                # these to the retryable queue made every restart re-POST the same
                # rejected batch forever — worse than dropping them once.
                self._dlq.write(event, permanent=True)
                self._events_dropped += 1
            # Deliberately does not touch the circuit breaker: a bad key or a
            # schema mismatch is not a transport outage.
            return None

        if status_code == 429:
            retry_after = self._parse_retry_after(exc.response)
            backoff = self._handle_transient_failure(
                f"rate limited (HTTP 429): error={body.get('error')} code={body.get('code')}",
                batch,
            )
            return retry_after if retry_after is not None else backoff

        return self._handle_transient_failure(
            f"HTTP {status_code}: error={body.get('error')} code={body.get('code')} "
            f"details={body.get('details')}",
            batch,
        )

    def _handle_transient_failure(self, reason: str, batch: list[dict[str, Any]]) -> float:
        """Count a retryable failure, requeue the batch, and return a backoff."""
        self._consecutive_failures += 1
        logger.warning(
            "Failed to flush events (attempt %d): %s", self._consecutive_failures, reason
        )

        if self._consecutive_failures >= self._circuit_break_threshold:
            self._circuit_open_until = time.monotonic() + self._circuit_break_cooldown
            logger.warning(
                "Circuit breaker opened for %.1fs after %d consecutive failures",
                self._circuit_break_cooldown,
                self._consecutive_failures,
            )

        self._requeue_or_dead_letter(batch)
        jitter: float = random.uniform(0, 1)  # noqa: S311 - jitter, not crypto
        return min(float(2**self._consecutive_failures) + jitter, 30.0)

    def _requeue_or_dead_letter(self, batch: list[dict[str, Any]]) -> None:
        """Put events back for another attempt, or persist them once retries run out."""
        for event in reversed(batch):
            retry_count = event.get(_RETRY_KEY, 0) + 1
            if retry_count <= self._max_retries:
                event[_RETRY_KEY] = retry_count
                if len(self._buffer) < (self._buffer.maxlen or 10_000):
                    self._buffer.appendleft(event)
                else:
                    self._dlq.write(event)
                    self._events_dropped += 1
            else:
                self._events_dropped += 1
                event.pop(_RETRY_KEY, None)
                self._dlq.write(event)
                logger.debug("Event persisted to dead-letter after %d retries", self._max_retries)

    @staticmethod
    def _parse_error_body(response: httpx.Response) -> dict[str, Any]:
        """Parse the server's ``{error, code, details}`` body. Never raises.

        Nothing in the SDK used to read a response body, which is exactly why a
        schema-mismatch 422 was invisible in production.
        """
        try:
            parsed = response.json()
        except Exception:
            text = (response.text or "").strip()
            return {"error": text[:500] or None, "code": None, "details": None}
        if isinstance(parsed, dict):
            return {
                "error": parsed.get("error") or parsed.get("message"),
                "code": parsed.get("code"),
                "details": parsed.get("details"),
            }
        return {"error": str(parsed)[:500], "code": None, "details": None}

    @staticmethod
    def _parse_accepted(response: httpx.Response, default: int) -> int:
        """Use the server's ``accepted`` count for the events_sent metric."""
        try:
            parsed = response.json()
        except Exception:
            return default
        if isinstance(parsed, dict):
            accepted = parsed.get("accepted")
            if isinstance(accepted, bool):
                return default
            if isinstance(accepted, int) and 0 <= accepted <= default:
                return accepted
        return default

    @staticmethod
    def _parse_retry_after(response: httpx.Response) -> float | None:
        """Honour a ``Retry-After`` header expressed in seconds."""
        raw = response.headers.get("Retry-After")
        if not raw:
            return None
        try:
            seconds = float(raw.strip())
        except ValueError:
            return None
        if seconds < 0:
            return None
        return min(seconds, 300.0)

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
