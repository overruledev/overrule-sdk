"""Test doubles shared across the suite."""

from __future__ import annotations

from typing import Any

from overrule.models.event import InterceptEvent


class RecordingReporter:
    """Captures enqueued events instead of shipping them."""

    def __init__(self) -> None:
        self.events: list[InterceptEvent] = []

    def enqueue(self, event: InterceptEvent) -> None:
        self.events.append(event)

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    def statuses(self) -> list[str]:
        return [e.status.value for e in self.events]


class ExplodingReporter:
    """A reporter whose telemetry path is completely broken."""

    def __init__(self) -> None:
        self.calls = 0

    def enqueue(self, event: Any) -> None:
        self.calls += 1
        raise RuntimeError("telemetry backend unavailable")

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None
