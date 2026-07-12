"""Event models representing AI operations intercepted by the SDK."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from overrule.models.violation import Violation


class EventType(StrEnum):
    """Types of AI operations the SDK can intercept."""

    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    RETRIEVAL = "retrieval"
    AGENT_STEP = "agent_step"


class EventStatus(StrEnum):
    """Outcome status of an intercepted event."""

    PASSED = "passed"
    FLAGGED = "flagged"
    BLOCKED = "blocked"


class InterceptEvent(BaseModel):
    """Record of an intercepted AI operation and its evaluation result."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    event_type: EventType
    status: EventStatus = EventStatus.PASSED
    input_content: str | None = None
    output_content: str | None = None
    model: str | None = None
    provider: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    latency_ms: float | None = None
    policies_applied: list[str] = Field(default_factory=list)
    violations: list[Violation] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0

    @property
    def is_blocked(self) -> bool:
        return self.status == EventStatus.BLOCKED
