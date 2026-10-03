"""Event models representing AI operations intercepted by the SDK."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from overrule._compat import StrEnum
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
    #: Governance was bypassed because an internal SDK error occurred while
    #: ``fail_open=True``. Emitted so the reliability dashboard can distinguish
    #: "healthy" from "silently not evaluating anything".
    FAIL_OPEN = "fail_open"


class InterceptEvent(BaseModel):
    """Record of an intercepted AI operation and its evaluation result."""

    # Canonical dashed UUID form. The ingest API validates this field with a
    # strict UUID schema, which rejects the bare 32-char hex form -- sending
    # `uuid4().hex` here 422s the entire batch, not just the one event.
    id: str = Field(default_factory=lambda: str(uuid4()))
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
