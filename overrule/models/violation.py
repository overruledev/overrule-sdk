"""Violation models representing detected policy breaches."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class ViolationSeverity(StrEnum):
    """Severity levels for policy violations."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Violation(BaseModel):
    """A detected policy violation on an AI operation."""

    id: str = Field(default_factory=lambda: uuid4().hex)
    policy_id: str
    severity: ViolationSeverity
    message: str
    matched_content: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    blocked: bool = False

    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.policy_id}: {self.message}"
