"""Violation models representing detected policy breaches."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_serializer

from overrule._compat import StrEnum

#: Metadata key holding the full, untruncated match. Needed in-process for redaction
#: (``matched_content`` is masked), but it is the customer's raw PII and must never
#: reach a log line, a ``repr()`` or a serialised payload.
RAW_MATCH_KEY = "raw_match"


class ViolationSeverity(StrEnum):
    """Severity levels for policy violations."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Violation(BaseModel):
    """A detected policy violation on an AI operation.

    ``matched_content`` is deliberately masked by the policies that set it, and
    ``metadata[RAW_MATCH_KEY]`` holds the full match for in-process redaction. Two
    guards keep that raw value from escaping:

    * :meth:`__repr__` mirrors :meth:`__str__` rather than dumping every field, so
      ``print(response.violations)`` no longer printed untruncated PII while
      ``matched_content`` on the very same object was masked;
    * a field serializer strips the key, so ``model_dump()`` /
      ``model_dump_json()`` — including when nested inside an ``InterceptEvent`` —
      cannot carry it either. The wire payload built by ``EventReporter`` never
      used it verbatim in the first place; this closes the direct-serialisation
      route callers reach for when logging events themselves.
    """

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

    def __repr__(self) -> str:
        return f"Violation({self})"

    @field_serializer("metadata")
    def _serialize_metadata(self, metadata: dict[str, Any]) -> dict[str, Any]:
        """Drop the verbatim match from every serialised form of this violation."""
        if RAW_MATCH_KEY not in metadata:
            return metadata
        return {key: value for key, value in metadata.items() if key != RAW_MATCH_KEY}
