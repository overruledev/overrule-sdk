"""Exception hierarchy for the overrule SDK."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from overrule.models.violation import Violation


class OverruleError(Exception):
    """Base exception for all overrule SDK errors."""


class ConfigurationError(OverruleError):
    """Raised when SDK configuration is invalid or incomplete."""


class TransportError(OverruleError):
    """Raised when event reporting to the cloud platform fails."""


class PolicyEvaluationError(OverruleError):
    """Raised when a policy crashes during evaluation."""

    def __init__(self, policy_id: str, original_error: Exception) -> None:
        self.policy_id = policy_id
        self.original_error = original_error
        super().__init__(
            f"Policy '{policy_id}' failed during evaluation: {original_error}"
        )


class ContentTooLargeError(OverruleError):
    """Raised when input content exceeds configured maximum length."""

    def __init__(self, content_length: int, max_length: int) -> None:
        self.content_length = content_length
        self.max_length = max_length
        super().__init__(
            f"Content length {content_length} exceeds maximum {max_length}"
        )


class ViolationError(OverruleError):
    """Raised when a policy violation blocks an operation."""

    def __init__(self, violations: list[Violation]) -> None:
        self.violations = violations
        messages = "; ".join(str(v) for v in violations)
        super().__init__(f"Blocked by policy: {messages}")
