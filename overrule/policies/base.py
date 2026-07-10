"""Base policy interface — all policies implement this contract."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel

from overrule.models.violation import Violation


class PolicyResult(BaseModel):
    """Result of evaluating content against a policy."""

    passed: bool
    violations: list[Violation] = []
    execution_time_ms: float = 0.0


class BasePolicy(ABC):
    """Abstract base class for all governance policies.

    Subclass this to implement custom policy checks. Each policy must
    define a unique `policy_id` and implement the `evaluate` method.
    """

    policy_id: str
    description: str

    def __init__(self, parameters: dict[str, Any] | None = None) -> None:
        self._parameters = parameters or {}

    @abstractmethod
    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        """Evaluate content against this policy.

        Args:
            content: The text content to check.
            direction: Whether this is "input" (to the model) or "output" (from the model).

        Returns:
            PolicyResult indicating pass/fail with any violations.
        """
        ...

    def configure(self, parameters: dict[str, Any]) -> None:
        """Update policy parameters at runtime."""
        self._parameters.update(parameters)
