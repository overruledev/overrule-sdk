"""overrule — Runtime AI governance SDK.

Intercept, evaluate, and enforce compliance policies on LLM calls
and agent tool executions in real-time.

Usage:
    from overrule import Guard, SyncGuard

    # Async
    async with Guard(api_key="sk-...") as guard:
        response = await guard.chat(model="gpt-4", messages=[...])

    # Sync
    with SyncGuard(api_key="sk-...") as guard:
        response = guard.chat(model="gpt-4", messages=[...])

    # Protect functions
    @guard.protect(policies=["pii-detection"])
    def my_tool(input: str) -> str:
        ...
"""

from overrule.exceptions import (
    ConfigurationError,
    ContentTooLargeError,
    OverruleError,
    PolicyEvaluationError,
    TransportError,
    ViolationError,
)
from overrule.guard import Guard
from overrule.models.config import GuardConfig, PolicyAction, PolicyConfig
from overrule.models.event import EventStatus, EventType, InterceptEvent
from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies.base import BasePolicy, PolicyResult
from overrule.policies.injection import InjectionPolicy
from overrule.policies.pii import PIIPolicy
from overrule.policies.registry import PolicyRegistry
from overrule.policies.toxicity import ToxicityPolicy
from overrule.sync import SyncGuard

__version__ = "0.2.0"

__all__ = [
    # Core
    "Guard",
    "SyncGuard",
    # Configuration
    "GuardConfig",
    "PolicyConfig",
    "PolicyAction",
    # Models
    "Violation",
    "ViolationSeverity",
    "InterceptEvent",
    "EventType",
    "EventStatus",
    # Policies
    "BasePolicy",
    "PolicyResult",
    "PolicyRegistry",
    "PIIPolicy",
    "InjectionPolicy",
    "ToxicityPolicy",
    # Exceptions
    "OverruleError",
    "ViolationError",
    "ConfigurationError",
    "TransportError",
    "PolicyEvaluationError",
    "ContentTooLargeError",
]
