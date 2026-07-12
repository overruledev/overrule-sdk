"""Policy registry — manages policy lifecycle and lookup with thread safety."""

from __future__ import annotations

import threading
from typing import Any

from overrule.policies.base import BasePolicy
from overrule.policies.injection import InjectionPolicy
from overrule.policies.pii import PIIPolicy
from overrule.policies.toxicity import ToxicityPolicy


class PolicyRegistry:
    """Central registry for all available policies.

    Handles registration, lookup, and instantiation of policy implementations.
    Supports both built-in and custom user-defined policies. Thread-safe.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._policies: dict[str, type[BasePolicy]] = {}
        self._instances: dict[str, BasePolicy] = {}
        self._register_builtins()

    def _register_builtins(self) -> None:
        """Register all built-in policies."""
        self.register(PIIPolicy)
        self.register(InjectionPolicy)
        self.register(ToxicityPolicy)

    def register(self, policy_cls: type[BasePolicy]) -> None:
        """Register a policy class by its policy_id."""
        with self._lock:
            self._policies[policy_cls.policy_id] = policy_cls
            # Invalidate cached instance if re-registering
            self._instances.pop(policy_cls.policy_id, None)

    def get(self, policy_id: str, parameters: dict[str, Any] | None = None) -> BasePolicy:
        """Get or create a policy instance by ID. Thread-safe."""
        with self._lock:
            if policy_id not in self._instances:
                if policy_id not in self._policies:
                    raise ValueError(
                        f"Unknown policy: '{policy_id}'. "
                        f"Available: {list(self._policies.keys())}"
                    )
                self._instances[policy_id] = self._policies[policy_id](parameters)
            return self._instances[policy_id]

    def resolve(self, policy_ids: list[str]) -> list[BasePolicy]:
        """Resolve a list of policy IDs to policy instances."""
        return [self.get(pid) for pid in policy_ids]

    @property
    def available(self) -> list[str]:
        """List all registered policy IDs."""
        with self._lock:
            return list(self._policies.keys())
