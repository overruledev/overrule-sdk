"""Tests for policy hot-reload functionality."""

from __future__ import annotations

import pytest

from overrule import Guard
from overrule.policies.base import BasePolicy, PolicyResult
from overrule.models.violation import Violation, ViolationSeverity


class MockPolicy(BasePolicy):
    policy_id = "mock-policy"
    description = "Test policy for reload"

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        if "blocked" in content.lower():
            return PolicyResult(
                passed=False,
                violations=[
                    Violation(
                        policy_id=self.policy_id,
                        severity=ViolationSeverity.HIGH,
                        message="Mock violation triggered",
                    )
                ],
            )
        return PolicyResult(passed=True, violations=[])


class MockPolicyV2(BasePolicy):
    policy_id = "mock-policy"
    description = "Updated version of test policy"

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        if "updated" in content.lower():
            return PolicyResult(
                passed=False,
                violations=[
                    Violation(
                        policy_id=self.policy_id,
                        severity=ViolationSeverity.CRITICAL,
                        message="V2 violation triggered",
                    )
                ],
            )
        return PolicyResult(passed=True, violations=[])


@pytest.fixture
def guard():
    return Guard(api_key="test", fail_open=True)


async def test_register_and_use_custom_policy(guard: Guard):
    """Custom policy can be registered and used."""
    await guard._ensure_initialized()
    guard.register_policy(MockPolicy)

    result = await guard.evaluate("This is blocked content", policies=["mock-policy"])
    assert not result.passed
    assert result.violations[0].message == "Mock violation triggered"


async def test_unregister_policy(guard: Guard):
    """Policy can be unregistered."""
    await guard._ensure_initialized()
    guard.register_policy(MockPolicy)

    guard.unregister_policy("mock-policy")

    with pytest.raises(ValueError, match="Unknown policy"):
        await guard.evaluate("blocked", policies=["mock-policy"])


async def test_reload_single_policy(guard: Guard):
    """Reload recreates a specific policy instance."""
    await guard._ensure_initialized()
    guard.register_policy(MockPolicy)

    # Use the policy to cache instance
    result = await guard.evaluate("blocked", policies=["mock-policy"])
    assert not result.passed

    # Re-register with V2 and reload
    guard.register_policy(MockPolicyV2)
    guard.reload_policies("mock-policy")

    # Now "blocked" should pass (V2 only triggers on "updated")
    result = await guard.evaluate("blocked", policies=["mock-policy"])
    assert result.passed

    # "updated" should now trigger
    result = await guard.evaluate("updated content", policies=["mock-policy"])
    assert not result.passed
    assert result.violations[0].severity == ViolationSeverity.CRITICAL


async def test_reload_all_policies(guard: Guard):
    """Reload all clears all cached instances."""
    await guard._ensure_initialized()
    guard.register_policy(MockPolicy)

    # Trigger caching
    await guard.evaluate("blocked", policies=["mock-policy"])

    # Reload all
    guard.reload_policies()

    # Should still work (recreates from registered class)
    result = await guard.evaluate("blocked", policies=["mock-policy"])
    assert not result.passed


async def test_builtin_policies_still_work_after_reload(guard: Guard):
    """Built-in policies work after a full reload."""
    await guard._ensure_initialized()

    guard.reload_policies()

    result = await guard.evaluate(
        "My SSN is 123-45-6789", policies=["pii-detection"]
    )
    assert not result.passed


async def test_available_policies_list(guard: Guard):
    """Available property lists all registered policy IDs."""
    await guard._ensure_initialized()
    guard.register_policy(MockPolicy)

    available = guard._registry.available
    assert "pii-detection" in available
    assert "injection-detection" in available
    assert "toxicity-detection" in available
    assert "mock-policy" in available
