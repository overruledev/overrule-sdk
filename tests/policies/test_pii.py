"""Tests for PII detection policy."""

import pytest

from overrule.models.violation import ViolationSeverity
from overrule.policies.pii import PIIPolicy


@pytest.fixture
def policy() -> PIIPolicy:
    return PIIPolicy()


class TestCreditCardDetection:
    def test_detects_visa(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("My card is 4111111111111111")
        assert not result.passed
        assert result.violations[0].severity == ViolationSeverity.CRITICAL
        assert "credit_card" in result.violations[0].metadata["pattern"]

    def test_detects_mastercard(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Pay with 5500000000000004")
        assert not result.passed

    def test_detects_amex(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Amex: 378282246310005")
        assert not result.passed

    def test_ignores_random_numbers(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Order #123456789 was placed")
        assert result.passed


class TestSSNDetection:
    def test_detects_valid_ssn(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("SSN: 123-45-6789")
        assert not result.passed
        assert result.violations[0].severity == ViolationSeverity.CRITICAL

    def test_ignores_invalid_ssn_000(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Not a SSN: 000-12-3456")
        assert result.passed

    def test_ignores_invalid_ssn_666(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Not a SSN: 666-12-3456")
        assert result.passed


class TestEmailDetection:
    def test_detects_email(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Contact me at john@example.com please")
        assert not result.passed
        assert result.violations[0].severity == ViolationSeverity.MEDIUM

    def test_ignores_non_email(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("This is not@an email at all")
        assert result.passed


class TestPhoneDetection:
    def test_detects_us_phone(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Call me at (415) 555-4567")
        assert not result.passed

    def test_detects_international_phone(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Reach me at +44 20 7946 0958")
        assert not result.passed


class TestIPAddressDetection:
    def test_detects_ipv4(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Server at 192.168.1.100")
        assert not result.passed
        assert result.violations[0].severity == ViolationSeverity.LOW

    def test_ignores_invalid_ip(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("Version 999.999.999.999 released")
        assert result.passed


class TestRedaction:
    def test_redacts_matched_content(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("SSN: 123-45-6789")
        assert "****" in (result.violations[0].matched_content or "")
        assert "123-45-6789" not in (result.violations[0].matched_content or "")


class TestConfiguration:
    def test_disable_specific_pattern(self) -> None:
        policy = PIIPolicy(parameters={"disabled_patterns": ["email"]})
        result = policy.evaluate("Contact john@example.com")
        assert result.passed

    def test_multiple_violations(self, policy: PIIPolicy) -> None:
        content = "SSN: 123-45-6789, card: 4111111111111111, email: test@foo.com"
        result = policy.evaluate(content)
        assert not result.passed
        assert len(result.violations) >= 3


class TestPerformance:
    def test_evaluation_under_5ms(self, policy: PIIPolicy) -> None:
        content = "A" * 10_000
        result = policy.evaluate(content)
        assert result.execution_time_ms < 5.0

    def test_handles_empty_string(self, policy: PIIPolicy) -> None:
        result = policy.evaluate("")
        assert result.passed
        assert len(result.violations) == 0
