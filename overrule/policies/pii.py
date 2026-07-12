"""PII detection policy — identifies personally identifiable information in content."""

from __future__ import annotations

import re
import time
from typing import Any

from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies.base import BasePolicy, PolicyResult

# Precompiled regex patterns for PII detection.
# Patterns are intentionally strict to minimize false positives in production.
_PII_PATTERNS: dict[str, tuple[re.Pattern[str], ViolationSeverity, str]] = {
    "credit_card": (
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|"
            r"3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|"
            r"(?:2131|1800|35\d{3})\d{11})\b"
        ),
        ViolationSeverity.CRITICAL,
        "Credit card number detected",
    ),
    "ssn": (
        re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        ViolationSeverity.CRITICAL,
        "Social Security Number detected",
    ),
    "email": (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        ViolationSeverity.MEDIUM,
        "Email address detected",
    ),
    "phone_us": (
        re.compile(
            r"(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}"
        ),
        ViolationSeverity.MEDIUM,
        "US phone number detected",
    ),
    "phone_international": (
        re.compile(r"\+[1-9]\d{0,2}[-.\s]?\d{1,4}[-.\s]?\d{3,5}[-.\s]?\d{3,5}"),
        ViolationSeverity.MEDIUM,
        "International phone number detected",
    ),
    "ip_address": (
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
        ViolationSeverity.LOW,
        "IP address detected",
    ),
    "iban": (
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"),
        ViolationSeverity.HIGH,
        "IBAN number detected",
    ),
    "passport_us": (
        re.compile(r"\b[A-Z]\d{8}\b"),
        ViolationSeverity.HIGH,
        "US passport number pattern detected",
    ),
}


class PIIPolicy(BasePolicy):
    """Detects personally identifiable information in AI inputs and outputs."""

    policy_id = "pii-detection"
    description = "Scans for PII patterns including credit cards, SSNs, emails, and phone numbers."

    def __init__(self, parameters: dict[str, Any] | None = None) -> None:
        super().__init__(parameters)
        self._enabled_patterns = self._resolve_patterns()

    def _resolve_patterns(self) -> dict[str, tuple[re.Pattern[str], ViolationSeverity, str]]:
        """Resolve which PII patterns to check based on configuration."""
        disabled: set[str] = set(self._parameters.get("disabled_patterns", []))
        return {k: v for k, v in _PII_PATTERNS.items() if k not in disabled}

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        start = time.perf_counter()
        violations: list[Violation] = []

        for pattern_name, (pattern, severity, message) in self._enabled_patterns.items():
            matches = pattern.findall(content)
            if matches:
                for match in matches:
                    matched_text = match if isinstance(match, str) else match[0]
                    violations.append(
                        Violation(
                            policy_id=self.policy_id,
                            severity=severity,
                            message=f"{message} in {direction}",
                            matched_content=self._redact(matched_text),
                            metadata={
                                "pattern": pattern_name,
                                "direction": direction,
                                "raw_match": matched_text,
                            },
                        )
                    )

        elapsed_ms = (time.perf_counter() - start) * 1000
        return PolicyResult(
            passed=len(violations) == 0,
            violations=violations,
            execution_time_ms=elapsed_ms,
        )

    @staticmethod
    def _redact(value: str) -> str:
        """Redact matched content for safe logging. Shows only last 4 chars."""
        if len(value) <= 4:
            return "****"
        return "*" * (len(value) - 4) + value[-4:]
