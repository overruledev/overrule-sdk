"""PII detection policy — identifies personally identifiable information in content."""

from __future__ import annotations

import re
import time
from typing import Any

from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies.base import BasePolicy, PolicyResult


def _luhn_check(number: str) -> bool:
    """Validate a card number using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# Context patterns that indicate an IP-like string is actually a version number.
_VERSION_CONTEXT_RE = re.compile(
    r"(?:v(?:ersion)?|release|build|update)[\s:=]*$|"
    r"^\s*[-/]",
    re.I,
)

# Precompiled regex patterns for PII detection.
_PII_PATTERNS: dict[str, tuple[re.Pattern[str], ViolationSeverity, str]] = {
    "credit_card": (
        re.compile(
            r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))"
            r"[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{3,4}\b"
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
        re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,3}\.[A-Za-z]{2,12}\b"),
        ViolationSeverity.MEDIUM,
        "Email address detected",
    ),
    "phone_us": (
        re.compile(
            r"(?<!\d)(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}(?!\d)"
        ),
        ViolationSeverity.MEDIUM,
        "US phone number detected",
    ),
    "phone_international": (
        re.compile(r"(?<!\d)\+[1-9]\d{0,2}[-.\s]?\d{1,4}[-.\s]?\d{3,5}[-.\s]?\d{3,5}(?!\d)"),
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
            for match in pattern.finditer(content):
                matched_text = match.group(0)

                if not self._validate_match(pattern_name, matched_text, content, match.start()):
                    continue

                violations.append(
                    Violation(
                        policy_id=self.policy_id,
                        severity=severity,
                        message=f"{message} in {direction}",
                        matched_content=self._redact(matched_text),
                        metadata={
                            "pattern": pattern_name,
                            "direction": direction,
                            "char_count": len(matched_text),
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
    def _validate_match(pattern_name: str, matched_text: str, content: str, start_pos: int) -> bool:
        """Post-match validation to reduce false positives."""
        if pattern_name == "credit_card":
            return _luhn_check(matched_text)

        if pattern_name == "ip_address":
            # Reject if preceded by version-like context
            prefix = content[max(0, start_pos - 20):start_pos]
            if _VERSION_CONTEXT_RE.search(prefix):
                return False
            # Reject if followed by another dot-separated segment (looks like a version)
            end_pos = start_pos + len(matched_text)
            if end_pos < len(content) and content[end_pos] == ".":
                return False

        return True

    @staticmethod
    def _redact(value: str) -> str:
        """Redact matched content for safe logging. Shows only last 4 chars."""
        if len(value) <= 4:
            return "****"
        return "*" * (len(value) - 4) + value[-4:]
