"""Injection detection policy — identifies prompt injection and SQL injection attempts."""

from __future__ import annotations

import re
import time
import unicodedata
from typing import Any

from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies.base import BasePolicy, PolicyResult

_ZERO_WIDTH_RE = re.compile(
    "[​‌‍‎‏⁠⁡⁢⁣⁤"
    "﻿­͏؜ᅟᅠ឴឵"
    "᠎ - ‪-‮⁦-⁩￹-￻]"
)

_SQL_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _normalize_for_scan(text: str) -> str:
    """Strip zero-width/invisible Unicode and SQL inline comments to prevent evasion."""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _ZERO_WIDTH_RE.sub("", normalized)
    normalized = _SQL_COMMENT_RE.sub(" ", normalized)
    return normalized

_PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?)", re.I),
        "Instruction override attempt",
    ),
    (
        re.compile(r"disregard\s+(all\s+)?(previous|above|prior|your)\s+\w+", re.I),
        "Instruction disregard attempt",
    ),
    (
        re.compile(r"you\s+are\s+now\s+(?:a|an|acting\s+as)", re.I),
        "Role reassignment attempt",
    ),
    (
        re.compile(r"new\s+instructions?:\s*", re.I),
        "Injected instruction block",
    ),
    (
        re.compile(r"system\s*:\s*you\s+are", re.I),
        "System prompt injection",
    ),
    (
        re.compile(r"\[INST\]|\[\/INST\]|<<SYS>>|<\|im_start\|>", re.I),
        "Chat template injection",
    ),
    (
        re.compile(r"(?:pretend|imagine|act\s+as\s+if)\s+(?:you|that|there)", re.I),
        "Behavioral override attempt",
    ),
    (
        re.compile(
            r"(?:do\s+not|don'?t|never)\s+(?:mention|reveal|disclose|tell|share)\s+"
            r"(?:your|the|any)\s+(?:instructions?|prompt|rules?|system)",
            re.I,
        ),
        "Instruction concealment probe",
    ),
]

_SQL_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(?:'\s*(?:OR|AND)\s+['\d]|;\s*(?:DROP|DELETE|INSERT|UPDATE|ALTER)\s)",
            re.I,
        ),
        "SQL injection — destructive statement",
    ),
    (
        re.compile(r"UNION\s+(?:ALL\s+)?SELECT", re.I),
        "SQL injection — UNION SELECT",
    ),
    (
        re.compile(r";\s*--\s*$|'\s*;\s*--", re.I),
        "SQL injection — comment termination",
    ),
    (
        re.compile(
            r"(?:exec|execute)\s*\(\s*(?:xp_|sp_)",
            re.I,
        ),
        "SQL injection — stored procedure execution",
    ),
    (
        re.compile(r"INTO\s+(?:OUTFILE|DUMPFILE)", re.I),
        "SQL injection — file write attempt",
    ),
]


class InjectionPolicy(BasePolicy):
    """Detects prompt injection and SQL injection attempts."""

    policy_id = "injection-detection"
    description = "Scans for prompt injection, jailbreak attempts, and SQL injection patterns."

    def __init__(self, parameters: dict[str, Any] | None = None) -> None:
        super().__init__(parameters)
        self._check_prompt = self._parameters.get("check_prompt_injection", True)
        self._check_sql = self._parameters.get("check_sql_injection", True)

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        start = time.perf_counter()
        violations: list[Violation] = []

        normalized = _normalize_for_scan(content)

        if self._check_prompt:
            violations.extend(self._check_prompt_injection(normalized, direction))

        if self._check_sql:
            violations.extend(self._check_sql_injection(normalized, direction))

        elapsed_ms = (time.perf_counter() - start) * 1000
        return PolicyResult(
            passed=len(violations) == 0,
            violations=violations,
            execution_time_ms=elapsed_ms,
        )

    def _check_prompt_injection(self, content: str, direction: str) -> list[Violation]:
        violations: list[Violation] = []
        for pattern, description in _PROMPT_INJECTION_PATTERNS:
            match = pattern.search(content)
            if match:
                violations.append(
                    Violation(
                        policy_id=self.policy_id,
                        severity=ViolationSeverity.HIGH,
                        message=f"Prompt injection: {description}",
                        matched_content=match.group(0)[:100],
                        blocked=True,
                        metadata={
                            "type": "prompt_injection",
                            "direction": direction,
                        },
                    )
                )
        return violations

    def _check_sql_injection(self, content: str, direction: str) -> list[Violation]:
        violations: list[Violation] = []
        for pattern, description in _SQL_INJECTION_PATTERNS:
            match = pattern.search(content)
            if match:
                violations.append(
                    Violation(
                        policy_id=self.policy_id,
                        severity=ViolationSeverity.CRITICAL,
                        message=f"SQL injection: {description}",
                        matched_content=match.group(0)[:100],
                        metadata={
                            "type": "sql_injection",
                            "direction": direction,
                        },
                    )
                )
        return violations
