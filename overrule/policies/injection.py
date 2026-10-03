"""Injection detection policy — identifies prompt injection and SQL injection attempts.

Coverage notes (see also ``_normalize``): detection is pattern based. Unicode
normalisation, invisible-character handling, confusable folding and flexible
word separators are applied, but regex matching is *not* a complete defence.
Encoded payloads (base64/rot13), paraphrase, synonyms, non-English phrasing and
elaborate roleplay framing are explicitly out of scope.
"""

from __future__ import annotations

import re
import time
from typing import Any

from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies._normalize import (
    MAX_MATCHES_PER_PATTERN,
    SEP,
    collect_matches,
    normalize_variants,
)
from overrule.policies.base import BasePolicy, PolicyResult


def _normalize_for_scan(text: str) -> str:
    """Normalise ``text`` for scanning (NFKC, invisible chars, SQL comments).

    Zero-width characters collapse to a single space rather than being deleted:
    deleting them glued words together and defeated the separator in every
    pattern. Full scanning uses :func:`normalize_variants`, which also yields a
    delete-zero-width variant for characters injected inside a word.
    """
    return normalize_variants(text)[0]


_PROMPT_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            rf"ignore{SEP}(?:all{SEP})?(?:previous|above|prior){SEP}(?:instructions?|prompts?)",
            re.I,
        ),
        "Instruction override attempt",
    ),
    (
        re.compile(
            rf"disregard{SEP}(?:all{SEP})?(?:previous|above|prior|your){SEP}\w+",
            re.I,
        ),
        "Instruction disregard attempt",
    ),
    (
        # The trailing \b matters: without it "You are now able to..." matches
        # the bare "a" alternative and becomes a false positive.
        re.compile(rf"you{SEP}are{SEP}now{SEP}(?:a|an|acting{SEP}as)\b", re.I),
        "Role reassignment attempt",
    ),
    (
        re.compile(rf"new{SEP}instructions?\s*:", re.I),
        "Injected instruction block",
    ),
    (
        re.compile(rf"system\s*:\s*you{SEP}are", re.I),
        "System prompt injection",
    ),
    (
        re.compile(r"\[INST\]|\[\/INST\]|<<SYS>>|<\|im_start\|>", re.I),
        "Chat template injection",
    ),
    (
        re.compile(rf"(?:pretend|imagine|act{SEP}as{SEP}if){SEP}(?:you|that|there)", re.I),
        "Behavioral override attempt",
    ),
    (
        re.compile(
            rf"(?:do{SEP}not|don'?t|never){SEP}(?:mention|reveal|disclose|tell|share){SEP}"
            rf"(?:your|the|any){SEP}(?:instructions?|prompt|rules?|system)",
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

        variants = normalize_variants(content)

        if self._check_prompt:
            violations.extend(self._check_prompt_injection(variants, direction))

        if self._check_sql:
            violations.extend(self._check_sql_injection(variants, direction))

        elapsed_ms = (time.perf_counter() - start) * 1000
        return PolicyResult(
            passed=len(violations) == 0,
            violations=violations,
            execution_time_ms=elapsed_ms,
        )

    def _check_prompt_injection(self, variants: tuple[str, ...], direction: str) -> list[Violation]:
        violations: list[Violation] = []
        for pattern, description in _PROMPT_INJECTION_PATTERNS:
            for match in collect_matches(pattern, variants, MAX_MATCHES_PER_PATTERN):
                raw = match.group(0)
                violations.append(
                    Violation(
                        policy_id=self.policy_id,
                        severity=ViolationSeverity.HIGH,
                        message=f"Prompt injection: {description}",
                        matched_content=raw[:100],
                        blocked=True,
                        metadata={
                            "type": "prompt_injection",
                            "pattern": "prompt_injection",
                            "direction": direction,
                            "char_count": len(raw),
                            # Full, untruncated match: REDACT prefers this over
                            # the truncated matched_content.
                            "raw_match": raw,
                        },
                    )
                )
        return violations

    def _check_sql_injection(self, variants: tuple[str, ...], direction: str) -> list[Violation]:
        violations: list[Violation] = []
        for pattern, description in _SQL_INJECTION_PATTERNS:
            for match in collect_matches(pattern, variants, MAX_MATCHES_PER_PATTERN):
                raw = match.group(0)
                violations.append(
                    Violation(
                        policy_id=self.policy_id,
                        severity=ViolationSeverity.CRITICAL,
                        message=f"SQL injection: {description}",
                        matched_content=raw[:100],
                        blocked=True,
                        metadata={
                            "type": "sql_injection",
                            "pattern": "sql_injection",
                            "direction": direction,
                            "char_count": len(raw),
                            "raw_match": raw,
                        },
                    )
                )
        return violations
