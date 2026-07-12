"""Toxicity detection policy — identifies harmful, abusive, or inappropriate content."""

from __future__ import annotations

import re
import time
from typing import Any

from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies.base import BasePolicy, PolicyResult

_SEVERITY_HIGH_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(?:kill\s+(?:your(?:self|selves)?|him|her|them|myself)|"
            r"commit\s+suicide|hang\s+yourself|"
            r"slit\s+(?:your|my)\s+wrists?|"
            r"jump\s+off\s+a\s+bridge)\b",
            re.I,
        ),
        "Self-harm or violence incitement",
    ),
    (
        re.compile(
            r"\b(?:how\s+to\s+(?:make|build|create)\s+(?:a\s+)?(?:bomb|explosive|weapon)|"
            r"synthesize\s+(?:meth|fentanyl|ricin|sarin)|"
            r"instructions?\s+(?:for|to)\s+(?:poison|murder))\b",
            re.I,
        ),
        "Dangerous activity instructions",
    ),
]

_SEVERITY_MEDIUM_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(?:fuck\s*(?:ing|ed)?(?:\s+you|\s+off)?|"
            r"shit(?:ty|head|face)?|"
            r"bitch(?:es|ing)?|"
            r"asshole|"
            r"motherfuck(?:er|ing)?|"
            r"cunt|"
            r"dick(?:head)?)\b",
            re.I,
        ),
        "Profanity detected",
    ),
    (
        re.compile(
            r"\b(?:retard(?:ed)?|"
            r"fagg?ot|"
            r"nig+(?:er|a)|"
            r"tranny|"
            r"spic|"
            r"chink|"
            r"kike|"
            r"wetback)\b",
            re.I,
        ),
        "Slur or hate speech detected",
    ),
]

_SEVERITY_LOW_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"\b(?:idiot|moron|stupid|dumb|loser|"
            r"shut\s+up|pathetic|worthless|disgusting)\b",
            re.I,
        ),
        "Mildly toxic language",
    ),
]


class ToxicityPolicy(BasePolicy):
    """Detects toxic, abusive, and harmful content across severity levels.

    Severity levels:
        - CRITICAL: Violence incitement, self-harm encouragement, dangerous instructions
        - HIGH: Slurs, hate speech, severe profanity
        - LOW: Mild insults, dismissive language

    Configuration:
        - min_severity: Minimum severity to flag (default: "low")
        - check_profanity: Whether to check for profanity (default: True)
        - check_slurs: Whether to check for slurs/hate speech (default: True)
        - check_violence: Whether to check for violence/self-harm (default: True)
    """

    policy_id = "toxicity-detection"
    description = "Scans for toxic language, profanity, slurs, and harmful content."

    def __init__(self, parameters: dict[str, Any] | None = None) -> None:
        super().__init__(parameters)
        self._check_profanity = self._parameters.get("check_profanity", True)
        self._check_slurs = self._parameters.get("check_slurs", True)
        self._check_violence = self._parameters.get("check_violence", True)
        self._min_severity = ViolationSeverity(
            self._parameters.get("min_severity", "low")
        )

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        start = time.perf_counter()
        violations: list[Violation] = []

        if self._check_violence:
            violations.extend(
                self._scan_patterns(
                    content, _SEVERITY_HIGH_PATTERNS, ViolationSeverity.CRITICAL, direction
                )
            )

        if self._check_slurs:
            violations.extend(
                self._scan_patterns(
                    content, _SEVERITY_MEDIUM_PATTERNS, ViolationSeverity.HIGH, direction
                )
            )

        if self._check_profanity:
            violations.extend(
                self._scan_patterns(
                    content, _SEVERITY_LOW_PATTERNS, ViolationSeverity.LOW, direction
                )
            )

        violations = self._filter_by_severity(violations)

        elapsed_ms = (time.perf_counter() - start) * 1000
        return PolicyResult(
            passed=len(violations) == 0,
            violations=violations,
            execution_time_ms=elapsed_ms,
        )

    def _scan_patterns(
        self,
        content: str,
        patterns: list[tuple[re.Pattern[str], str]],
        severity: ViolationSeverity,
        direction: str,
    ) -> list[Violation]:
        violations: list[Violation] = []
        for pattern, description in patterns:
            match = pattern.search(content)
            if match:
                violations.append(
                    Violation(
                        policy_id=self.policy_id,
                        severity=severity,
                        message=f"Toxicity: {description}",
                        matched_content=match.group(0)[:80],
                        metadata={"type": "toxicity", "direction": direction},
                    )
                )
        return violations

    def _filter_by_severity(self, violations: list[Violation]) -> list[Violation]:
        severity_order = list(ViolationSeverity)
        min_index = severity_order.index(self._min_severity)
        return [
            v for v in violations
            if severity_order.index(v.severity) <= min_index
        ]
