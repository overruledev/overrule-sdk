"""Toxicity detection policy — identifies harmful, abusive, or inappropriate content."""

from __future__ import annotations

import re
import time
from typing import Any

from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies._normalize import MAX_MATCHES_PER_PATTERN
from overrule.policies.base import BasePolicy, PolicyResult

#: Gated by ``check_violence``. Reported as CRITICAL.
_VIOLENCE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
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

#: Gated by ``check_profanity``. Reported as HIGH.
_PROFANITY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
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
]

#: Gated by ``check_slurs``. Reported as HIGH.
_SLUR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
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

#: Gated by ``check_insults``. Reported as LOW.
_MILD_INSULT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
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

    Each ``check_*`` flag gates exactly the category it is named after, and each
    category maps to one severity:

    ==================  ==========  ================================================
    Flag                Severity    Content
    ==================  ==========  ================================================
    ``check_violence``  CRITICAL    Violence incitement, self-harm, dangerous how-tos
    ``check_slurs``     HIGH        Slurs and hate speech
    ``check_profanity`` HIGH        Severe profanity
    ``check_insults``   LOW         Mild insults, dismissive language
    ==================  ==========  ================================================

    There is deliberately no MEDIUM tier: profanity and slurs are both reported as
    HIGH, they are simply gated independently.

    Configuration:
        - min_severity: Minimum severity to flag (default: "low", i.e. report everything)
        - check_violence: Check for violence/self-harm (default: True)
        - check_slurs: Check for slurs/hate speech (default: True)
        - check_profanity: Check for severe profanity (default: True)
        - check_insults: Check for mild insults (default: True)

    .. versionchanged:: 0.4.0
        ``check_slurs`` used to gate profanity *and* slurs together, and
        ``check_profanity`` used to gate the mild-insult tier rather than profanity —
        so ``check_profanity=False`` did not turn off profanity detection. The flags now
        match their names. Defaults are unchanged, so behaviour only differs if you set
        one of them to ``False``; use ``check_insults=False`` for what
        ``check_profanity=False`` used to do.
    """

    policy_id = "toxicity-detection"
    description = "Scans for toxic language, profanity, slurs, and harmful content."

    def __init__(self, parameters: dict[str, Any] | None = None) -> None:
        super().__init__(parameters)
        self._check_violence = self._parameters.get("check_violence", True)
        self._check_slurs = self._parameters.get("check_slurs", True)
        self._check_profanity = self._parameters.get("check_profanity", True)
        self._check_insults = self._parameters.get("check_insults", True)
        self._min_severity = ViolationSeverity(self._parameters.get("min_severity", "low"))

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        start = time.perf_counter()
        violations: list[Violation] = []

        for enabled, patterns, severity in (
            (self._check_violence, _VIOLENCE_PATTERNS, ViolationSeverity.CRITICAL),
            (self._check_slurs, _SLUR_PATTERNS, ViolationSeverity.HIGH),
            (self._check_profanity, _PROFANITY_PATTERNS, ViolationSeverity.HIGH),
            (self._check_insults, _MILD_INSULT_PATTERNS, ViolationSeverity.LOW),
        ):
            if enabled:
                violations.extend(self._scan_patterns(content, patterns, severity, direction))

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
            # finditer, not search: every occurrence must become a violation or
            # REDACT (which replaces per violation) leaves later copies verbatim.
            # The cap counts *reported* violations, matching pii.py. There is no
            # refine step here so the two are currently identical, but counting
            # candidates is the idiom that let decoys disable PII detection.
            reported: list[Violation] = []
            for match in pattern.finditer(content):
                if len(reported) >= MAX_MATCHES_PER_PATTERN:
                    break
                raw = match.group(0)
                reported.append(
                    Violation(
                        policy_id=self.policy_id,
                        severity=severity,
                        message=f"Toxicity: {description}",
                        matched_content=raw[:80],
                        metadata={
                            "type": "toxicity",
                            "pattern": description,
                            "direction": direction,
                            "char_count": len(raw),
                            # Full, untruncated match: REDACT prefers this over
                            # the truncated matched_content.
                            "raw_match": raw,
                        },
                    )
                )
            violations.extend(reported)
        return violations

    def _filter_by_severity(self, violations: list[Violation]) -> list[Violation]:
        severity_order = list(ViolationSeverity)
        min_index = severity_order.index(self._min_severity)
        return [v for v in violations if severity_order.index(v.severity) <= min_index]
