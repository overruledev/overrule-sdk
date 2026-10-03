"""Jailbreak detection policy — identifies attempts to bypass model safety measures."""

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

_JAILBREAK_PATTERNS: list[tuple[re.Pattern[str], str, ViolationSeverity]] = [
    (
        re.compile(
            # "do anything now" spelled out is unambiguous on its own.
            rf"\bdo{SEP}anything{SEP}now\b"
            # Persona + activation keyword, case-insensitive.
            # {1,2} so "DAN mode enabled" is consumed whole, which makes
            # metadata["raw_match"] usable for redaction.
            rf"|\b(?:dan|stan|dude|aim)"
            rf"(?:{SEP}(?:mode|prompt|enabled|activated|unlocked)){{1,2}}\b"
            # Bare persona token only when written in caps, so the ordinary
            # words/names "dan" and "dude" do not trigger a violation.
            rf"|(?-i:\b(?:DAN|D\.A\.N\.?|STAN)\b)",
            re.I,
        ),
        "Known jailbreak persona activation (DAN/STAN/DUDE)",
        ViolationSeverity.CRITICAL,
    ),
    (
        re.compile(
            # An activation keyword is required: bare "dev mode" is ordinary
            # software vocabulary and would be a false positive.
            rf"\b(?:developer|dev)[\s\-_.]?mode\b{SEP}"
            rf"(?:enabled?|on|activated?|output|unlocked|prompt|jailbreak)\b",
            re.I,
        ),
        "Developer Mode jailbreak activation",
        ViolationSeverity.HIGH,
    ),
    (
        re.compile(
            rf"(?:from{SEP}now{SEP}on|henceforth|going{SEP}forward){SEP}?"
            rf"(?:you{SEP}(?:will|must|should|can)|ignore|forget|disregard)",
            re.I,
        ),
        "Temporal reset jailbreak attempt",
        ViolationSeverity.HIGH,
    ),
    (
        re.compile(
            # The trailing "where"/"in which" clause is now optional — the
            # classic "in a hypothetical scenario, ..." omits it.
            rf"(?:hypothetical(?:ly)?|fictional|imaginary|make[\s\-]?believe){SEP}"
            rf"(?:scenario|situation|world|context|setting|story|universe|roleplay)"
            rf"|in{SEP}a{SEP}(?:story|novel|movie|film|screenplay|game|play){SEP}where",
            re.I,
        ),
        "Fictional framing bypass",
        ViolationSeverity.HIGH,
    ),
    (
        re.compile(
            rf"(?:translate|encode|convert|write){SEP}(?:this|the{SEP}following|it){SEP}"
            rf"(?:in|into|to|using){SEP}"
            rf"(?:base64|hex|rot13|binary|morse|pig{SEP}?latin|leetspeak|reversed)",
            re.I,
        ),
        "Encoding-based evasion attempt",
        ViolationSeverity.HIGH,
    ),
    (
        re.compile(
            rf"(?:opposite{SEP}day|opposite{SEP}mode|reverse{SEP}(?:mode|psychology))"
            rf"|(?:when{SEP}I{SEP}say{SEP}(?:yes|no|good|bad){SEP}?"
            rf"(?:I{SEP}(?:actually{SEP})?mean|it{SEP}means))",
            re.I,
        ),
        "Semantic inversion trick",
        ViolationSeverity.MEDIUM,
    ),
    (
        re.compile(
            rf"(?:as{SEP}(?:a|an){SEP}(?:AI|language{SEP}model|assistant){SEP}?"
            rf"you{SEP}(?:should|must|need{SEP}to|have{SEP}to){SEP}"
            rf"(?:be{SEP}able{SEP}to|always))"
            rf"|(?:your{SEP}(?:training|guidelines|rules|restrictions){SEP}"
            rf"(?:are|were){SEP}(?:wrong|outdated|incorrect|flawed))",
            re.I,
        ),
        "Authority challenge / training dismissal",
        ViolationSeverity.MEDIUM,
    ),
    (
        re.compile(
            rf"(?:multi[-\s]?turn|previous{SEP}(?:messages?|context|conversation)){SEP}"
            rf"(?:established|confirmed|proved|showed){SEP}(?:that|you)",
            re.I,
        ),
        "Multi-turn manipulation (false consensus)",
        ViolationSeverity.MEDIUM,
    ),
    (
        re.compile(
            rf"(?:token{SEP}smuggling|payload{SEP}splitting|"
            rf"invisible{SEP}(?:text|characters?|unicode)|"
            rf"zero[-\s]?width{SEP}(?:space|char))",
            re.I,
        ),
        "Token smuggling / invisible character attack",
        ViolationSeverity.CRITICAL,
    ),
]


class JailbreakPolicy(BasePolicy):
    """Detects jailbreak attempts targeting model safety boundaries.

    Covers:
        - Known personas (DAN, STAN, DUDE, Developer Mode)
        - Temporal resets ("from now on, ignore your rules")
        - Fictional framing ("in a hypothetical world where...")
        - Encoding evasion (base64, rot13, binary obfuscation)
        - Semantic inversion ("opposite day")
        - Authority challenges ("your training is wrong")
        - Multi-turn manipulation (false consensus building)
        - Token smuggling and invisible characters

    Content is normalised (NFKC, invisible characters, common Latin/Cyrillic
    confusables) before matching, and inter-word separators are flexible.
    Detection is still pattern based: encoded payloads, paraphrase, synonyms and
    non-English phrasing are not covered.
    """

    policy_id = "jailbreak-detection"
    description = (
        "Identifies attempts to bypass model safety measures through "
        "manipulation, encoding tricks, and multi-turn attacks."
    )

    def __init__(self, parameters: dict[str, Any] | None = None) -> None:
        super().__init__(parameters)
        self._min_severity = ViolationSeverity(self._parameters.get("min_severity", "low"))

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        start = time.perf_counter()
        violations: list[Violation] = []

        variants = normalize_variants(content)

        for pattern, description, severity in _JAILBREAK_PATTERNS:
            for match in collect_matches(pattern, variants, MAX_MATCHES_PER_PATTERN):
                raw = match.group(0)
                violations.append(
                    Violation(
                        policy_id=self.policy_id,
                        severity=severity,
                        message=f"Jailbreak: {description}",
                        matched_content=raw[:120],
                        blocked=True,
                        metadata={
                            "type": "jailbreak",
                            "pattern": description,
                            "direction": direction,
                            "char_count": len(raw),
                            # Full, untruncated match: REDACT prefers this over
                            # the truncated matched_content.
                            "raw_match": raw,
                        },
                    )
                )

        severity_order = list(ViolationSeverity)
        min_index = severity_order.index(self._min_severity)
        violations = [v for v in violations if severity_order.index(v.severity) <= min_index]

        elapsed_ms = (time.perf_counter() - start) * 1000
        return PolicyResult(
            passed=len(violations) == 0,
            violations=violations,
            execution_time_ms=elapsed_ms,
        )
