"""Jailbreak detection policy — identifies attempts to bypass model safety measures."""

from __future__ import annotations

import re
import time
from typing import Any

from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies.base import BasePolicy, PolicyResult

_JAILBREAK_PATTERNS: list[tuple[re.Pattern[str], str, ViolationSeverity]] = [
    (
        re.compile(
            r"(?:DAN|Do\s+Anything\s+Now|Developer\s+Mode|STAN|DUDE)\s*(?:mode|prompt|enabled)",
            re.I,
        ),
        "Known jailbreak persona activation (DAN/STAN/DUDE)",
        ViolationSeverity.CRITICAL,
    ),
    (
        re.compile(
            r"(?:from\s+now\s+on|henceforth|going\s+forward)\s*,?\s*"
            r"(?:you\s+(?:will|must|should|can)|ignore|forget|disregard)",
            re.I,
        ),
        "Temporal reset jailbreak attempt",
        ViolationSeverity.HIGH,
    ),
    (
        re.compile(
            r"(?:hypothetical(?:ly)?|fictional|in\s+a\s+(?:story|novel|movie))\s*"
            r"(?:scenario|situation|world|context)\s*(?:where|in\s+which)",
            re.I,
        ),
        "Fictional framing bypass",
        ViolationSeverity.HIGH,
    ),
    (
        re.compile(
            r"(?:translate|encode|convert|write)\s+(?:this|the\s+following|it)\s+"
            r"(?:in|into|to|using)\s+(?:base64|hex|rot13|binary|morse|pig\s*latin|leetspeak|reversed)",
            re.I,
        ),
        "Encoding-based evasion attempt",
        ViolationSeverity.HIGH,
    ),
    (
        re.compile(
            r"(?:opposite\s+day|opposite\s+mode|reverse\s+(?:mode|psychology))\s*"
            r"|(?:when\s+I\s+say\s+(?:yes|no|good|bad)\s*,?\s*(?:I\s+(?:actually\s+)?mean|it\s+means))",
            re.I,
        ),
        "Semantic inversion trick",
        ViolationSeverity.MEDIUM,
    ),
    (
        re.compile(
            r"(?:as\s+(?:a|an)\s+(?:AI|language\s+model|assistant)\s*,?\s*"
            r"you\s+(?:should|must|need\s+to|have\s+to)\s+(?:be\s+able\s+to|always))"
            r"|(?:your\s+(?:training|guidelines|rules|restrictions)\s+"
            r"(?:are|were)\s+(?:wrong|outdated|incorrect|flawed))",
            re.I,
        ),
        "Authority challenge / training dismissal",
        ViolationSeverity.MEDIUM,
    ),
    (
        re.compile(
            r"(?:multi[-\s]?turn|previous\s+(?:messages?|context|conversation))\s*"
            r"(?:established|confirmed|proved|showed)\s+(?:that|you)",
            re.I,
        ),
        "Multi-turn manipulation (false consensus)",
        ViolationSeverity.MEDIUM,
    ),
    (
        re.compile(
            r"(?:token\s+smuggling|payload\s+splitting|"
            r"invisible\s+(?:text|characters?|unicode)|"
            r"zero[-\s]?width\s+(?:space|char))",
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
    """

    policy_id = "jailbreak-detection"
    description = "Identifies attempts to bypass model safety measures through manipulation, encoding tricks, and multi-turn attacks."

    def __init__(self, parameters: dict[str, Any] | None = None) -> None:
        super().__init__(parameters)
        self._min_severity = ViolationSeverity(
            self._parameters.get("min_severity", "low")
        )

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        start = time.perf_counter()
        violations: list[Violation] = []

        for pattern, description, severity in _JAILBREAK_PATTERNS:
            match = pattern.search(content)
            if match:
                violations.append(
                    Violation(
                        policy_id=self.policy_id,
                        severity=severity,
                        message=f"Jailbreak: {description}",
                        matched_content=match.group(0)[:120],
                        metadata={
                            "type": "jailbreak",
                            "direction": direction,
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
