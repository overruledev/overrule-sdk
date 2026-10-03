"""PII detection policy — identifies personally identifiable information in content.

Design notes
------------
Several detectors are intentionally split into a *permissive candidate regex*
plus a *structured validator*:

* Credit cards match any 13–19 digit run with optional ``-``, space or ``.``
  separators, then require both a Luhn check and a known issuer prefix/length.
  This is simultaneously broader (dot separators, Amex 4-6-5 print format,
  13/19-digit Visa, Diners, JCB, UnionPay) and more precise (an order ID such as
  ``4111-2024-0001-5678`` is rejected) than a fixed 4-4-4-4 grouping.
* IBANs allow embedded spaces, then require an ISO country code, the exact
  length registered for that country, and the ISO 7064 mod-97 checksum.
* SSNs and US passport numbers require a nearby keyword, because
  ``NNN-NN-NNNN`` and ``letter + 8 digits`` are indistinguishable from invoice,
  part and ticket identifiers.

None of the added patterns introduce nested unbounded quantifiers.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from typing import Any

from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies._normalize import MAX_CANDIDATES_PER_PATTERN, MAX_MATCHES_PER_PATTERN
from overrule.policies.base import BasePolicy, PolicyResult

logger = logging.getLogger("overrule.policies.pii")


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


def _card_issuer(digits: str) -> str | None:
    """Return the issuing network for ``digits``, or None if no prefix matches.

    Requiring a known issuer prefix *and* a length that issuer actually uses is
    what keeps the permissive candidate regex from flagging arbitrary long
    digit runs that happen to satisfy Luhn.
    """
    length = len(digits)
    if not digits.isdigit():
        return None
    if digits[0] == "4" and length in (13, 16, 19):
        return "visa"
    if length == 16 and (51 <= int(digits[:2]) <= 55 or 2221 <= int(digits[:4]) <= 2720):
        return "mastercard"
    if length == 15 and digits[:2] in ("34", "37"):
        return "amex"
    if 16 <= length <= 19 and (
        digits[:4] == "6011" or digits[:2] == "65" or 644 <= int(digits[:3]) <= 649
    ):
        return "discover"
    if 14 <= length <= 19 and (
        digits[:2] in ("36", "38", "39") or 300 <= int(digits[:3]) <= 305 or digits[:4] == "3095"
    ):
        return "diners"
    if 16 <= length <= 19 and 3528 <= int(digits[:4]) <= 3589:
        return "jcb"
    if 16 <= length <= 19 and digits[:2] in ("62", "81"):
        return "unionpay"
    return None


#: Registered IBAN length per ISO 3166-1 alpha-2 country code.
# fmt: off
_IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24,
    "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
    "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27,
    "GT": 28, "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
    "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20,
    "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20,
    "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24,
    "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25,
    "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
    "YE": 30,
}
# fmt: on


def _iban_mod97(compact: str) -> bool:
    """Validate the ISO 7064 mod-97-10 checksum of a compact IBAN string."""
    rearranged = compact[4:] + compact[:4]
    total = 0
    for char in rearranged:
        if char.isdigit():
            total = (total * 10 + int(char)) % 97
        elif char.isalpha():
            total = (total * 100 + (ord(char.upper()) - 55)) % 97
        else:
            return False
    return total == 1


# Context patterns that indicate an IP-like string is actually a version number.
# The window inspected around the match is wide enough to catch "upgrade to
# 10.20.30.40", but the gap between the keyword and the number is kept short so
# that unrelated sentences ("the server was updated; connect to 10.0.0.5") are
# still reported.
_VERSION_CONTEXT_RE = re.compile(
    r"(?:\bv(?:ersion)?|\brelease[ds]?|\bbuild|\bupdate[ds]?|\bupgrade[ds]?|\bpatch(?:ed)?|"
    r"\brevision|\bsdk|\bpython|\bnode|\bkernel|\bfirmware|\bschema|\bsemver|"
    r"\brollback|\bbump(?:ed)?|\bdowngrade[ds]?)"
    r"[^\d\n]{0,8}$"
    r"|^\s*[-/]",
    re.I,
)
_VERSION_CONTEXT_WINDOW = 64

# Keywords that must appear near an SSN-shaped number for it to be reported.
_SSN_CONTEXT_RE = re.compile(
    r"\b(?:ssn|ssns|ss#|s\.s\.n\.?|social[\s\-_]?security|socsec|"
    r"tax[\s\-_]?(?:id|payer)|taxpayer|itin|tin)\b",
    re.I,
)
_SSN_CONTEXT_BEFORE = 64
_SSN_CONTEXT_AFTER = 40

# Keywords that must appear near a "letter + 8 digits" token for it to be
# reported as a passport number.
_PASSPORT_CONTEXT_RE = re.compile(
    r"\b(?:passports?|travel[\s\-_]?document|document[\s\-_]?(?:no|number|#)|"
    r"visa[\s\-_]?(?:no|number)|dob|nationality)\b",
    re.I,
)
_PASSPORT_CONTEXT_WINDOW = 30

# Keywords that qualify a space-separated 10-digit run as a phone number.
_PHONE_CONTEXT_RE = re.compile(
    r"\b(?:phone|telephone|tel|mobile|cell(?:ular)?|fax|call|called|calling|"
    r"contact|reach|dial|whatsapp|sms|text|hotline|number)\b",
    re.I,
)
_PHONE_CONTEXT_BEFORE = 48
_PHONE_CONTEXT_AFTER = 32

# Permissive credit-card candidate: 13–19 digits with optional separators.
# Validated afterwards by Luhn + issuer prefix. No left *word* boundary, so
# "x4111111111111111" is caught; the digit boundaries `(?<!\d)`/`(?!\d)` mean the
# candidate always spans the whole digit run, and `_refine_card` slides a window
# inside it so leading junk digits ("id=004111111111111111") cannot hide a card.
_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)\d(?:[ \-.]?\d){12,18}(?!\d)")

#: Shortest run any issuer uses (13-digit Visa) and the shortest run trusted when
#: further digits follow it inside the same run. A 13-digit Visa prefix of a longer
#: number is far more often an IMEI or a device serial than a card.
_MIN_CARD_DIGITS = 13
_MIN_CARD_DIGITS_WITH_TRAILING = 14
_MAX_CARD_DIGITS = 19

# Permissive IBAN candidate allowing the printed space-grouped format.
_IBAN_CANDIDATE_RE = re.compile(r"\b[A-Z]{2}\d{2}[ ]?[A-Za-z0-9](?:[ ]?[A-Za-z0-9]){10,40}")

# SSN in dashed, space-separated or unseparated form. The backreference forces a
# consistent separator so "123-456789" is not treated as an SSN.
_SSN_CANDIDATE_RE = re.compile(r"(?<![\d-])(\d{3})([ \-]?)(\d{2})\2(\d{4})(?![\d-])")

# IPv6: full form, or a compressed form with at least one group before "::" so
# that "::1" and Python slices like "x[::1]" are not matched. Validated with the
# stdlib ipaddress module afterwards.
_IPV6_CANDIDATE_RE = re.compile(
    r"(?<![0-9A-Za-z:.])(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?"
    r")(?![0-9A-Za-z:.])"
)

# Precompiled regex patterns for PII detection.
_PII_PATTERNS: dict[str, tuple[re.Pattern[str], ViolationSeverity, str]] = {
    "credit_card": (
        _CARD_CANDIDATE_RE,
        ViolationSeverity.CRITICAL,
        "Credit card number detected",
    ),
    "ssn": (
        _SSN_CANDIDATE_RE,
        ViolationSeverity.CRITICAL,
        "Social Security Number detected",
    ),
    "email": (
        re.compile(
            r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,3}\.[A-Za-z]{2,12}\b"
        ),
        ViolationSeverity.MEDIUM,
        "Email address detected",
    ),
    "phone_us": (
        re.compile(
            r"(?<!\d)(?:"
            # (415) 555-4567 — parenthesised area code
            r"(?:\+1[-.\s]?)?\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}"
            # 415-555-4567 / 415.555.4567 — consistent punctuation separator
            r"|(?:\+1[-.\s]?)?[2-9]\d{2}([-.])[2-9]\d{2}\1\d{4}"
            # +1 415 555 4567 — explicit country code
            r"|\+1[ ]?[2-9]\d{2}[ ]?[2-9]\d{2}[ ]?\d{4}"
            # 415 555 4567 — space separated; requires phone context (see
            # _refine_match), otherwise a price list matches.
            r"|[2-9]\d{2}[ ][2-9]\d{2}[ ]\d{4}"
            # 4155554567 — bare 10 digits
            r"|[2-9]\d{9}"
            r")(?!\d)"
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
    "ipv6_address": (
        _IPV6_CANDIDATE_RE,
        ViolationSeverity.LOW,
        "IPv6 address detected",
    ),
    "iban": (
        _IBAN_CANDIDATE_RE,
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
            # `reported` counts violations actually emitted; `examined` bounds the
            # regex work. Counting candidates against MAX_MATCHES_PER_PATTERN let a
            # wall of decoys that `_refine_match` rejects (failed Luhn, context-less
            # SSN shapes) silently disable the detector before the real value.
            reported = 0
            examined = 0
            for match in pattern.finditer(content):
                if reported >= MAX_MATCHES_PER_PATTERN:
                    break
                examined += 1
                if examined > MAX_CANDIDATES_PER_PATTERN:
                    logger.debug(
                        "PII pattern '%s' examined %d candidates without filling its "
                        "report budget; abandoning the rest of this window",
                        pattern_name,
                        examined - 1,
                    )
                    break

                matched_text = self._refine_match(pattern_name, match, content)
                if matched_text is None:
                    continue

                reported += 1
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

    @classmethod
    def _refine_match(cls, pattern_name: str, match: re.Match[str], content: str) -> str | None:
        """Post-match validation.

        Returns the exact substring to report, or ``None`` if the candidate is
        not really PII. Returning a substring (rather than a bool) lets the
        permissive card/IBAN candidates be narrowed to the real value, which
        keeps ``metadata["raw_match"]`` usable for redaction.
        """
        matched_text = match.group(0)
        start_pos = match.start()

        if pattern_name == "credit_card":
            return cls._refine_card(matched_text)

        if pattern_name == "iban":
            return cls._refine_iban(matched_text)

        if pattern_name == "ssn":
            return cls._refine_ssn(match, content)

        if pattern_name == "passport_us":
            window = content[max(0, start_pos - _PASSPORT_CONTEXT_WINDOW) : start_pos]
            window += content[
                start_pos + len(matched_text) : start_pos
                + len(matched_text)
                + _PASSPORT_CONTEXT_WINDOW
            ]
            if not _PASSPORT_CONTEXT_RE.search(window):
                return None
            return matched_text

        if pattern_name == "phone_us":
            return cls._refine_phone_us(matched_text, content, start_pos)

        if pattern_name == "ipv6_address":
            if not any(char.isdigit() for char in matched_text):
                # "abc::def" is valid hex but is far more likely to be code.
                return None
            try:
                ipaddress.IPv6Address(matched_text)
            except ValueError:
                return None
            return matched_text

        if pattern_name == "ip_address":
            # Reject if preceded by version-like context.
            prefix = content[max(0, start_pos - _VERSION_CONTEXT_WINDOW) : start_pos]
            if _VERSION_CONTEXT_RE.search(prefix):
                return None
            # Reject if followed by another dot-separated segment (a version).
            end_pos = start_pos + len(matched_text)
            if end_pos < len(content) and content[end_pos] == ".":
                return None

        return matched_text

    @staticmethod
    def _refine_card(candidate: str) -> str | None:
        """Narrow a digit run to an embedded valid card number, if any.

        The start of the window is slid across the run rather than anchored at the
        first digit: anchoring meant a single stray leading digit hid a real card
        (``id=004111111111111111`` was not detected at all).

        A run that only validates at 13 digits is rejected when more digits follow
        it inside the same run. 13 is the shortest length any issuer uses, so such a
        prefix is far more likely to belong to a device identifier than a card
        (``IMEI 490154203237518`` used to be reported as a Visa).
        """
        positions = [i for i, char in enumerate(candidate) if char.isdigit()]
        total = len(positions)
        if total < _MIN_CARD_DIGITS:
            return None
        for start in range(total - _MIN_CARD_DIGITS + 1):
            longest = min(_MAX_CARD_DIGITS, total - start)
            for length in range(longest, _MIN_CARD_DIGITS - 1, -1):
                window = positions[start : start + length]
                digits = "".join(candidate[i] for i in window)
                if not _card_issuer(digits) or not _luhn_check(digits):
                    continue
                if length < _MIN_CARD_DIGITS_WITH_TRAILING and start + length < total:
                    continue
                return candidate[window[0] : window[-1] + 1]
        return None

    @staticmethod
    def _refine_iban(candidate: str) -> str | None:
        """Validate country code, registered length and mod-97 checksum."""
        expected = _IBAN_LENGTHS.get(candidate[:2])
        if expected is None:
            return None
        seen = 0
        end = -1
        for i, char in enumerate(candidate):
            if char.isalnum():
                seen += 1
                if seen == expected:
                    end = i + 1
                    break
        if end < 0:
            return None
        trimmed = candidate[:end]
        compact = "".join(char for char in trimmed if char.isalnum()).upper()
        if len(compact) != expected or not compact[2:4].isdigit():
            return None
        if not _iban_mod97(compact):
            return None
        return trimmed

    @staticmethod
    def _refine_ssn(match: re.Match[str], content: str) -> str | None:
        """Reject structurally invalid SSNs and those with no supporting context."""
        area, _, group, serial = match.groups()
        if area in {"000", "666"} or area[0] == "9":
            return None
        if group == "00" or serial == "0000":
            return None

        start_pos = match.start()
        end_pos = match.end()
        window = content[max(0, start_pos - _SSN_CONTEXT_BEFORE) : start_pos]
        window += content[end_pos : end_pos + _SSN_CONTEXT_AFTER]
        if not _SSN_CONTEXT_RE.search(window):
            # NNN-NN-NNNN is shape-identical to invoice/part/ticket numbers, so
            # a keyword is required to avoid flooding callers with noise.
            return None
        return match.group(0)

    @staticmethod
    def _refine_phone_us(matched_text: str, content: str, start_pos: int) -> str | None:
        """Space-separated 10-digit runs need phone context; other forms do not."""
        space_separated = (
            " " in matched_text and "(" not in matched_text and not matched_text.startswith("+")
        )
        if not space_separated:
            return matched_text
        end_pos = start_pos + len(matched_text)
        window = content[max(0, start_pos - _PHONE_CONTEXT_BEFORE) : start_pos]
        window += content[end_pos : end_pos + _PHONE_CONTEXT_AFTER]
        if not _PHONE_CONTEXT_RE.search(window):
            return None
        return matched_text

    @staticmethod
    def _redact(value: str) -> str:
        """Redact matched content for safe logging. Shows only last 4 chars."""
        if len(value) <= 4:
            return "****"
        return "*" * (len(value) - 4) + value[-4:]
