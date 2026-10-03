"""Shared text normalisation helpers for pattern-based policies.

Attackers evade regex detection by inserting invisible characters, swapping
Latin letters for visually identical Cyrillic/Greek ones, or replacing spaces
with punctuation. The helpers here produce a small set of *normalisation
variants* of the input; policies run every pattern against each variant and
keep whichever variant yields the most matches.

Two zero-width variants are required, not one:

* ``zero-width -> " "``  fixes ``"Ignore​all​previous"`` (separators
  replaced by invisible characters).
* ``zero-width -> ""``   fixes ``"Ig​nore all previous"`` (invisible
  characters injected *inside* a word).

Stripping zero-width characters alone (the previous behaviour) glued words
together and therefore defeated the ``\\s+`` in every pattern, turning the
mitigation into a bypass.
"""

from __future__ import annotations

import re
import unicodedata

__all__ = [
    "MAX_CANDIDATES_PER_PATTERN",
    "MAX_MATCHES_PER_PATTERN",
    "SEP",
    "collect_matches",
    "normalize_variants",
]

#: Upper bound on violations emitted per pattern, to bound pathological inputs.
#:
#: This counts *reported* violations only. Counting raw regex candidates instead
#: let 100 cheap decoys (16-digit runs that fail Luhn, context-less SSN shapes)
#: exhaust the budget and disable the detector for the rest of the window.
MAX_MATCHES_PER_PATTERN = 100

#: Upper bound on *candidates* a single pattern will examine before giving up.
#:
#: Deliberately loose: its only job is to keep a pathological input cheap. It is
#: set far above the number of candidates one scan window can physically hold
#: (a 100_000-char window admits at most ~14_000 candidates of the shortest
#: pattern), so padding with rejected decoys cannot push a real match out of
#: reporting range.
MAX_CANDIDATES_PER_PATTERN = 20_000

#: Inter-word separator used by injection/jailbreak patterns.
#:
#: Widened from ``\s+`` so that ``"Ignore, all previous instructions."`` and
#: ``"Ignore-all-previous-instructions"`` no longer evade detection. The set is
#: deliberately limited to whitespace plus separator-ish punctuation, and the
#: repetition is bounded, so no nested/unbounded quantifiers are introduced.
SEP = r"[\s\-_,.:;*~]{1,4}"

# Zero-width, invisible, joiner and bidi-control code points.
# fmt: off
_ZERO_WIDTH_RE = re.compile(
    "[​‌‍‎‏⁠⁡⁢⁣⁤"
    "﻿­͏؜ᅟᅠ឴឵"
    "᠎ - ‪-‮⁦-⁩￹-￻]"
)

_SQL_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

# Cheap confusable folding for the most common Cyrillic/Greek homoglyphs.
# This is not a complete confusable mapping (see the policy docstrings): it
# covers the substitutions that show up in copy-pasted jailbreak prompts.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic lower-case
    "а": "a", "в": "b", "е": "e", "ѕ": "s", "і": "i",
    "ј": "j", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x",
    "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    # Cyrillic upper-case
    "А": "A", "В": "B", "Е": "E", "Ѕ": "S", "І": "I",
    "Ј": "J", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X",
    # Greek lower-case
    "α": "a", "ε": "e", "ι": "i", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    # Greek upper-case
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Υ": "Y", "Χ": "X",
}
# fmt: on

_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)
_CONFUSABLE_RE = re.compile("[" + "".join(_CONFUSABLES) + "]")


def normalize_variants(text: str) -> tuple[str, ...]:
    """Return the normalisation variants of ``text`` that policies should scan.

    The first element is always the "safe" variant (zero-width characters
    become a single space), so callers that only want one string can use it.
    Duplicate variants are collapsed, so ordinary ASCII input produces exactly
    one variant and costs exactly one pass per pattern.
    """
    base = unicodedata.normalize("NFKC", text)
    base = _SQL_COMMENT_RE.sub(" ", base)

    variants: list[str] = []
    for candidate in (_ZERO_WIDTH_RE.sub(" ", base), _ZERO_WIDTH_RE.sub("", base)):
        if candidate not in variants:
            variants.append(candidate)

    if _CONFUSABLE_RE.search(base):
        for candidate in list(variants):
            folded = candidate.translate(_CONFUSABLE_TABLE)
            if folded not in variants:
                variants.append(folded)

    return tuple(variants)


def collect_matches(
    pattern: re.Pattern[str],
    variants: tuple[str, ...],
    limit: int = MAX_MATCHES_PER_PATTERN,
) -> list[re.Match[str]]:
    """Return every match of ``pattern`` in the most-matching variant.

    Using ``finditer`` (rather than ``search``) means each *occurrence* becomes
    a violation, which is what makes REDACT able to replace all of them.

    Scanning per-variant and keeping the best result — rather than merging
    results across variants — avoids emitting duplicate violations for the same
    occurrence while preserving multiplicity.
    """
    best: list[re.Match[str]] = []
    for variant in variants:
        matches: list[re.Match[str]] = []
        for match in pattern.finditer(variant):
            matches.append(match)
            if len(matches) >= limit:
                break
        if len(matches) > len(best):
            best = matches
        if len(best) >= limit:
            break
    return best
