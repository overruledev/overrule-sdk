"""Python version compatibility shims.

The SDK supports Python 3.10+ (see ``requires-python`` in pyproject.toml).
``enum.StrEnum`` was added in 3.11, so 3.10 gets a behaviour-compatible
backport here. Import ``StrEnum`` from this module — never from ``enum``
directly — so the package keeps importing on 3.10.
"""

from __future__ import annotations

import sys

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from enum import Enum

    class StrEnum(str, Enum):
        """Backport of :class:`enum.StrEnum` for Python 3.10.

        Matches 3.11 semantics: ``str(member)`` and ``format(member)`` return
        the member *value*, not ``"ClassName.MEMBER"`` as plain ``Enum`` would.
        """

        def __str__(self) -> str:
            return str.__str__(self)

        def __format__(self, format_spec: str) -> str:
            return str.__format__(self, format_spec)


__all__ = ["StrEnum"]
