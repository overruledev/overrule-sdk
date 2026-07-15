"""Framework integrations for Overrule governance."""

from __future__ import annotations

__all__ = ["OverruleCallback"]


def __getattr__(name: str) -> object:
    if name == "OverruleCallback":
        from overrule.integrations.langchain import OverruleCallback

        return OverruleCallback
    raise AttributeError(f"module 'overrule.integrations' has no attribute '{name}'")
