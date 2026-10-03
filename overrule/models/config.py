"""Configuration models for overrule SDK."""

from __future__ import annotations

import os
from typing import Any

from pydantic import BaseModel, Field

from overrule._compat import StrEnum
from overrule.models.violation import ViolationSeverity


class PolicyAction(StrEnum):
    """Action to take when a policy violation is detected."""

    BLOCK = "block"
    LOG = "log"
    WARN = "warn"
    REDACT = "redact"


class PolicyConfig(BaseModel):
    """Configuration for a single policy."""

    id: str
    enabled: bool = True
    action: PolicyAction = PolicyAction.LOG
    #: Force every violation from this policy to a fixed severity, replacing the
    #: severity the policy itself assigned. The policy's own value is preserved on
    #: the violation as ``metadata["original_severity"]``. Applied to input, output
    #: and streamed evaluation alike. ``None`` (default) keeps the policy's severity.
    severity_override: ViolationSeverity | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class GuardConfig(BaseModel):
    """Top-level configuration for the Guard instance."""

    api_key: str | None = Field(default=None, repr=False, exclude=True)
    endpoint: str = "https://overrule.dev/api"
    environment: str = "production"
    policies: list[PolicyConfig] = Field(default_factory=list)
    default_action: PolicyAction = PolicyAction.WARN
    fail_open: bool = True
    batch_size: int = Field(default=50, ge=1, le=100)
    flush_interval_seconds: float = Field(default=5.0, ge=0.1, le=300.0)
    #: Cap on how much content is *stored and reported*. Policy evaluation always
    #: scans the full content in overlapping windows (see ``Guard._evaluate_content``).
    max_content_length: int = Field(default=100_000, ge=1_000, le=10_000_000)
    max_retries: int = Field(default=3, ge=0, le=10)
    circuit_break_threshold: int = Field(default=5, ge=1, le=100)
    circuit_break_cooldown_seconds: float = Field(default=30.0, ge=1.0, le=600.0)
    #: Off by default: prompts and completions never leave your infrastructure.
    #: When enabled, a *masked* (shape-only) preview of each match is reported
    #: alongside its length and hash to help debug policy false positives.
    send_match_preview: bool = False

    @classmethod
    def from_env(cls, **overrides: Any) -> GuardConfig:
        """Load configuration from environment variables with explicit overrides.

        Env vars use OVERRULE_ prefix:
            OVERRULE_API_KEY, OVERRULE_ENDPOINT, OVERRULE_ENVIRONMENT,
            OVERRULE_FAIL_OPEN, OVERRULE_DEFAULT_ACTION, OVERRULE_BATCH_SIZE,
            OVERRULE_FLUSH_INTERVAL, OVERRULE_MAX_CONTENT_LENGTH,
            OVERRULE_SEND_MATCH_PREVIEW
        """
        env_values: dict[str, Any] = {}

        if api_key := os.getenv("OVERRULE_API_KEY"):
            env_values["api_key"] = api_key
        if endpoint := os.getenv("OVERRULE_ENDPOINT"):
            env_values["endpoint"] = endpoint
        if environment := os.getenv("OVERRULE_ENVIRONMENT"):
            env_values["environment"] = environment
        if fail_open := os.getenv("OVERRULE_FAIL_OPEN"):
            env_values["fail_open"] = fail_open.lower() not in ("false", "0", "no")
        if default_action := os.getenv("OVERRULE_DEFAULT_ACTION"):
            env_values["default_action"] = default_action
        if batch_size := os.getenv("OVERRULE_BATCH_SIZE"):
            env_values["batch_size"] = int(batch_size)
        if flush_interval := os.getenv("OVERRULE_FLUSH_INTERVAL"):
            env_values["flush_interval_seconds"] = float(flush_interval)
        if max_content := os.getenv("OVERRULE_MAX_CONTENT_LENGTH"):
            env_values["max_content_length"] = int(max_content)
        if send_preview := os.getenv("OVERRULE_SEND_MATCH_PREVIEW"):
            env_values["send_match_preview"] = send_preview.lower() in ("true", "1", "yes")

        # Explicit overrides take precedence
        merged = {**env_values, **{k: v for k, v in overrides.items() if v is not None}}
        return cls(**merged)
