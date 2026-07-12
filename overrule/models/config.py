"""Configuration models for overrule SDK."""

from __future__ import annotations

import os
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class PolicyAction(StrEnum):
    """Action to take when a policy violation is detected."""

    BLOCK = "block"
    LOG = "log"
    WARN = "warn"


class PolicyConfig(BaseModel):
    """Configuration for a single policy."""

    id: str
    enabled: bool = True
    action: PolicyAction = PolicyAction.LOG
    severity_override: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


class GuardConfig(BaseModel):
    """Top-level configuration for the Guard instance."""

    api_key: str | None = Field(default=None, repr=False, exclude=True)
    endpoint: str = "https://overrule.dev/api"
    environment: str = "production"
    policies: list[PolicyConfig] = Field(default_factory=list)
    default_action: PolicyAction = PolicyAction.LOG
    fail_open: bool = True
    async_reporting: bool = True
    batch_size: int = Field(default=50, ge=1, le=10_000)
    flush_interval_seconds: float = Field(default=5.0, ge=0.1, le=300.0)
    max_content_length: int = Field(default=100_000, ge=1_000, le=10_000_000)
    max_retries: int = Field(default=3, ge=0, le=10)
    circuit_break_threshold: int = Field(default=5, ge=1, le=100)
    circuit_break_cooldown_seconds: float = Field(default=30.0, ge=1.0, le=600.0)
    redact_on_block: bool = True

    @classmethod
    def from_env(cls, **overrides: Any) -> GuardConfig:
        """Load configuration from environment variables with explicit overrides.

        Env vars use OVERRULE_ prefix:
            OVERRULE_API_KEY, OVERRULE_ENDPOINT, OVERRULE_ENVIRONMENT,
            OVERRULE_FAIL_OPEN, OVERRULE_DEFAULT_ACTION, OVERRULE_BATCH_SIZE,
            OVERRULE_FLUSH_INTERVAL, OVERRULE_MAX_CONTENT_LENGTH
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

        # Explicit overrides take precedence
        merged = {**env_values, **{k: v for k, v in overrides.items() if v is not None}}
        return cls(**merged)
