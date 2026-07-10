"""Structured logging configuration for the overrule SDK."""

from __future__ import annotations

import logging
import sys
from typing import Any

_LOGGER_NAME = "overrule"
_configured = False


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a namespaced overrule logger."""
    if name:
        return logging.getLogger(f"{_LOGGER_NAME}.{name}")
    return logging.getLogger(_LOGGER_NAME)


def configure_logging(
    *,
    level: int | str = logging.WARNING,
    handler: logging.Handler | None = None,
    format_string: str | None = None,
) -> None:
    """Configure the overrule SDK logging.

    Call this once at application startup to control SDK log output.
    If not called, the SDK defaults to WARNING level with no handler
    (respects the application's root logger configuration).
    """
    global _configured
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level)

    if handler is None and not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        fmt = format_string or "[%(levelname)s] overrule.%(name)s: %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
    elif handler is not None:
        logger.addHandler(handler)

    logger.propagate = False
    _configured = True


def _log_structured(
    logger: logging.Logger,
    level: int,
    message: str,
    **fields: Any,
) -> None:
    """Emit a structured log entry with additional fields as extras."""
    if logger.isEnabledFor(level):
        extra_str = " ".join(f"{k}={v}" for k, v in fields.items() if v is not None)
        full_message = f"{message} {extra_str}".strip() if extra_str else message
        logger.log(level, full_message)
