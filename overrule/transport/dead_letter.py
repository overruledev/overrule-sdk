"""Dead-letter queue — persists dropped events to disk for recovery on next startup."""

from __future__ import annotations

import json
import logging
import os
import threading
from collections import deque
from pathlib import Path
from typing import Any

logger = logging.getLogger("overrule.transport.dead_letter")

_DEFAULT_DIR = ".overrule"
_DLQ_FILE = "dead_letter.jsonl"
_REJECTED_FILE = "rejected.jsonl"
_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB cap


class DeadLetterQueue:
    """Persists failed events to a JSONL file for recovery.

    Events that exhaust retries in the EventReporter are written to disk
    instead of being silently dropped. On next startup, these events are
    loaded back into the send buffer for automatic retry.

    Events the server rejected *permanently* (a 4xx that will never succeed) go
    to a second file, ``rejected.jsonl``, which :meth:`recover` never reads. They
    are kept for inspection only. Writing them to the recoverable queue turned a
    bad API key or a schema mismatch into an infinite poison-pill loop: every
    process start re-POSTed the same rejected batch, got the same 4xx, and wrote
    it straight back to disk.

    Each file is capped at 10MB — oldest events are trimmed when exceeded.
    """

    def __init__(self, directory: str | None = None) -> None:
        base = directory or os.getenv("OVERRULE_DLQ_DIR") or _DEFAULT_DIR
        self._path = Path(base) / _DLQ_FILE
        self._rejected_path = Path(base) / _REJECTED_FILE
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def rejected_path(self) -> Path:
        """File holding permanently-rejected events. Never recovered."""
        return self._rejected_path

    def write(self, event: dict[str, Any], *, permanent: bool = False) -> None:
        """Append a failed event to disk. Thread-safe.

        ``permanent=True`` routes the event to :attr:`rejected_path` so it is
        retained for inspection but never retried.
        """
        target = self._rejected_path if permanent else self._path
        with self._lock:
            try:
                if target.exists() and target.stat().st_size > _MAX_FILE_SIZE:
                    self._trim(target)
                with target.open("a") as f:
                    f.write(json.dumps(event, default=str) + "\n")
            except Exception as exc:
                logger.debug("Failed to write dead-letter event: %s", exc)

    def recover(self) -> deque[dict[str, Any]]:
        """Load and clear the *retryable* dead-letter events. Thread-safe.

        Returns events in original order. Clears the file after reading.
        Permanently-rejected events (:attr:`rejected_path`) are never returned.
        """
        with self._lock:
            events: deque[dict[str, Any]] = deque()
            if not self._path.exists():
                return events

            try:
                with self._path.open() as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                events.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                self._path.unlink()
                if events:
                    logger.info("Recovered %d dead-letter events for retry", len(events))
            except Exception as exc:
                logger.debug("Failed to recover dead-letter events: %s", exc)

            return events

    @property
    def count(self) -> int:
        """Number of retryable events currently in the dead-letter file."""
        return self._count_lines(self._path)

    @property
    def rejected_count(self) -> int:
        """Number of permanently-rejected events retained for inspection."""
        return self._count_lines(self._rejected_path)

    @staticmethod
    def _count_lines(path: Path) -> int:
        if not path.exists():
            return 0
        try:
            with path.open() as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0

    @staticmethod
    def _trim(path: Path) -> None:
        """Keep only the most recent half of events when file exceeds max size."""
        try:
            lines = path.read_text().splitlines()
            keep = lines[len(lines) // 2 :]
            path.write_text("\n".join(keep) + "\n")
            logger.debug("Trimmed dead-letter file from %d to %d events", len(lines), len(keep))
        except Exception as exc:
            logger.debug("Failed to trim dead-letter file: %s", exc)
