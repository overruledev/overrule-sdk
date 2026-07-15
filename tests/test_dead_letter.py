"""Tests for dead-letter queue persistence and recovery."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from overrule.transport.dead_letter import DeadLetterQueue


@pytest.fixture
def dlq(tmp_path):
    """Create a DLQ with a temp directory."""
    return DeadLetterQueue(directory=str(tmp_path))


def test_write_and_recover(dlq: DeadLetterQueue):
    """Events written to DLQ can be recovered."""
    event = {"id": "test-1", "event_type": "llm_call", "status": "blocked"}
    dlq.write(event)

    recovered = dlq.recover()
    assert len(recovered) == 1
    assert recovered[0]["id"] == "test-1"


def test_recover_clears_file(dlq: DeadLetterQueue):
    """Recovery clears the DLQ file."""
    dlq.write({"id": "test-1"})
    dlq.write({"id": "test-2"})

    recovered = dlq.recover()
    assert len(recovered) == 2

    # Second recover should be empty
    recovered_again = dlq.recover()
    assert len(recovered_again) == 0


def test_recover_empty_when_no_file(dlq: DeadLetterQueue):
    """Recovery returns empty deque when no file exists."""
    recovered = dlq.recover()
    assert len(recovered) == 0


def test_count_property(dlq: DeadLetterQueue):
    """Count reflects number of events in file."""
    assert dlq.count == 0

    dlq.write({"id": "1"})
    dlq.write({"id": "2"})
    dlq.write({"id": "3"})

    assert dlq.count == 3


def test_multiple_events_preserve_order(dlq: DeadLetterQueue):
    """Events are recovered in the same order they were written."""
    for i in range(5):
        dlq.write({"id": f"event-{i}", "order": i})

    recovered = dlq.recover()
    assert len(recovered) == 5
    for i, event in enumerate(recovered):
        assert event["order"] == i


def test_handles_corrupt_lines_gracefully(dlq: DeadLetterQueue):
    """Corrupt JSON lines are skipped during recovery."""
    with dlq.path.open("w") as f:
        f.write(json.dumps({"id": "valid-1"}) + "\n")
        f.write("this is not json\n")
        f.write(json.dumps({"id": "valid-2"}) + "\n")
        f.write("{broken json\n")
        f.write(json.dumps({"id": "valid-3"}) + "\n")

    recovered = dlq.recover()
    assert len(recovered) == 3
    assert recovered[0]["id"] == "valid-1"
    assert recovered[1]["id"] == "valid-2"
    assert recovered[2]["id"] == "valid-3"


def test_trim_on_large_file(tmp_path):
    """File is trimmed when it exceeds max size."""
    dlq = DeadLetterQueue(directory=str(tmp_path))

    # Write enough to exceed 10MB cap (each event ~10KB, 1100 = ~11MB)
    large_event = {"id": "x", "data": "y" * 10000}
    for _ in range(1100):
        dlq.write(large_event)

    # File should exist
    assert dlq.path.exists()
    file_size = dlq.path.stat().st_size

    # File should have been trimmed at least once (less than 1100 * ~10KB = 11MB)
    assert file_size < 11 * 1024 * 1024

    # Count should be less than 1100 due to trimming
    count = dlq.count
    assert count < 1100
    assert count > 0


def test_write_with_non_serializable_data(dlq: DeadLetterQueue):
    """Events with non-JSON-serializable data use default=str fallback."""
    from datetime import datetime, timezone

    event = {
        "id": "test-datetime",
        "timestamp": datetime(2026, 7, 12, tzinfo=timezone.utc),
    }
    dlq.write(event)

    recovered = dlq.recover()
    assert len(recovered) == 1
    assert "2026-07-12" in recovered[0]["timestamp"]


def test_path_property(dlq: DeadLetterQueue):
    """Path property returns the DLQ file path."""
    assert dlq.path.name == "dead_letter.jsonl"
    assert dlq.path.parent.exists()
