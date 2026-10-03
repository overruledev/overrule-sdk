"""Regression tests for Guard registry bookkeeping and the atexit flush (S7, S11).

S7: `_active_guards` held only weakrefs, and `_atexit_flush` skipped a dead ref
silently. The most idiomatic usage —

    async def main():
        guard = Guard()
        await guard.evaluate(...)
    asyncio.run(main())

— collects the Guard before `atexit` runs, so its buffered events were dropped with
no warning at all, contradicting `EventReporter.stop()`'s promise that unsent events
are persisted "instead of being discarded at process exit". A module-level Guard
worked fine, which is why nothing caught it.

S11: the registry was pruned only inside `shutdown()`, so constructing a Guard per
request grew it without bound (60 short-lived Guards left len=60, all dead refs).
"""

from __future__ import annotations

import gc
import subprocess
import sys
import textwrap

import pytest

from overrule import Guard
from overrule import guard as guard_module

# A port nothing listens on, so the flush fails and the event lands in the DLQ.
DEAD_ENDPOINT = "http://127.0.0.1:1/api"


def _registry_size() -> tuple[int, int]:
    with guard_module._active_guards_lock:
        refs = list(guard_module._active_guards)
    return len(refs), sum(1 for ref in refs if ref() is None)


class TestRegistryIsPruned:
    def test_collected_guards_leave_no_dead_refs(self) -> None:
        before, _ = _registry_size()
        for _ in range(60):
            Guard(api_key="test")
        gc.collect()
        after, dead = _registry_size()
        assert dead == 0, f"{dead} dead weakrefs left behind"
        assert after <= before, "the registry grew for guards that are already gone"

    @pytest.mark.asyncio
    async def test_shutdown_still_removes_its_own_entry(self) -> None:
        before, _ = _registry_size()
        guard = Guard(api_key="test")
        assert _registry_size()[0] == before + 1
        await guard.shutdown()
        assert _registry_size()[0] == before

    @pytest.mark.asyncio
    async def test_a_shutdown_guard_is_not_retained_as_an_orphan(self) -> None:
        guard = Guard(api_key="test")
        await guard._ensure_initialized()
        guard._reporter.enqueue_count = 0  # type: ignore[attr-defined]
        await guard.shutdown()
        with guard_module._active_guards_lock:
            assert guard._reporter not in guard_module._orphaned_reporters


class TestCollectedGuardsAreRescued:
    def test_a_reporter_with_pending_events_is_retained(self) -> None:
        """The in-process half of S7: the strong ref that makes the flush possible."""
        guard = Guard(api_key="test", endpoint=DEAD_ENDPOINT)
        guard._initialized = True
        reporter = guard._reporter
        reporter.enqueue(_an_event())
        assert reporter.pending_count == 1

        del guard
        gc.collect()

        with guard_module._active_guards_lock:
            retained = list(guard_module._orphaned_reporters)
        assert reporter in retained, "buffered events were abandoned on collection"

    def test_an_empty_reporter_is_not_retained(self) -> None:
        """Nothing to rescue means nothing is held on to — this must not leak."""
        guard = Guard(api_key="test", endpoint=DEAD_ENDPOINT)
        reporter = guard._reporter
        assert reporter.pending_count == 0

        del guard
        gc.collect()

        with guard_module._active_guards_lock:
            assert reporter not in guard_module._orphaned_reporters

    def test_the_orphan_registry_is_bounded(self) -> None:
        for _ in range(guard_module._MAX_ORPHANED_REPORTERS + 25):
            guard = Guard(api_key="test", endpoint=DEAD_ENDPOINT)
            guard._initialized = True
            guard._reporter.enqueue(_an_event())
            del guard
        gc.collect()
        with guard_module._active_guards_lock:
            held = len(guard_module._orphaned_reporters)
        assert held <= guard_module._MAX_ORPHANED_REPORTERS


def _an_event():
    from overrule.models.event import EventStatus, EventType, InterceptEvent

    return InterceptEvent(
        event_type=EventType.LLM_CALL,
        status=EventStatus.FLAGGED,
        input_content="test",
        latency_ms=1.0,
    )


# The end-to-end half of S7 needs a real process exit, so it runs in a subprocess.
_SCRIPT = """
import asyncio, os, sys
os.environ["OVERRULE_DLQ_DIR"] = sys.argv[1]
os.environ["OVERRULE_ENDPOINT"] = "http://127.0.0.1:1/api"
from overrule import Guard

async def main():
    guard = Guard(api_key="test")
    await guard.evaluate("SSN 123-45-6789", policies=["pii-detection"])

asyncio.run(main())
"""


def _dlq_lines(directory) -> int:
    path = directory / "dead_letter.jsonl"
    if not path.exists():
        return 0
    return len([line for line in path.read_text().splitlines() if line.strip()])


class TestAtexitFlushOnRealProcessExit:
    def test_a_guard_collected_before_exit_still_persists_its_events(self, tmp_path) -> None:
        directory = tmp_path / "dlq"
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user input
            [sys.executable, "-c", textwrap.dedent(_SCRIPT), str(directory)],
            capture_output=True,
            text=True,
            timeout=90,
        )
        assert completed.returncode == 0, completed.stderr
        assert _dlq_lines(directory) == 1, (
            "the event was lost at process exit; stderr was:\n" + completed.stderr
        )

    def test_the_loss_is_reported_rather_than_silent(self, tmp_path) -> None:
        directory = tmp_path / "dlq"
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user input
            [sys.executable, "-c", textwrap.dedent(_SCRIPT), str(directory)],
            capture_output=True,
            text=True,
            timeout=90,
        )
        assert completed.returncode == 0, completed.stderr
        assert "dead-letter queue" in completed.stderr
