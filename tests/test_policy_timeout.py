"""Regression tests for the policy evaluation deadline (F4).

The 5s budget used to be measured *after* `policy.evaluate()` returned, so it
interrupted nothing: a catastrophically backtracking regex blocked the whole
asyncio event loop (measured 12.7s) and then raised PolicyEvaluationError, which
was re-raised ahead of the fail-open branch and skipped every remaining policy.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import textwrap
import threading
import time

import pytest

from overrule import Guard
from overrule._pool import PolicyPool
from overrule.exceptions import PolicyEvaluationError
from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies.base import BasePolicy, PolicyResult


class SlowPolicy(BasePolicy):
    """Stands in for a customer policy with catastrophic backtracking.

    A literal catastrophic regex is used deliberately *not* used here: a Python
    thread cannot be interrupted, so a real 12s regex would keep a pool worker busy
    past the end of the test session (the interpreter joins executor threads at
    exit). `time.sleep` reproduces exactly what matters — a blocking call the guard
    cannot cancel — deterministically and cheaply.
    """

    policy_id = "slow-policy"
    description = "Blocks its thread for a long time"

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        time.sleep(3.0)
        return PolicyResult(passed=True, violations=[])


class LaterPolicy(BasePolicy):
    policy_id = "later-policy"
    description = "Must still run after a policy times out"

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        return PolicyResult(
            passed=False,
            violations=[
                Violation(
                    policy_id=self.policy_id,
                    severity=ViolationSeverity.HIGH,
                    message="later policy ran",
                )
            ],
        )


class CrashingPolicy(BasePolicy):
    policy_id = "crashing-policy"
    description = "Raises"

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        raise RuntimeError("policy exploded")


@pytest.fixture
async def guard():
    g = Guard(api_key="test", fail_open=True)
    g._POLICY_TIMEOUT_MS = 200  # keep the test fast
    g.register_policy(SlowPolicy)
    g.register_policy(LaterPolicy)
    g.register_policy(CrashingPolicy)
    yield g
    await g.shutdown()


class TestDeadlineIsReal:
    @pytest.mark.asyncio
    async def test_timeout_is_enforced_not_merely_measured(self, guard: Guard) -> None:
        started = time.perf_counter()
        await guard._evaluate_content("content", ["slow-policy"], direction="input")
        elapsed = time.perf_counter() - started
        assert elapsed < 1.5, f"deadline not enforced: waited {elapsed:.2f}s"

    @pytest.mark.asyncio
    async def test_event_loop_is_not_blocked(self, guard: Guard) -> None:
        ticks = 0

        async def heartbeat() -> None:
            nonlocal ticks
            for _ in range(20):
                await asyncio.sleep(0.02)
                ticks += 1

        beat = asyncio.create_task(heartbeat())
        await guard._evaluate_content("content", ["slow-policy"], direction="input")
        assert ticks > 3, "the event loop was blocked while the policy ran"
        beat.cancel()

    @pytest.mark.asyncio
    async def test_fail_open_does_not_crash(self, guard: Guard) -> None:
        result = await guard._evaluate_content("content", ["slow-policy"], direction="input")
        assert result.violations == []

    @pytest.mark.asyncio
    async def test_remaining_policies_still_run_after_a_timeout(self, guard: Guard) -> None:
        result = await guard._evaluate_content(
            "content", ["slow-policy", "later-policy"], direction="input"
        )
        assert [v.policy_id for v in result.violations] == ["later-policy"]

    @pytest.mark.asyncio
    async def test_remaining_policies_still_run_after_a_crash(self, guard: Guard) -> None:
        result = await guard._evaluate_content(
            "content", ["crashing-policy", "later-policy"], direction="input"
        )
        assert [v.policy_id for v in result.violations] == ["later-policy"]

    @pytest.mark.asyncio
    async def test_timeout_logs_a_warning(self, guard: Guard, caplog) -> None:
        with caplog.at_level("WARNING", logger="overrule.guard"):
            await guard._evaluate_content("content", ["slow-policy"], direction="input")
        assert "timed out" in caplog.text
        assert "slow-policy" in caplog.text

    @pytest.mark.asyncio
    async def test_raises_only_when_fail_open_is_false(self) -> None:
        guard = Guard(api_key="test", fail_open=False)
        guard._POLICY_TIMEOUT_MS = 200
        guard.register_policy(SlowPolicy)
        try:
            with pytest.raises(PolicyEvaluationError):
                await guard._evaluate_content("content", ["slow-policy"], direction="input")
        finally:
            await guard.shutdown()

    @pytest.mark.asyncio
    async def test_skipped_policy_is_recorded_on_the_event(self, guard: Guard) -> None:
        """A skipped policy must not look like a clean pass."""
        from tests.fakes import RecordingReporter

        reporter = RecordingReporter()
        guard._reporter = reporter  # type: ignore[assignment]
        guard._initialized = True

        await guard.evaluate("content", policies=["slow-policy", "later-policy"])

        assert reporter.events
        metadata = reporter.events[-1].metadata
        assert metadata["degraded_policies"] == ["slow-policy"]

    @pytest.mark.asyncio
    async def test_healthy_evaluation_records_nothing_extra(self, guard: Guard) -> None:
        from tests.fakes import RecordingReporter

        reporter = RecordingReporter()
        guard._reporter = reporter  # type: ignore[assignment]
        guard._initialized = True

        await guard.evaluate("content", policies=["later-policy"])

        assert "degraded_policies" not in reporter.events[-1].metadata

    @pytest.mark.asyncio
    async def test_pool_is_shut_down_with_the_guard(self) -> None:
        guard = Guard(api_key="test")
        await guard._evaluate_content("hello", ["pii-detection"], direction="input")
        assert guard._policy_pool is not None
        await guard.shutdown()
        assert guard._policy_pool is None


class TestPoolRetirementIsBounded:
    """S9(a): `_orphaned_policy_runs >= _POLICY_POOL_WORKERS` fired on every timeout.

    Retirement set `_policy_pool = None` but left the orphan counter satisfied, so
    from the fourth stuck policy onwards *every* subsequent timeout retired a
    brand-new four-worker pool. Orphan bookkeeping is now scoped to the generation of
    the pool a run was actually scheduled against, so each pool retires exactly once.
    """

    @pytest.mark.asyncio
    async def test_each_pool_is_retired_at_most_once(self, guard: Guard, caplog) -> None:
        workers = guard._POLICY_POOL_WORKERS
        rounds = workers * 3
        with caplog.at_level("WARNING", logger="overrule.pool"):
            for _ in range(rounds):
                await guard._evaluate_content("x", ["slow-policy"], direction="input")

        retirements = caplog.text.count("Retiring policy thread pool")
        assert retirements == rounds // workers, (
            f"{retirements} retirements for {rounds} stuck runs across {workers} workers"
        )

    @pytest.mark.asyncio
    async def test_thread_growth_is_one_per_stuck_run(self, guard: Guard) -> None:
        """A stuck run costs exactly one unreclaimable thread, not a whole new pool."""

        def policy_threads() -> int:
            return sum(1 for t in threading.enumerate() if "overrule-policy" in t.name)

        before = policy_threads()
        rounds = guard._POLICY_POOL_WORKERS * 2
        for _ in range(rounds):
            await guard._evaluate_content("x", ["slow-policy"], direction="input")
        assert policy_threads() - before <= rounds

    @pytest.mark.asyncio
    async def test_evaluation_stays_available_after_starvation(self, guard: Guard) -> None:
        """The property retirement exists to protect: keep it."""
        for _ in range(guard._POLICY_POOL_WORKERS + 1):
            await guard._evaluate_content("x", ["slow-policy"], direction="input")

        started = time.perf_counter()
        result = await guard._evaluate_content("x", ["later-policy"], direction="input")
        elapsed_ms = (time.perf_counter() - started) * 1000
        assert [v.policy_id for v in result.violations] == ["later-policy"]
        assert elapsed_ms < 500, f"a healthy policy waited {elapsed_ms:.0f}ms"

    @pytest.mark.asyncio
    async def test_an_orphan_from_a_retired_pool_does_not_retire_the_new_one(self) -> None:
        pool = PolicyPool(max_workers=2)
        _executor, generation = pool.acquire()

        assert pool.note_orphan(_FakeFuture(), generation) is False
        assert pool.note_orphan(_FakeFuture(), generation) is True, "should retire at 2/2"
        retired_generation = generation

        # More orphans from the pool that is already gone must be inert.
        for _ in range(5):
            assert pool.note_orphan(_FakeFuture(), retired_generation) is False

        _new_executor, new_generation = pool.acquire()
        assert new_generation != retired_generation
        assert pool.orphaned_runs == 0
        pool.shutdown()


class TestPolicyWorkersAreDaemons:
    """S9(b): non-daemon workers meant a stuck policy blocked interpreter exit.

    `Guard.shutdown()` cannot reclaim a retired pool, and both
    `concurrent.futures`' atexit hook and `threading._shutdown` join every
    non-daemon thread — so a genuinely stuck policy meant the process never exited.
    """

    @pytest.mark.asyncio
    async def test_pool_threads_are_daemon_threads(self, guard: Guard) -> None:
        await guard._evaluate_content("hello", ["pii-detection"], direction="input")
        workers = [t for t in threading.enumerate() if "overrule-policy" in t.name]
        assert workers, "expected at least one policy worker"
        assert all(t.daemon for t in workers), "a non-daemon worker blocks process exit"

    def test_a_process_with_a_stuck_policy_still_exits(self, tmp_path) -> None:
        """End to end: a 120s policy under a 300ms deadline must not delay exit."""
        script = textwrap.dedent(
            """
            import asyncio, os, sys, time
            os.environ["OVERRULE_DLQ_DIR"] = sys.argv[1]
            os.environ["OVERRULE_ENDPOINT"] = "http://127.0.0.1:1/api"
            from overrule import Guard
            from overrule.policies.base import BasePolicy, PolicyResult

            class Stuck(BasePolicy):
                policy_id = "stuck"
                description = "never returns in time"
                def evaluate(self, content, *, direction="input"):
                    time.sleep(120.0)
                    return PolicyResult(passed=True, violations=[])

            async def main():
                guard = Guard(api_key="test")
                guard._POLICY_TIMEOUT_MS = 300
                guard.register_policy(Stuck)
                await guard._evaluate_content("x", ["stuck"], direction="input")
                await guard.shutdown()

            asyncio.run(main())
            print("exited cleanly")
            """
        )
        started = time.perf_counter()
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user input
            [sys.executable, "-c", script, str(tmp_path / "dlq")],
            capture_output=True,
            text=True,
            timeout=60,
        )
        elapsed = time.perf_counter() - started
        assert completed.returncode == 0, completed.stderr
        assert "exited cleanly" in completed.stdout
        assert elapsed < 30, f"interpreter took {elapsed:.1f}s to exit (policy sleeps 120s)"


class _FakeFuture:
    """Minimal future stand-in for PolicyPool bookkeeping tests."""

    def add_done_callback(self, fn) -> None:  # noqa: D102
        return None

    def exception(self, *_args) -> None:  # noqa: D102
        return None


class TestSyncPathStillWorks:
    def test_sync_guard_evaluate(self) -> None:
        from overrule import SyncGuard

        with SyncGuard(api_key="test") as guard:
            result = guard.evaluate("My SSN is 123-45-6789", policies=["pii-detection"])
            assert not result.passed

    def test_sync_protect_still_blocks(self) -> None:
        from overrule import SyncGuard, ViolationError
        from overrule.models.config import PolicyAction

        with SyncGuard(api_key="test", default_action=PolicyAction.BLOCK) as guard:

            @guard.protect(policies=["pii-detection"], action=PolicyAction.BLOCK)
            def send(body: str) -> str:  # pragma: no cover - must not execute
                raise AssertionError("executed despite a violation")

            with pytest.raises(ViolationError):
                send("SSN: 123-45-6789")
