"""Synchronous usage — for scripts, notebooks, and non-async codebases.

SyncGuard provides the same API as Guard without requiring async/await.

Run:
    python examples/sync_usage.py
"""

from overrule import SyncGuard


def main() -> None:
    with SyncGuard() as guard:
        # Evaluate content without an LLM call
        result = guard.evaluate(
            "Send payment to account 4532-1234-5678-9012",
            policies=["pii-detection"],
        )

        print("Sync Evaluation Demo")
        print("=" * 60)
        print()

        if not result.passed:
            print(f"✗ {len(result.violations)} violation(s) detected:")
            for v in result.violations:
                print(f"  - [{v.severity}] {v.description}")
        else:
            print("✓ Content passed all policies")

        print()
        print("SyncGuard works in scripts, Jupyter notebooks, and Django views.")


if __name__ == "__main__":
    main()
