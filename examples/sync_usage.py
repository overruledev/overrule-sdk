"""Synchronous usage — for scripts, notebooks, and non-async codebases.

SyncGuard provides the same API as Guard without requiring async/await.

Note that `guard.evaluate()` is check-only and never raises. `@guard.protect()`
does enforce: violations carrying `blocked=True` (prompt injection, SQL
injection, jailbreak) raise `ViolationError` regardless of the configured
action.

Run:
    python examples/sync_usage.py
"""

from overrule import SyncGuard, ViolationError


def main() -> None:
    with SyncGuard() as guard:
        print("Sync Evaluation Demo")
        print("=" * 60)
        print()

        # 1. Check-only evaluation (never raises)
        result = guard.evaluate(
            "Send payment to card 4532 0151 1283 0366",
            policies=["pii-detection"],
        )

        if not result.passed:
            print(f"{len(result.violations)} violation(s) detected:")
            for violation in result.violations:
                print(f"  - [{violation.severity.value}] {violation.message}")
        else:
            print("Content passed all policies")
        print()

        # 2. Enforcement via the decorator
        @guard.protect(policies=["injection-detection"])
        def query_database(sql: str) -> str:
            return f"executed: {sql}"

        print("Protected function, clean argument:")
        clean_sql = "SELECT name FROM users WHERE id = 1"  # noqa: S608 - demo string
        print(f"  {query_database(clean_sql)}")
        print()

        print("Protected function, SQL injection argument:")
        try:
            query_database("'; DROP TABLE users; --")
            print("  NOT blocked (unexpected)")
        except ViolationError as exc:
            print(f"  blocked: {exc}")
        print()

        print("SyncGuard works in scripts, Jupyter notebooks, and Django views.")


if __name__ == "__main__":
    main()
