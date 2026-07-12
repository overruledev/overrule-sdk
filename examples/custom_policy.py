"""Custom policy example — extend BasePolicy to create domain-specific rules.

This example creates a topic restriction policy that blocks medical advice
and a profanity filter. Shows how to build your own policies.

Run:
    python examples/custom_policy.py
"""

import asyncio

from overrule import Guard
from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies.base import BasePolicy, PolicyResult


class TopicRestrictionPolicy(BasePolicy):
    """Block responses that contain restricted topics."""

    policy_id = "topic-restriction"
    description = "Prevents AI from giving advice on restricted topics"

    RESTRICTED_TOPICS = [
        ("medical advice", "Medical advice is restricted — refer users to professionals"),
        ("legal advice", "Legal advice is restricted — refer users to qualified attorneys"),
        ("financial advice", "Financial advice is restricted — add appropriate disclaimers"),
    ]

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        violations: list[Violation] = []
        lower = content.lower()

        for topic, description in self.RESTRICTED_TOPICS:
            if topic in lower:
                violations.append(
                    Violation(
                        policy_id=self.policy_id,
                        severity=ViolationSeverity.HIGH,
                        description=description,
                        matched_content=topic,
                        direction=direction,
                    )
                )

        return PolicyResult(passed=len(violations) == 0, violations=violations)


class ContentLengthPolicy(BasePolicy):
    """Enforce maximum content length to prevent abuse."""

    policy_id = "content-length"
    description = "Rejects inputs exceeding safe length thresholds"

    MAX_INPUT_LENGTH = 5000

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        if direction == "input" and len(content) > self.MAX_INPUT_LENGTH:
            return PolicyResult(
                passed=False,
                violations=[
                    Violation(
                        policy_id=self.policy_id,
                        severity=ViolationSeverity.MEDIUM,
                        description=f"Input exceeds {self.MAX_INPUT_LENGTH} characters ({len(content)} chars)",
                        direction=direction,
                    )
                ],
            )
        return PolicyResult(passed=True, violations=[])


async def main() -> None:
    guard = Guard()
    await guard._ensure_initialized()

    # Register custom policies
    guard.register_policy(TopicRestrictionPolicy)
    guard.register_policy(ContentLengthPolicy)

    print("Custom Policy Demo")
    print("=" * 60)
    print()

    # Test topic restriction
    samples = [
        "Can you give me medical advice about my headache?",
        "What's a good recipe for pasta?",
        "I need legal advice about my lease agreement",
        "A" * 6000,  # exceeds length limit
    ]

    for text in samples:
        display = text[:60] + "..." if len(text) > 60 else text
        result = await guard.evaluate(
            text,
            policies=["topic-restriction", "content-length"],
        )

        status = "✗ BLOCKED" if not result.passed else "✓ ALLOWED"
        color = "\033[91m" if not result.passed else "\033[92m"
        reset = "\033[0m"

        print(f"{color}{status}{reset}  \"{display}\"")
        for v in result.violations:
            print(f"         → {v.description}")
        print()

    await guard.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
