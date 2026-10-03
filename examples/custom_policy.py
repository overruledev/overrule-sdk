"""Custom policy example — extend BasePolicy to create domain-specific rules.

Builds a topic-restriction policy and a content-length policy, then shows how
per-policy configuration (``GuardConfig.policies`` / ``PolicyConfig``) turns a
policy off or feeds it parameters without touching the policy code.

``guard.evaluate()`` is check-only: it never raises, even for violations that
carry ``blocked=True``. Enforcement happens in ``guard.chat()``,
``guard.stream()`` and ``@guard.protect()``.

Run:
    python examples/custom_policy.py
"""

import asyncio
from typing import Any

from overrule import Guard, GuardConfig, PolicyConfig
from overrule.models.violation import Violation, ViolationSeverity
from overrule.policies.base import BasePolicy, PolicyResult


class TopicRestrictionPolicy(BasePolicy):
    """Flag content that touches a restricted topic."""

    policy_id = "topic-restriction"
    description = "Prevents AI from giving advice on restricted topics"

    DEFAULT_TOPICS = {
        "medical advice": "Medical advice is restricted — refer users to professionals",
        "legal advice": "Legal advice is restricted — refer users to qualified attorneys",
        "financial advice": "Financial advice is restricted — add a disclaimer",
    }

    def __init__(self, parameters: dict[str, Any] | None = None) -> None:
        super().__init__(parameters)
        # Reachable via PolicyConfig(id="topic-restriction", parameters={...}).
        extra: dict[str, str] = self._parameters.get("extra_topics", {})
        self._topics = {**self.DEFAULT_TOPICS, **extra}

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        violations: list[Violation] = []
        lower = content.lower()

        for topic, explanation in self._topics.items():
            if topic in lower:
                violations.append(
                    Violation(
                        policy_id=self.policy_id,
                        severity=ViolationSeverity.HIGH,
                        # `message` is the field on Violation. There is no
                        # `description` field and no top-level `direction`.
                        message=explanation,
                        matched_content=topic,
                        metadata={
                            "type": "restricted_topic",
                            "direction": direction,
                            # `raw_match` is what REDACT and dedup use.
                            "raw_match": topic,
                        },
                    )
                )

        return PolicyResult(passed=len(violations) == 0, violations=violations)


class ContentLengthPolicy(BasePolicy):
    """Enforce a maximum content length to prevent abuse."""

    policy_id = "content-length"
    description = "Rejects inputs exceeding safe length thresholds"

    def __init__(self, parameters: dict[str, Any] | None = None) -> None:
        super().__init__(parameters)
        self._max_length = int(self._parameters.get("max_input_length", 5000))

    def evaluate(self, content: str, *, direction: str = "input") -> PolicyResult:
        if direction == "input" and len(content) > self._max_length:
            return PolicyResult(
                passed=False,
                violations=[
                    Violation(
                        policy_id=self.policy_id,
                        severity=ViolationSeverity.MEDIUM,
                        message=(
                            f"Input exceeds {self._max_length} characters ({len(content)} chars)"
                        ),
                        metadata={"type": "too_long", "direction": direction},
                    )
                ],
            )
        return PolicyResult(passed=True, violations=[])


SAMPLES = [
    "Can you give me medical advice about my headache?",
    "What's a good recipe for pasta?",
    "I need legal advice about my lease agreement",
    "A" * 6000,  # exceeds the configured length limit
]


async def run(guard: Guard, label: str) -> None:
    print(label)
    print("=" * 60)
    for text in SAMPLES:
        display = text[:60] + "..." if len(text) > 60 else text
        result = await guard.evaluate(text, policies=["topic-restriction", "content-length"])

        status = "FLAGGED" if not result.passed else "CLEAN  "
        color = "\033[91m" if not result.passed else "\033[92m"
        print(f'{color}{status}\033[0m  "{display}"')
        for violation in result.violations:
            print(f"         -> [{violation.severity.value}] {violation.message}")
    print()


async def build_guard(config: GuardConfig) -> Guard:
    guard = Guard(config=config)
    await guard._ensure_initialized()
    guard.register_policy(TopicRestrictionPolicy)
    guard.register_policy(ContentLengthPolicy)
    return guard


async def main() -> None:
    # PolicyConfig is honoured: `parameters` reach the policy constructor and
    # `enabled=False` stops the policy from running at all.
    guard = await build_guard(
        GuardConfig.from_env(
            policies=[
                PolicyConfig(id="content-length", parameters={"max_input_length": 1000}),
            ]
        )
    )
    await run(guard, "Custom Policy Demo — length limit lowered to 1000 chars")
    await guard.shutdown()

    # Same policies, but content-length switched off by configuration.
    guard = await build_guard(
        GuardConfig.from_env(policies=[PolicyConfig(id="content-length", enabled=False)])
    )
    await run(guard, "Same run with content-length disabled via PolicyConfig")
    await guard.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
