"""Tests for the toxicity detection policy."""

from overrule.policies.toxicity import ToxicityPolicy


class TestToxicityBasicDetection:
    def test_detects_profanity(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate("what the fuck is this")
        assert not result.passed
        assert len(result.violations) >= 1
        assert result.violations[0].policy_id == "toxicity-detection"

    def test_detects_slurs(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate("you're such a retard")
        assert not result.passed
        assert any("Slur" in v.message for v in result.violations)

    def test_detects_violence_incitement(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate("you should kill yourself")
        assert not result.passed
        assert any(v.severity.value == "critical" for v in result.violations)

    def test_detects_dangerous_instructions(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate("how to make a bomb")
        assert not result.passed
        assert any(v.severity.value == "critical" for v in result.violations)

    def test_clean_content_passes(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate("Hello, how can I help you today?")
        assert result.passed
        assert len(result.violations) == 0

    def test_technical_content_passes(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate(
            "The function returns a dictionary with keys 'model' and 'choices'."
        )
        assert result.passed

    def test_mild_insults_detected(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate("that's a stupid idea, you idiot")
        assert not result.passed
        assert any("Mildly toxic" in v.message for v in result.violations)


class TestToxicityConfiguration:
    def test_disable_profanity_check(self) -> None:
        policy = ToxicityPolicy(parameters={"check_profanity": False})
        result = policy.evaluate("that's stupid and idiotic")
        assert result.passed

    def test_disable_slur_check(self) -> None:
        policy = ToxicityPolicy(parameters={"check_slurs": False})
        result = policy.evaluate("you retard")
        assert result.passed

    def test_disable_violence_check(self) -> None:
        policy = ToxicityPolicy(parameters={"check_violence": False})
        result = policy.evaluate("kill yourself")
        assert result.passed

    def test_min_severity_filters_low(self) -> None:
        policy = ToxicityPolicy(parameters={"min_severity": "high"})
        result = policy.evaluate("you're an idiot")
        assert result.passed

    def test_min_severity_keeps_critical(self) -> None:
        policy = ToxicityPolicy(parameters={"min_severity": "high"})
        result = policy.evaluate("kill yourself loser")
        assert not result.passed


class TestToxicityMetadata:
    def test_violation_contains_matched_content(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate("what the fuck")
        assert result.violations[0].matched_content is not None

    def test_violation_has_direction_metadata(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate("fuck off", direction="output")
        assert result.violations[0].metadata["direction"] == "output"

    def test_execution_time_recorded(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate("some clean content")
        assert result.execution_time_ms >= 0
