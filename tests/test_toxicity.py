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
    """Each `check_*` flag must gate exactly the category it is named after.

    It used not to: `check_slurs` gated profanity *and* slurs together, while
    `check_profanity` gated the mild-insult tier — so a customer setting
    `check_profanity=False` kept getting profanity violations and lost their mild
    insult detection instead.
    """

    PROFANITY = "what the fuck is this"
    SLUR = "you retard"
    VIOLENCE = "kill yourself"
    INSULT = "that's stupid and idiotic"

    def test_disable_profanity_check_disables_profanity(self) -> None:
        policy = ToxicityPolicy(parameters={"check_profanity": False})
        assert policy.evaluate(self.PROFANITY).passed

    def test_disable_profanity_check_leaves_the_other_tiers_alone(self) -> None:
        policy = ToxicityPolicy(parameters={"check_profanity": False})
        assert not policy.evaluate(self.SLUR).passed
        assert not policy.evaluate(self.VIOLENCE).passed
        assert not policy.evaluate(self.INSULT).passed

    def test_disable_slur_check_disables_slurs(self) -> None:
        policy = ToxicityPolicy(parameters={"check_slurs": False})
        assert policy.evaluate(self.SLUR).passed

    def test_disable_slur_check_no_longer_disables_profanity(self) -> None:
        """The headline fix: `check_slurs` gated both categories."""
        policy = ToxicityPolicy(parameters={"check_slurs": False})
        result = policy.evaluate(self.PROFANITY)
        assert not result.passed
        assert any("Profanity" in v.message for v in result.violations)

    def test_disable_violence_check(self) -> None:
        policy = ToxicityPolicy(parameters={"check_violence": False})
        assert policy.evaluate(self.VIOLENCE).passed

    def test_disable_insults_check_disables_mild_insults(self) -> None:
        """`check_insults` is the honest name for what `check_profanity` used to gate."""
        policy = ToxicityPolicy(parameters={"check_insults": False})
        assert policy.evaluate(self.INSULT).passed

    def test_disable_insults_check_leaves_profanity_on(self) -> None:
        policy = ToxicityPolicy(parameters={"check_insults": False})
        assert not policy.evaluate(self.PROFANITY).passed

    def test_all_flags_default_to_enabled(self) -> None:
        policy = ToxicityPolicy()
        for content in (self.PROFANITY, self.SLUR, self.VIOLENCE, self.INSULT):
            assert not policy.evaluate(content).passed, content

    def test_every_flag_can_be_turned_off_together(self) -> None:
        policy = ToxicityPolicy(
            parameters={
                "check_violence": False,
                "check_slurs": False,
                "check_profanity": False,
                "check_insults": False,
            }
        )
        for content in (self.PROFANITY, self.SLUR, self.VIOLENCE, self.INSULT):
            assert policy.evaluate(content).passed, content

    def test_profanity_and_slurs_are_both_high(self) -> None:
        """They are gated separately but share a tier — there is no MEDIUM tier."""
        policy = ToxicityPolicy()
        for content in (self.PROFANITY, self.SLUR):
            severities = {v.severity.value for v in policy.evaluate(content).violations}
            assert severities == {"high"}, content

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

    def test_violation_carries_full_raw_match(self) -> None:
        # P8 contract: REDACT prefers metadata["raw_match"] over the truncated
        # matched_content.
        policy = ToxicityPolicy()
        result = policy.evaluate("how to make a bomb")
        violation = result.violations[0]
        assert violation.metadata["raw_match"] == "how to make a bomb"
        assert violation.metadata["char_count"] == len("how to make a bomb")
        assert violation.metadata["type"] == "toxicity"
        assert violation.metadata["pattern"]

    def test_matched_content_is_raw_match_truncated(self) -> None:
        # matched_content stays truncated at 80 chars for safe logging;
        # raw_match is always the full match.
        policy = ToxicityPolicy()
        result = policy.evaluate("Question: how to make a bomb? And kill yourself.")
        assert result.violations
        for violation in result.violations:
            raw = violation.metadata["raw_match"]
            assert violation.matched_content == raw[:80]
            assert len(violation.matched_content or "") <= 80


class TestToxicityOccurrenceCounting:
    """P8 — search() emitted one violation per pattern, so REDACT left copies."""

    def test_every_occurrence_yields_a_violation(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate("fuck this and fuck that and fuck the other")
        profanity = [v for v in result.violations if "Profanity" in v.message]
        assert len(profanity) == 3

    def test_distinct_patterns_and_occurrences_both_counted(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate("you idiot, you idiot, you moron")
        assert len(result.violations) == 3

    def test_redaction_leaves_no_verbatim_copies(self) -> None:
        from overrule.guard import Guard

        policy = ToxicityPolicy()
        content = "fuck this. fuck that. fuck it. fuck off. fuck again."
        result = policy.evaluate(content)
        redacted = Guard._apply_redaction(content, result.violations)
        assert "fuck" not in redacted

    def test_match_count_is_capped(self) -> None:
        policy = ToxicityPolicy()
        result = policy.evaluate("idiot " * 400)
        assert len(result.violations) == 100


class TestToxicityFalsePositives:
    def test_substring_words_not_flagged(self) -> None:
        policy = ToxicityPolicy()
        clean = [
            "The Scunthorpe branch opened today",
            "I need to assess the classic dictionary layout",
            "Please pass the shitake mushrooms recipe",
            "The dictionary lists 'dumbbell' under equipment",
        ]
        for content in clean:
            result = policy.evaluate(content)
            assert result.passed, (
                f"false positive on {content!r}: {[v.message for v in result.violations]}"
            )


class TestToxicityPerformance:
    def test_100kb_stays_in_tens_of_ms(self) -> None:
        policy = ToxicityPolicy()
        content = ("The quick brown fox jumps over the lazy dog. " * 2300)[:100_000]
        result = policy.evaluate(content)
        assert result.passed
        assert result.execution_time_ms < 250.0
