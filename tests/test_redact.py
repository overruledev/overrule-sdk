"""Tests for the REDACT policy action in the Guard."""

import os
from unittest.mock import AsyncMock, patch

import pytest

from overrule.guard import Guard
from overrule.models.config import PolicyAction


@pytest.fixture
def guard_redact():
    """Create a Guard configured with REDACT action."""
    return Guard(
        api_key="sk_ovr_test",
        default_action=PolicyAction.REDACT,
    )


class TestRedactAction:
    def test_apply_redaction_uses_raw_match_from_metadata(self) -> None:
        from overrule.models.violation import Violation, ViolationSeverity

        violations = [
            Violation(
                policy_id="pii-detection",
                severity=ViolationSeverity.CRITICAL,
                message="SSN detected",
                matched_content="*******6789",
                metadata={"raw_match": "123-45-6789"},
            )
        ]
        content = "The customer SSN is 123-45-6789 on file."
        result = Guard._apply_redaction(content, violations)
        assert "123-45-6789" not in result
        assert "[PII_DETECTION]" in result

    def test_apply_redaction_falls_back_to_matched_content(self) -> None:
        from overrule.models.violation import Violation, ViolationSeverity

        violations = [
            Violation(
                policy_id="toxicity-detection",
                severity=ViolationSeverity.LOW,
                message="Profanity",
                matched_content="damn",
            )
        ]
        content = "oh damn that's bad"
        result = Guard._apply_redaction(content, violations)
        assert "damn" not in result
        assert "[TOXICITY_DETECTION]" in result

    def test_apply_redaction_handles_multiple_violations(self) -> None:
        from overrule.models.violation import Violation, ViolationSeverity

        violations = [
            Violation(
                policy_id="pii-detection",
                severity=ViolationSeverity.MEDIUM,
                message="Email detected",
                matched_content="****@example.com",
                metadata={"raw_match": "test@example.com"},
            ),
            Violation(
                policy_id="pii-detection",
                severity=ViolationSeverity.MEDIUM,
                message="Phone detected",
                matched_content="***-***-4567",
                metadata={"raw_match": "555-123-4567"},
            ),
        ]
        content = "Email: test@example.com, Phone: 555-123-4567"
        result = Guard._apply_redaction(content, violations)
        assert "test@example.com" not in result
        assert "555-123-4567" not in result
        assert result.count("[PII_DETECTION]") == 2

    def test_apply_redaction_no_match_in_content_is_noop(self) -> None:
        from overrule.models.violation import Violation, ViolationSeverity

        violations = [
            Violation(
                policy_id="pii-detection",
                severity=ViolationSeverity.CRITICAL,
                message="SSN detected",
                matched_content="*******6789",
            )
        ]
        content = "Clean content with no PII."
        result = Guard._apply_redaction(content, violations)
        assert result == content

    def test_apply_redaction_different_policy_ids(self) -> None:
        from overrule.models.violation import Violation, ViolationSeverity

        violations = [
            Violation(
                policy_id="pii-detection",
                severity=ViolationSeverity.MEDIUM,
                message="Email detected",
                matched_content="****@corp.com",
                metadata={"raw_match": "user@corp.com"},
            ),
            Violation(
                policy_id="toxicity-detection",
                severity=ViolationSeverity.LOW,
                message="Profanity",
                matched_content="damn",
            ),
        ]
        content = "Send to user@corp.com, damn it"
        result = Guard._apply_redaction(content, violations)
        assert "[PII_DETECTION]" in result
        assert "[TOXICITY_DETECTION]" in result

    def test_replace_output_modifies_response(self) -> None:
        response = {
            "choices": [{"message": {"role": "assistant", "content": "Original output"}}],
            "model": "gpt-4o",
        }
        result = Guard._replace_output(response, "Redacted output")
        assert result["choices"][0]["message"]["content"] == "Redacted output"
        assert response["choices"][0]["message"]["content"] == "Original output"

    def test_replace_output_preserves_other_fields(self) -> None:
        response = {
            "choices": [{"message": {"role": "assistant", "content": "text"}}],
            "model": "gpt-4o",
            "usage": {"input_tokens": 10, "output_tokens": 20},
        }
        result = Guard._replace_output(response, "new text")
        assert result["model"] == "gpt-4o"
        assert result["usage"]["input_tokens"] == 10

    @pytest.mark.asyncio
    async def test_redact_action_in_chat_flow(self, guard_redact) -> None:
        mock_response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Customer SSN is 123-45-6789 in our records.",
                    }
                }
            ],
            "model": "gpt-4o",
        }

        with patch.object(guard_redact, "_call_llm", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = mock_response
            guard_redact._initialized = True
            guard_redact._reporter = AsyncMock()
            guard_redact._reporter.enqueue = lambda e: None

            response = await guard_redact.chat(
                model="gpt-4o",
                messages=[{"role": "user", "content": "Show me customer details"}],
                policies=["pii-detection"],
            )

            output = response["choices"][0]["message"]["content"]
            assert "123-45-6789" not in output
            assert "[PII_DETECTION]" in output
