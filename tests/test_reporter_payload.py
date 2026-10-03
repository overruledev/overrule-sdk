"""Wire-contract and privacy tests for the reporter payload (F5, F6, F11).

F5: the payload used to ship `matched_content` verbatim — a substring of the
customer's prompt or completion, and for PII the identifying half of an SSN.
F6: null-valued optionals, a falsy-zero latency, an unvalidated `direction`, a
missing `id`/`timestamp`, and unbounded policy/violation lists all made the server
reject the entire batch of up to 50 events.
"""

from __future__ import annotations

import json

import pytest

from overrule.models.event import EventStatus, EventType, InterceptEvent
from overrule.models.violation import Violation, ViolationSeverity
from overrule.transport.reporter import EventReporter

PROMPT = "Please email the report to alice.mcgregor@example.com right away"
SSN = "123-45-6789"


def _reporter(**kwargs: object) -> EventReporter:
    return EventReporter(endpoint="http://localhost:9999", **kwargs)  # type: ignore[arg-type]


def _pii_violation() -> Violation:
    return Violation(
        policy_id="pii-detection",
        severity=ViolationSeverity.CRITICAL,
        message="SSN detected in input",
        matched_content="*******6789",
        metadata={"raw_match": SSN, "pattern": "ssn", "direction": "input"},
    )


def _prompt_violation() -> Violation:
    return Violation(
        policy_id="injection-detection",
        severity=ViolationSeverity.HIGH,
        message="Prompt injection",
        matched_content=PROMPT[:100],
        blocked=True,
        metadata={"raw_match": PROMPT, "type": "prompt_injection", "direction": "input"},
    )


def _event(**kwargs: object) -> InterceptEvent:
    defaults: dict[str, object] = {
        "event_type": EventType.LLM_CALL,
        "status": EventStatus.FLAGGED,
        "input_content": PROMPT,
        "output_content": f"Sure, the SSN is {SSN}",
    }
    defaults.update(kwargs)
    return InterceptEvent(**defaults)  # type: ignore[arg-type]


class TestRawMatchDoesNotEscapeViaReprOrSerialisation:
    """S10: the wire payload was clean, but `repr()`/`model_dump_json()` were not.

    Pydantic's default repr prints every field, `metadata` included, so
    `print(response.violations)` emitted full untruncated PII while
    `matched_content` on the very same object was deliberately masked. The same
    applied to `event.model_dump_json()`, which callers reach for when logging
    events themselves.
    """

    def test_violation_repr_does_not_leak_the_match(self) -> None:
        violation = _pii_violation()
        rendered = repr(violation)
        assert SSN not in rendered
        assert "raw_match" not in rendered
        # Still identifies which violation it is.
        assert "pii-detection" in rendered
        assert "CRITICAL" in rendered

    def test_repr_of_a_violation_list_does_not_leak(self) -> None:
        """`print(response.violations)` is the reported reproduction."""
        violations = [_pii_violation(), _prompt_violation()]
        rendered = repr(violations)
        assert SSN not in rendered
        assert PROMPT not in rendered
        assert "raw_match" not in rendered

    def test_event_repr_does_not_leak_nested_matches(self) -> None:
        # Scope note: `input_content`/`output_content` are the caller's own in-memory
        # record of the call and are deliberately retained (the reporter never ships
        # them), and `matched_content` is masked by PII / clipped by injection on
        # purpose. What must not escape is the full, untruncated
        # `metadata["raw_match"]`.
        event = _event(
            input_content=None,
            output_content=None,
            violations=[_pii_violation(), _prompt_violation()],
        )
        rendered = repr(event)
        assert SSN not in rendered
        assert "raw_match" not in rendered

    def test_violation_model_dump_json_does_not_leak(self) -> None:
        rendered = _pii_violation().model_dump_json()
        assert SSN not in rendered
        assert "raw_match" not in rendered

    def test_event_model_dump_json_does_not_leak_nested_matches(self) -> None:
        event = _event(
            input_content=None,
            output_content=None,
            violations=[_pii_violation(), _prompt_violation()],
        )
        rendered = event.model_dump_json()
        assert SSN not in rendered
        assert "raw_match" not in rendered
        # The clipped `matched_content` is still there by design; the full match
        # behind it (which for a long injection is longer than 100 chars) is not.
        assert PROMPT[:100] in rendered

    def test_the_rest_of_the_metadata_still_serialises(self) -> None:
        """Only the raw match is stripped — `pattern`/`direction` remain useful."""
        dumped = _pii_violation().model_dump()
        assert dumped["metadata"]["pattern"] == "ssn"
        assert dumped["metadata"]["direction"] == "input"
        assert "raw_match" not in dumped["metadata"]

    def test_the_match_is_still_readable_in_process(self) -> None:
        """Redaction depends on it, so the attribute itself must not change."""
        violation = _pii_violation()
        assert violation.metadata["raw_match"] == SSN
        from overrule.guard import Guard

        assert Guard._apply_redaction(f"ssn {SSN}", [violation]) == "ssn [PII_DETECTION]"

    def test_masked_matched_content_is_untouched(self) -> None:
        """The masking the reviewer verified must keep working."""
        assert _pii_violation().matched_content == "*******6789"


class TestNoVerbatimContentIsSent:
    def test_prompt_text_never_appears_in_the_payload(self) -> None:
        event = _event(violations=[_prompt_violation(), _pii_violation()])
        serialized = json.dumps(_reporter().serialize(event))

        assert PROMPT not in serialized
        assert "alice.mcgregor@example.com" not in serialized
        assert SSN not in serialized
        assert "6789" not in serialized  # the identifying half of the SSN
        for word in PROMPT.split():
            if len(word) > 4:
                assert word not in serialized

    def test_input_and_output_content_are_not_serialised(self) -> None:
        payload = _reporter().serialize(_event())
        assert "input_content" not in payload
        assert "output_content" not in payload

    def test_violation_metadata_is_not_serialised(self) -> None:
        payload = _reporter().serialize(_event(violations=[_pii_violation()]))
        assert "metadata" not in payload["violations"][0]
        assert "raw_match" not in json.dumps(payload)

    def test_match_is_reported_as_length_and_hash(self) -> None:
        payload = _reporter().serialize(_event(violations=[_pii_violation()]))
        violation = payload["violations"][0]
        assert violation["match_len"] == len(SSN)
        assert len(violation["match_sha256"]) == 16
        assert violation["match_type"] == "ssn"
        assert "matched_content" not in violation

    def test_hash_is_stable_and_distinguishing(self) -> None:
        reporter = _reporter()
        first = reporter.serialize(_event(violations=[_pii_violation()]))
        second = reporter.serialize(_event(violations=[_pii_violation()]))
        assert first["violations"][0]["match_sha256"] == second["violations"][0]["match_sha256"]
        other = reporter.serialize(_event(violations=[_prompt_violation()]))
        assert other["violations"][0]["match_sha256"] != first["violations"][0]["match_sha256"]

    def test_match_type_falls_back_to_the_type_label(self) -> None:
        payload = _reporter().serialize(_event(violations=[_prompt_violation()]))
        assert payload["violations"][0]["match_type"] == "prompt_injection"


class TestOptInMaskedPreview:
    def test_preview_is_absent_by_default(self) -> None:
        payload = _reporter().serialize(_event(violations=[_pii_violation()]))
        assert "matched_content" not in payload["violations"][0]

    def test_preview_keeps_the_wire_field_name(self) -> None:
        payload = _reporter(send_match_preview=True).serialize(
            _event(violations=[_pii_violation()])
        )
        violation = payload["violations"][0]
        assert "matched_content" in violation
        assert violation["match_len"] == len(SSN)

    def test_preview_is_masked_not_verbatim(self) -> None:
        payload = _reporter(send_match_preview=True).serialize(
            _event(violations=[_pii_violation()])
        )
        preview = payload["violations"][0]["matched_content"]
        assert preview == "***-**-****"
        assert SSN not in preview
        assert "6789" not in preview

    def test_preview_of_prose_leaks_no_words(self) -> None:
        payload = _reporter(send_match_preview=True).serialize(
            _event(violations=[_prompt_violation()])
        )
        preview = payload["violations"][0]["matched_content"]
        for word in PROMPT.split():
            if len(word) > 3:
                assert word not in preview

    def test_env_var_enables_the_preview(self, monkeypatch) -> None:
        from overrule.models.config import GuardConfig

        monkeypatch.setenv("OVERRULE_SEND_MATCH_PREVIEW", "true")
        assert GuardConfig.from_env().send_match_preview is True
        monkeypatch.setenv("OVERRULE_SEND_MATCH_PREVIEW", "false")
        assert GuardConfig.from_env().send_match_preview is False

    def test_default_config_disables_the_preview(self) -> None:
        from overrule.models.config import GuardConfig

        assert GuardConfig().send_match_preview is False


class TestNullOptionalsAreOmitted:
    def test_unset_optionals_are_absent_rather_than_null(self) -> None:
        payload = _reporter().serialize(
            InterceptEvent(event_type=EventType.TOOL_CALL, status=EventStatus.PASSED)
        )
        for key in ("model", "provider", "input_tokens", "output_tokens"):
            assert key not in payload
        assert "null" not in json.dumps(payload)

    def test_set_optionals_are_present(self) -> None:
        payload = _reporter().serialize(
            _event(model="gpt-4o", provider="openai", input_tokens=12, output_tokens=8)
        )
        assert payload["model"] == "gpt-4o"
        assert payload["provider"] == "openai"
        assert payload["input_tokens"] == 12
        assert payload["output_tokens"] == 8

    def test_zero_token_counts_survive(self) -> None:
        payload = _reporter().serialize(_event(input_tokens=0, output_tokens=0))
        assert payload["input_tokens"] == 0
        assert payload["output_tokens"] == 0

    def test_zero_latency_survives(self) -> None:
        payload = _reporter().serialize(_event(latency_ms=0.0))
        assert payload["latency_ms"] == 0

    def test_unset_latency_is_omitted(self) -> None:
        payload = _reporter().serialize(_event(latency_ms=None))
        assert "latency_ms" not in payload


class TestDirectionIsClamped:
    @pytest.mark.parametrize(
        ("reported", "expected"),
        [
            ("input", "input"),
            ("output", "output"),
            ("both", "input"),
            ("", "input"),
            (None, "input"),
            (42, "input"),
        ],
    )
    def test_direction_is_always_a_valid_enum_value(self, reported, expected) -> None:
        violation = _pii_violation()
        violation.metadata["direction"] = reported
        payload = _reporter().serialize(_event(violations=[violation]))
        assert payload["violations"][0]["direction"] == expected

    def test_guard_evaluate_direction_is_typed(self) -> None:
        import inspect
        import typing

        from overrule import Guard

        hints = typing.get_type_hints(Guard.evaluate)
        assert hints["direction"] == typing.Literal["input", "output"]
        assert inspect.signature(Guard.evaluate).parameters["direction"].default == "input"


class TestIdempotencyAndTimestamps:
    def test_event_id_is_sent(self) -> None:
        event = _event()
        payload = _reporter().serialize(event)
        assert payload["id"] == event.id

    def test_timestamp_is_sent_as_iso8601(self) -> None:
        from datetime import datetime

        event = _event()
        payload = _reporter().serialize(event)
        assert payload["timestamp"] == event.timestamp.isoformat()
        assert datetime.fromisoformat(payload["timestamp"]) == event.timestamp

    def test_ids_differ_between_events(self) -> None:
        reporter = _reporter()
        assert reporter.serialize(_event())["id"] != reporter.serialize(_event())["id"]


class TestServerLimits:
    def test_policies_are_capped_at_50(self) -> None:
        payload = _reporter().serialize(
            _event(policies_applied=[f"policy-{i}" for i in range(120)])
        )
        assert len(payload["policies_applied"]) == 50

    def test_violations_are_capped_at_100(self) -> None:
        payload = _reporter().serialize(_event(violations=[_pii_violation() for _ in range(250)]))
        assert len(payload["violations"]) == 100

    def test_within_limits_is_untouched(self) -> None:
        payload = _reporter().serialize(
            _event(policies_applied=["a", "b"], violations=[_pii_violation()])
        )
        assert payload["policies_applied"] == ["a", "b"]
        assert len(payload["violations"]) == 1


class TestEnvironmentTag:
    def test_environment_is_sent_when_configured(self) -> None:
        payload = _reporter(environment="staging").serialize(_event())
        assert payload["environment"] == "staging"

    def test_environment_is_omitted_when_unset(self) -> None:
        assert "environment" not in _reporter().serialize(_event())

    def test_guard_passes_its_environment_through(self) -> None:
        from overrule import Guard
        from overrule.models.config import GuardConfig

        guard = Guard(config=GuardConfig(api_key="k", environment="staging"))
        assert guard._reporter._environment == "staging"


class TestPayloadIsJsonSerialisable:
    def test_full_payload_round_trips(self) -> None:
        payload = _reporter(environment="production").serialize(
            _event(
                model="gpt-4o",
                provider="openai",
                input_tokens=10,
                output_tokens=0,
                latency_ms=0.0,
                policies_applied=["pii-detection"],
                violations=[_pii_violation(), _prompt_violation()],
                metadata={"streaming": False},
            )
        )
        assert json.loads(json.dumps(payload)) == payload

    def test_enqueue_stores_the_serialised_payload(self) -> None:
        reporter = _reporter()
        reporter.enqueue(_event(violations=[_pii_violation()]))
        assert reporter.pending_count == 1
        assert SSN not in json.dumps(list(reporter._buffer))
