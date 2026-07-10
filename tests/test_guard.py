"""Tests for the Guard core class."""

import pytest

from overrule import Guard, SyncGuard, ViolationError
from overrule.models.config import PolicyAction


@pytest.fixture
def guard() -> Guard:
    return Guard(api_key="test-key", default_action=PolicyAction.BLOCK)


@pytest.fixture
def guard_log_only() -> Guard:
    return Guard(api_key="test-key", default_action=PolicyAction.LOG)


@pytest.fixture
def guard_fail_open() -> Guard:
    return Guard(api_key="test-key", default_action=PolicyAction.BLOCK, fail_open=True)


class TestProtectDecorator:
    def test_blocks_pii_in_tool_call(self, guard: Guard) -> None:
        @guard.protect(policies=["pii-detection"], action=PolicyAction.BLOCK)
        def send_email(body: str) -> str:
            return f"sent: {body}"

        with pytest.raises(ViolationError) as exc_info:
            send_email("Send to SSN 123-45-6789")

        assert len(exc_info.value.violations) > 0

    def test_blocks_sql_injection_in_tool_call(self, guard: Guard) -> None:
        @guard.protect(policies=["injection-detection"], action=PolicyAction.BLOCK)
        def query_db(sql: str) -> str:
            return f"result: {sql}"

        with pytest.raises(ViolationError):
            query_db("'; DROP TABLE users; --")

    def test_allows_clean_tool_call(self, guard: Guard) -> None:
        @guard.protect(policies=["pii-detection", "injection-detection"], action=PolicyAction.BLOCK)
        def greet(name: str) -> str:
            return f"Hello, {name}!"

        result = greet("World")
        assert result == "Hello, World!"

    def test_log_mode_does_not_block(self, guard_log_only: Guard) -> None:
        @guard_log_only.protect(policies=["pii-detection"])
        def process(data: str) -> str:
            return data

        result = process("SSN: 123-45-6789")
        assert "123-45-6789" in result


class TestSyncGuard:
    def test_sync_protect_blocks_pii(self) -> None:
        with SyncGuard(api_key="test-key", default_action=PolicyAction.BLOCK) as guard:

            @guard.protect(policies=["pii-detection"], action=PolicyAction.BLOCK)
            def send(body: str) -> str:
                return body

            with pytest.raises(ViolationError):
                send("SSN: 123-45-6789")

    def test_sync_protect_allows_clean(self) -> None:
        with SyncGuard(api_key="test-key", default_action=PolicyAction.BLOCK) as guard:

            @guard.protect(policies=["pii-detection"], action=PolicyAction.BLOCK)
            def greet(name: str) -> str:
                return f"Hello, {name}!"

            assert greet("World") == "Hello, World!"

    def test_sync_evaluate(self) -> None:
        with SyncGuard(api_key="test-key") as guard:
            result = guard.evaluate("My SSN is 123-45-6789", policies=["pii-detection"])
            assert not result.passed
            assert len(result.violations) > 0

    def test_sync_evaluate_clean(self) -> None:
        with SyncGuard(api_key="test-key") as guard:
            result = guard.evaluate("Hello world", policies=["pii-detection"])
            assert result.passed


class TestPolicyRegistry:
    def test_resolve_unknown_policy_raises(self, guard: Guard) -> None:
        with pytest.raises(ValueError, match="Unknown policy"):
            guard._registry.get("nonexistent-policy")

    def test_lists_available_policies(self, guard: Guard) -> None:
        available = guard._registry.available
        assert "pii-detection" in available
        assert "injection-detection" in available


class TestContentTruncation:
    def test_truncates_long_content(self, guard: Guard) -> None:
        long_content = "A" * 200_000
        truncated = guard._truncate(long_content)
        assert len(truncated) == 100_000

    def test_preserves_short_content(self, guard: Guard) -> None:
        short = "Hello world"
        assert guard._truncate(short) == short


class TestInputValidation:
    @pytest.mark.asyncio
    async def test_empty_messages_raises(self, guard: Guard) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            await guard.chat(model="gpt-4", messages=[])


class TestExtractMethods:
    def test_extract_input_handles_malformed(self) -> None:
        messages = [
            {"role": "user", "content": "hello"},
            {"role": "system"},  # missing content
            {"content": 123},  # non-string content
        ]
        result = Guard._extract_input(messages)
        assert "hello" in result

    def test_extract_output_handles_empty(self) -> None:
        assert Guard._extract_output({}) == ""
        assert Guard._extract_output({"choices": []}) == ""
        assert Guard._extract_output({"choices": [{}]}) == ""

    def test_extract_output_normal(self) -> None:
        response = {"choices": [{"message": {"content": "Hi there"}}]}
        assert Guard._extract_output(response) == "Hi there"
