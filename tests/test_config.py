"""Tests for configuration loading from env vars and explicit params."""

import os
from unittest.mock import patch

from overrule.models.config import GuardConfig, PolicyAction


class TestEnvLoading:
    def test_loads_api_key_from_env(self) -> None:
        with patch.dict(os.environ, {"OVERRULE_API_KEY": "sk-test-123"}):
            config = GuardConfig.from_env()
            assert config.api_key == "sk-test-123"

    def test_loads_endpoint_from_env(self) -> None:
        with patch.dict(os.environ, {"OVERRULE_ENDPOINT": "https://custom.api.com"}):
            config = GuardConfig.from_env()
            assert config.endpoint == "https://custom.api.com"

    def test_loads_environment_from_env(self) -> None:
        with patch.dict(os.environ, {"OVERRULE_ENVIRONMENT": "staging"}):
            config = GuardConfig.from_env()
            assert config.environment == "staging"

    def test_fail_open_from_env_true(self) -> None:
        with patch.dict(os.environ, {"OVERRULE_FAIL_OPEN": "true"}):
            config = GuardConfig.from_env()
            assert config.fail_open is True

    def test_fail_open_from_env_false(self) -> None:
        with patch.dict(os.environ, {"OVERRULE_FAIL_OPEN": "false"}):
            config = GuardConfig.from_env()
            assert config.fail_open is False

    def test_batch_size_from_env(self) -> None:
        with patch.dict(os.environ, {"OVERRULE_BATCH_SIZE": "100"}):
            config = GuardConfig.from_env()
            assert config.batch_size == 100

    def test_max_content_from_env(self) -> None:
        with patch.dict(os.environ, {"OVERRULE_MAX_CONTENT_LENGTH": "50000"}):
            config = GuardConfig.from_env()
            assert config.max_content_length == 50000


class TestOverrides:
    def test_explicit_overrides_env(self) -> None:
        with patch.dict(os.environ, {"OVERRULE_API_KEY": "from-env"}):
            config = GuardConfig.from_env(api_key="from-code")
            assert config.api_key == "from-code"

    def test_none_override_does_not_clobber_env(self) -> None:
        with patch.dict(os.environ, {"OVERRULE_API_KEY": "from-env"}):
            config = GuardConfig.from_env(api_key=None)
            assert config.api_key == "from-env"


class TestDefaults:
    def test_default_endpoint(self) -> None:
        config = GuardConfig.from_env()
        assert config.endpoint == "https://api.overrule.dev"

    def test_default_action(self) -> None:
        config = GuardConfig.from_env()
        assert config.default_action == PolicyAction.LOG

    def test_default_fail_open(self) -> None:
        config = GuardConfig.from_env()
        assert config.fail_open is True

    def test_default_batch_size(self) -> None:
        config = GuardConfig.from_env()
        assert config.batch_size == 50

    def test_default_max_content(self) -> None:
        config = GuardConfig.from_env()
        assert config.max_content_length == 100_000
