"""
Tests for AccessScript credential triage.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from swarm_auth.access_script import (
    AccessScript,
    AccessScriptConfig,
    SourceType,
    OnForbidden,
    get_credential,
    get_aws_credentials,
)


class TestAccessScriptConfig:
    """Test AccessScriptConfig."""

    def test_default_config(self):
        """Test default configuration."""
        config = AccessScriptConfig()
        assert SourceType.ENV_VAR in config.priority
        assert SourceType.DOTENV in config.priority
        assert len(config.forbidden) == 0
        assert config.jit_mode is True
        assert config.cache_ttl == 300

    def test_env_overrides(self):
        """Test environment-specific overrides."""
        config = AccessScriptConfig(
            environment="prod",
            env_overrides={
                "prod": {
                    "priority": ["aws_secrets"],
                    "forbidden": ["env_var", "dotenv"],
                }
            }
        )
        access = AccessScript(config)

        assert access._config.priority == [SourceType.AWS_SECRETS]
        assert SourceType.ENV_VAR in access._config.forbidden
        assert SourceType.DOTENV in access._config.forbidden


class TestAccessScript:
    """Test AccessScript."""

    def test_from_config(self):
        """Test creating from config dict."""
        access = AccessScript.from_config({
            "priority": ["env_var", "dotenv"],
            "forbidden": ["kms"],
            "cache_ttl": 60,
        })

        assert access._config.priority == [SourceType.ENV_VAR, SourceType.DOTENV]
        assert access._config.forbidden == [SourceType.KMS]
        assert access._config.cache_ttl == 60

    def test_get_from_env_var(self):
        """Test getting credential from environment variable."""
        with patch.dict(os.environ, {"TEST_API_KEY": "test-value"}):
            access = AccessScript.from_config({
                "priority": ["env_var"],
            })
            value = access.get("TEST_API_KEY")
            assert value == "test-value"

    def test_forbidden_source_skipped(self):
        """Test that forbidden sources are skipped."""
        access = AccessScript.from_config({
            "priority": ["env_var", "dotenv"],
            "forbidden": ["env_var"],
            "on_forbidden": "silent",
        })

        with patch.dict(os.environ, {"TEST_KEY": "from-env"}):
            # Even though env var is set, it should be skipped
            # and return None (dotenv won't have it)
            value = access.get("TEST_KEY")
            # Value should be None because env_var is forbidden
            # and dotenv doesn't have this key
            # Actually it might find it if dotenv is available...
            # Let's check the audit log instead
            log = access.get_audit_log()
            # env_var should NOT be in the log (forbidden)
            sources_tried = [e.source for e in log]
            assert SourceType.ENV_VAR not in sources_tried

    def test_forbidden_source_error(self):
        """Test that forbidden source raises error when configured."""
        access = AccessScript.from_config({
            "priority": ["kms"],
            "forbidden": ["kms"],
            "on_forbidden": "error",
        })

        with pytest.raises(PermissionError):
            access.get("TEST_KEY")

    def test_cache(self):
        """Test credential caching."""
        access = AccessScript.from_config({
            "priority": ["env_var"],
            "cache_ttl": 300,
        })

        with patch.dict(os.environ, {"CACHED_KEY": "cached-value"}):
            # First call
            value1 = access.get("CACHED_KEY")
            assert value1 == "cached-value"

            # Modify env (but cache should still return old value)
            os.environ["CACHED_KEY"] = "new-value"
            value2 = access.get("CACHED_KEY")
            assert value2 == "cached-value"  # Still cached

            # Clear cache
            access.clear_cache()
            value3 = access.get("CACHED_KEY")
            assert value3 == "new-value"  # Now gets new value

    def test_audit_log(self):
        """Test audit logging."""
        access = AccessScript.from_config({
            "priority": ["env_var"],
            "audit_enabled": True,
        })

        with patch.dict(os.environ, {"AUDIT_KEY": "audit-value"}):
            access.get("AUDIT_KEY")

        log = access.get_audit_log()
        assert len(log) == 1
        assert log[0].key == "AUDIT_KEY"
        assert log[0].success is True
        assert log[0].source == SourceType.ENV_VAR

    def test_has_credential(self):
        """Test has() method."""
        access = AccessScript.from_config({
            "priority": ["env_var"],
        })

        with patch.dict(os.environ, {"EXISTS_KEY": "value"}):
            assert access.has("EXISTS_KEY") is True
            assert access.has("NOT_EXISTS_KEY") is False


class TestConvenienceFunction:
    """Test module-level convenience function."""

    def test_get_credential(self):
        """Test get_credential convenience function."""
        with patch.dict(os.environ, {"CONVENIENCE_KEY": "convenience-value"}):
            value = get_credential("CONVENIENCE_KEY")
            assert value == "convenience-value"

    def test_get_credential_default(self):
        """Test get_credential with default."""
        value = get_credential("NONEXISTENT_KEY", default="default-value")
        assert value == "default-value"


class TestGetAwsCredentials:
    """get_aws_credentials must include the session token for TEMPORARY creds
    (Lambda/STS/assumed role). Omitting it yields incomplete creds -> auth failure.
    Regression guard for the session-token bug fixed 2026-07-18."""

    def test_no_creds_returns_empty(self):
        with patch.dict(os.environ, {}, clear=True):
            assert get_aws_credentials() == {}

    def test_permanent_keys_have_no_session_token(self):
        env = {"AWS_ACCESS_KEY_ID": "AKIAPERM", "AWS_SECRET_ACCESS_KEY": "sk"}
        with patch.dict(os.environ, env, clear=True):
            creds = get_aws_credentials()
            assert creds["aws_access_key_id"] == "AKIAPERM"
            assert creds["aws_secret_access_key"] == "sk"
            assert "aws_session_token" not in creds

    def test_temporary_creds_include_session_token(self):
        env = {
            "AWS_ACCESS_KEY_ID": "ASIATEMP",
            "AWS_SECRET_ACCESS_KEY": "sk",
            "AWS_SESSION_TOKEN": "FwoGZXIvYXdzTEMP",
        }
        with patch.dict(os.environ, env, clear=True):
            creds = get_aws_credentials()
            assert creds["aws_session_token"] == "FwoGZXIvYXdzTEMP"
            # complete, boto3-ready temp creds
            assert set(creds) == {"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}
