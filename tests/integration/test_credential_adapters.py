"""
Integration tests for credential adapters.

Tests that require external services (Vault, AWS) are skipped by default.
"""

import pytest
import os
from swarm_auth.adapters import EnvCredentialAdapter


class TestEnvCredentialAdapter:
    """Test environment variable credential storage."""

    def test_store_and_retrieve(self):
        """Test storing and retrieving credentials."""
        adapter = EnvCredentialAdapter(prefix="TEST_")

        # Store credential
        cred = adapter.store("api_key", "sk-test123", metadata={"description": "Test key"})
        assert cred.key == "api_key"

        # Retrieve credential
        value = adapter.retrieve("api_key")
        assert value == "sk-test123"

    def test_list_keys(self):
        """Test listing credential keys."""
        adapter = EnvCredentialAdapter(prefix="TEST_")

        adapter.store("key1", "value1")
        adapter.store("key2", "value2")
        adapter.store("key3", "value3")

        keys = adapter.list_keys()
        assert "key1" in keys
        assert "key2" in keys
        assert "key3" in keys

    def test_delete(self):
        """Test deleting credentials."""
        adapter = EnvCredentialAdapter(prefix="TEST_")

        adapter.store("temp_key", "temp_value")
        assert adapter.retrieve("temp_key") == "temp_value"

        deleted = adapter.delete("temp_key")
        assert deleted is True
        assert adapter.retrieve("temp_key") is None

    def test_rotate(self):
        """Test credential rotation."""
        adapter = EnvCredentialAdapter(prefix="TEST_")

        # Store initial value
        adapter.store("rotate_key", "old_value")
        assert adapter.retrieve("rotate_key") == "old_value"

        # Rotate to new value
        cred = adapter.rotate("rotate_key", "new_value")
        assert cred.version == 1  # Version incremented

        # Verify new value
        assert adapter.retrieve("rotate_key") == "new_value"


@pytest.mark.skip(reason="Requires Vault running")
class TestVaultCredentialAdapter:
    """Test HashiCorp Vault credential storage."""

    @pytest.fixture
    def vault_adapter(self):
        """Create Vault adapter (skip if unavailable)."""
        try:
            from swarm_auth.adapters import VaultCredentialAdapter

            # Requires VAULT_TOKEN env var
            adapter = VaultCredentialAdapter(
                url="http://localhost:8200",
                token=os.environ.get("VAULT_TOKEN"),
            )
            return adapter
        except Exception:
            pytest.skip("Vault not available")

    def test_store_and_retrieve_vault(self, vault_adapter):
        """Test Vault credential storage."""
        cred = vault_adapter.store("test_key", "test_value")
        value = vault_adapter.retrieve("test_key")
        assert value == "test_value"


@pytest.mark.skip(reason="Requires AWS credentials")
class TestAWSSecretsAdapter:
    """Test AWS Secrets Manager credential storage."""

    @pytest.fixture
    def aws_adapter(self):
        """Create AWS adapter (skip if unavailable)."""
        try:
            from swarm_auth.adapters import AWSSecretsAdapter

            # Requires AWS credentials configured
            adapter = AWSSecretsAdapter(region_name="us-east-1", prefix="test/")
            return adapter
        except Exception:
            pytest.skip("AWS not available")

    def test_store_and_retrieve_aws(self, aws_adapter):
        """Test AWS Secrets Manager storage."""
        cred = aws_adapter.store("test_key", "test_value")
        value = aws_adapter.retrieve("test_key")
        assert value == "test_value"
