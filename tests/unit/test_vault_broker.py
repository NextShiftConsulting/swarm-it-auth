import sys
import types
import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta, timezone

from swarm_auth.domain.user import User, UserRole
from swarm_auth.ports.credential_broker_port import ToolRequest, ProviderType, ProviderCredential


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def broker_fixture():
    mock_hvac = types.ModuleType("hvac")
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = True
    mock_hvac.Client = MagicMock(return_value=mock_client)

    with patch.dict(sys.modules, {"hvac": mock_hvac}):
        from swarm_auth.adapters.vault_broker import VaultCredentialBroker
        broker = VaultCredentialBroker(
            vault_url="http://vault:8200",
            vault_token="test-token",
        )
        yield broker, mock_client


@pytest.fixture
def principal():
    return User(
        user_id="svc-agent-001",
        username="agent",
        role=UserRole.SERVICE,
        is_service_account=True,
    )


@pytest.fixture
def aws_request():
    return ToolRequest(
        tool_name="s3_upload",
        provider=ProviderType.AWS,
        action="s3:PutObject",
        resource="arn:aws:s3:::my-bucket/*",
        max_duration=900,
        request_id="req-aws-1",
    )


@pytest.fixture
def gcp_request():
    return ToolRequest(
        tool_name="storage_read",
        provider=ProviderType.GCP,
        action="storage.objects.get",
        resource="my-gcs-bucket",
        max_duration=3600,
        request_id="req-gcp-1",
    )


@pytest.fixture
def openai_request():
    return ToolRequest(
        tool_name="openai_chat",
        provider=ProviderType.OPENAI,
        action="chat.completions.create",
        resource="project-abc123",
        max_duration=3600,
        request_id="req-oai-1",
    )


@pytest.fixture
def huggingface_request():
    return ToolRequest(
        tool_name="hf_inference",
        provider=ProviderType.HUGGINGFACE,
        action="inference.run",
        resource="prod",
        max_duration=3600,
        request_id="req-hf-1",
    )


@pytest.fixture
def azure_request():
    return ToolRequest(
        tool_name="azure_blob",
        provider=ProviderType.AZURE,
        action="blob.write",
        resource="my-container",
        max_duration=900,
        request_id="req-az-1",
    )


# ---------------------------------------------------------------------------
# __init__ tests
# ---------------------------------------------------------------------------

def test_init_raises_import_error_when_hvac_missing():
    with patch.dict(sys.modules, {"hvac": None}):
        # Reload so the import inside __init__ is attempted fresh
        import importlib
        import swarm_auth.adapters.vault_broker as mod
        importlib.reload(mod)
        with pytest.raises(ImportError, match="hvac"):
            mod.VaultCredentialBroker()
        importlib.reload(mod)  # restore for other tests


def test_init_raises_value_error_when_not_authenticated():
    mock_hvac = types.ModuleType("hvac")
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = False
    mock_hvac.Client = MagicMock(return_value=mock_client)

    with patch.dict(sys.modules, {"hvac": mock_hvac}):
        from swarm_auth.adapters.vault_broker import VaultCredentialBroker
        with pytest.raises(ValueError, match="authentication failed"):
            VaultCredentialBroker(vault_url="http://vault:8200", vault_token="bad")


# ---------------------------------------------------------------------------
# vend_credential routing tests
# ---------------------------------------------------------------------------

def test_vend_credential_aws(broker_fixture, principal, aws_request):
    broker, mock_client = broker_fixture
    mock_client.secrets.aws.generate_credentials.return_value = {
        "data": {
            "access_key": "FAKE_ACCESS_KEY_ID",
            "secret_key": "fake-secret-access-key",
            "security_token": "AQoDYXdzEJr//token==",
        }
    }

    cred = broker.vend_credential(principal, aws_request)

    mock_client.secrets.aws.generate_credentials.assert_called_once()
    assert cred.provider == ProviderType.AWS
    assert cred.credential_type == "aws_sts"
    assert cred.credentials["access_key_id"] == "FAKE_ACCESS_KEY_ID"
    assert cred.credentials["secret_access_key"] == "fake-secret-access-key"
    assert cred.credentials["session_token"] == "AQoDYXdzEJr//token=="
    assert cred.issued_to == "svc-agent-001"
    assert cred.request_id == "req-aws-1"


def test_vend_credential_gcp(broker_fixture, principal, gcp_request):
    broker, mock_client = broker_fixture
    expires_iso = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    mock_client.secrets.gcp.generate_credentials.return_value = {
        "data": {
            "token": "fake-gcp-access-token",
            "token_ttl": expires_iso,
            "token_scopes": "https://www.googleapis.com/auth/devstorage.read_only",
        }
    }

    cred = broker.vend_credential(principal, gcp_request)

    mock_client.secrets.gcp.generate_credentials.assert_called_once()
    assert cred.provider == ProviderType.GCP
    assert cred.credential_type == "access_token"
    assert cred.credentials["access_token"] == "fake-gcp-access-token"
    assert cred.credentials["token_type"] == "Bearer"
    assert cred.issued_to == "svc-agent-001"
    assert cred.request_id == "req-gcp-1"


def test_vend_credential_openai(broker_fixture, principal, openai_request):
    broker, mock_client = broker_fixture
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {
            "data": {
                "api_key": "sk-test-openai-key",
                "project_id": "project-abc123",
            }
        }
    }

    cred = broker.vend_credential(principal, openai_request)

    mock_client.secrets.kv.v2.read_secret_version.assert_called_once()
    assert cred.provider == ProviderType.OPENAI
    assert cred.credential_type == "api_key"
    assert cred.credentials["api_key"] == "sk-test-openai-key"
    assert cred.credentials["project_id"] == "project-abc123"
    assert cred.issued_to == "svc-agent-001"
    assert cred.request_id == "req-oai-1"


def test_vend_credential_huggingface(broker_fixture, principal, huggingface_request):
    broker, mock_client = broker_fixture
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {
            "data": {
                "token": "hf_test_token_abc",
            }
        }
    }

    cred = broker.vend_credential(principal, huggingface_request)

    mock_client.secrets.kv.v2.read_secret_version.assert_called_once()
    assert cred.provider == ProviderType.HUGGINGFACE
    assert cred.credential_type == "token"
    assert cred.credentials["token"] == "hf_test_token_abc"
    assert cred.issued_to == "svc-agent-001"
    assert cred.request_id == "req-hf-1"


def test_vend_credential_unsupported_provider_raises(broker_fixture, principal, azure_request):
    broker, _ = broker_fixture
    with pytest.raises(ValueError, match="Unsupported provider"):
        broker.vend_credential(principal, azure_request)


# ---------------------------------------------------------------------------
# Role/roleset mapping tests
# ---------------------------------------------------------------------------

def test_map_tool_to_aws_role_known(broker_fixture):
    broker, _ = broker_fixture
    assert broker._map_tool_to_aws_role("s3_upload") == "s3-upload-role"
    assert broker._map_tool_to_aws_role("s3_read") == "s3-read-role"
    assert broker._map_tool_to_aws_role("dynamodb_read") == "dynamodb-read-role"
    assert broker._map_tool_to_aws_role("dynamodb_write") == "dynamodb-write-role"


def test_map_tool_to_aws_role_unknown_returns_default(broker_fixture):
    broker, _ = broker_fixture
    assert broker._map_tool_to_aws_role("unknown_tool") == "default-role"


def test_map_tool_to_gcp_roleset_known(broker_fixture):
    broker, _ = broker_fixture
    assert broker._map_tool_to_gcp_roleset("storage_read") == "storage-reader"
    assert broker._map_tool_to_gcp_roleset("storage_write") == "storage-writer"
    assert broker._map_tool_to_gcp_roleset("bigquery_read") == "bigquery-reader"


def test_map_tool_to_gcp_roleset_unknown_returns_default(broker_fixture):
    broker, _ = broker_fixture
    assert broker._map_tool_to_gcp_roleset("unknown_tool") == "default-roleset"


# ---------------------------------------------------------------------------
# revoke / list / validate / refresh tests
# ---------------------------------------------------------------------------

def test_revoke_credential_returns_true(broker_fixture):
    broker, _ = broker_fixture
    assert broker.revoke_credential("any-credential-id") is True


def test_list_active_credentials_returns_empty_list(broker_fixture, principal):
    broker, _ = broker_fixture
    result = broker.list_active_credentials(principal)
    assert result == []


def test_validate_credential_not_expired_returns_true(broker_fixture):
    broker, _ = broker_fixture
    cred = ProviderCredential(
        provider=ProviderType.AWS,
        credential_type="aws_sts",
        credentials={"access_key_id": "AK", "secret_access_key": "SK", "session_token": "ST"},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        scope="s3:PutObject",
        issued_to="svc-agent-001",
    )
    assert broker.validate_credential(cred) is True


def test_validate_credential_expired_returns_false(broker_fixture):
    broker, _ = broker_fixture
    cred = ProviderCredential(
        provider=ProviderType.AWS,
        credential_type="aws_sts",
        credentials={"access_key_id": "AK", "secret_access_key": "SK", "session_token": "ST"},
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        scope="s3:PutObject",
        issued_to="svc-agent-001",
    )
    assert broker.validate_credential(cred) is False


def test_refresh_credential_raises_not_implemented(broker_fixture):
    broker, _ = broker_fixture
    cred = ProviderCredential(
        provider=ProviderType.AWS,
        credential_type="aws_sts",
        credentials={"access_key_id": "AK", "secret_access_key": "SK", "session_token": "ST"},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        scope="s3:PutObject",
        issued_to="svc-agent-001",
    )
    with pytest.raises(NotImplementedError):
        broker.refresh_credential(cred)
