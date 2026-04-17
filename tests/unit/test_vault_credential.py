from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from swarm_auth.adapters.vault_credential import VaultCredentialAdapter
from swarm_auth.domain.credential import Credential


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_hvac_mock(authenticated: bool = True) -> MagicMock:
    """Return a mock hvac module with a pre-configured Client factory."""
    hvac_mod = MagicMock(name="hvac")
    mock_client = MagicMock()
    mock_client.is_authenticated.return_value = authenticated
    hvac_mod.Client.return_value = mock_client
    return hvac_mod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def vault(monkeypatch):
    hvac_mod = _make_hvac_mock(authenticated=True)
    monkeypatch.setitem(sys.modules, "hvac", hvac_mod)
    adapter = VaultCredentialAdapter(
        url="http://vault:8200",
        token="test-token",
        mount_point="secret",
        path_prefix="swarm-it",
    )
    yield adapter, hvac_mod.Client.return_value


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------

def test_init_raises_import_error_when_hvac_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "hvac", None)
    with pytest.raises(ImportError, match="hvac"):
        VaultCredentialAdapter()


def test_init_raises_value_error_when_not_authenticated(monkeypatch):
    hvac_mod = _make_hvac_mock(authenticated=False)
    monkeypatch.setitem(sys.modules, "hvac", hvac_mod)
    with pytest.raises(ValueError, match="authentication"):
        VaultCredentialAdapter()


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------

def test_store_writes_to_vault_and_returns_credential(vault):
    adapter, mock_client = vault
    cred = adapter.store("MY_KEY", "s3cr3t")

    mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once_with(
        path="swarm-it/MY_KEY",
        secret={"value": "s3cr3t"},
        mount_point="secret",
    )
    assert isinstance(cred, Credential)
    assert cred.key == "MY_KEY"


def test_store_includes_metadata_in_secret_payload(vault):
    adapter, mock_client = vault
    meta = {"description": "test desc", "tags": {"env": "prod"}}
    adapter.store("TAGGED_KEY", "val", metadata=meta)

    call_kwargs = mock_client.secrets.kv.v2.create_or_update_secret.call_args.kwargs
    assert call_kwargs["secret"]["metadata"] == meta


def test_store_with_metadata_sets_description_and_tags_on_credential(vault):
    adapter, _ = vault
    meta = {"description": "my desc", "tags": {"team": "auth"}}
    cred = adapter.store("K", "v", metadata=meta)

    assert cred.description == "my desc"
    assert cred.tags == {"team": "auth"}


# ---------------------------------------------------------------------------
# retrieve
# ---------------------------------------------------------------------------

def test_retrieve_returns_value_from_vault_response(vault):
    adapter, mock_client = vault
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"value": "the-secret"}}
    }
    result = adapter.retrieve("MY_KEY")

    mock_client.secrets.kv.v2.read_secret_version.assert_called_once_with(
        path="swarm-it/MY_KEY",
        mount_point="secret",
    )
    assert result == "the-secret"


def test_retrieve_returns_none_on_exception(vault):
    adapter, mock_client = vault
    mock_client.secrets.kv.v2.read_secret_version.side_effect = Exception("not found")
    assert adapter.retrieve("MISSING") is None


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

def test_delete_returns_true_on_success(vault):
    adapter, mock_client = vault
    assert adapter.delete("MY_KEY") is True
    mock_client.secrets.kv.v2.delete_metadata_and_all_versions.assert_called_once_with(
        path="swarm-it/MY_KEY",
        mount_point="secret",
    )


def test_delete_returns_false_on_exception(vault):
    adapter, mock_client = vault
    mock_client.secrets.kv.v2.delete_metadata_and_all_versions.side_effect = Exception("vault error")
    assert adapter.delete("BAD_KEY") is False


# ---------------------------------------------------------------------------
# list_keys
# ---------------------------------------------------------------------------

def test_list_keys_returns_stripped_keys(vault):
    adapter, mock_client = vault
    mock_client.secrets.kv.v2.list_secrets.return_value = {
        "data": {"keys": ["alpha/", "beta", "gamma/"]}
    }
    result = adapter.list_keys()

    mock_client.secrets.kv.v2.list_secrets.assert_called_once_with(
        path="swarm-it",
        mount_point="secret",
    )
    assert result == ["alpha", "beta", "gamma"]


def test_list_keys_with_prefix_adjusts_path(vault):
    adapter, mock_client = vault
    mock_client.secrets.kv.v2.list_secrets.return_value = {
        "data": {"keys": ["mykey"]}
    }
    adapter.list_keys(prefix="myprefix")

    mock_client.secrets.kv.v2.list_secrets.assert_called_once_with(
        path="swarm-it/myprefix",
        mount_point="secret",
    )


def test_list_keys_returns_empty_list_on_exception(vault):
    adapter, mock_client = vault
    mock_client.secrets.kv.v2.list_secrets.side_effect = Exception("forbidden")
    assert adapter.list_keys() == []


# ---------------------------------------------------------------------------
# rotate
# ---------------------------------------------------------------------------

def test_rotate_delegates_to_store(vault):
    adapter, mock_client = vault
    cred = adapter.rotate("ROTATE_KEY", "new-value")

    mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once_with(
        path="swarm-it/ROTATE_KEY",
        secret={"value": "new-value"},
        mount_point="secret",
    )
    assert isinstance(cred, Credential)
    assert cred.key == "ROTATE_KEY"


# ---------------------------------------------------------------------------
# get_metadata
# ---------------------------------------------------------------------------

def test_get_metadata_returns_dict_on_success(vault):
    adapter, mock_client = vault
    mock_client.secrets.kv.v2.read_secret_metadata.return_value = {
        "data": {
            "versions": {"1": {}, "2": {}},
            "created_time": "2024-01-01T00:00:00Z",
            "updated_time": "2024-06-01T00:00:00Z",
            "current_version": 2,
        }
    }
    result = adapter.get_metadata("META_KEY")

    mock_client.secrets.kv.v2.read_secret_metadata.assert_called_once_with(
        path="swarm-it/META_KEY",
        mount_point="secret",
    )
    assert result["key"] == "META_KEY"
    assert result["versions"] == {"1": {}, "2": {}}
    assert result["created_time"] == "2024-01-01T00:00:00Z"
    assert result["updated_time"] == "2024-06-01T00:00:00Z"
    assert result["current_version"] == 2


def test_get_metadata_returns_none_on_exception(vault):
    adapter, mock_client = vault
    mock_client.secrets.kv.v2.read_secret_metadata.side_effect = Exception("no metadata")
    assert adapter.get_metadata("GHOST_KEY") is None
