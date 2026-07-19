"""Tests for KMSAdapter."""

from __future__ import annotations

import base64
import json
import sys
from unittest.mock import MagicMock, patch

import pytest

from swarm_auth.adapters.kms_credential import KMSAdapter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_KEY_ID = "arn:aws:kms:us-east-1:123456789012:key/fake-key-id"
_FAKE_REGION = "us-east-1"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def kms_env(monkeypatch):
    """Set the minimum env vars required to construct a KMSAdapter."""
    monkeypatch.setenv("KMS_KEY_ID", _FAKE_KEY_ID)
    monkeypatch.delenv("KMS_KEY_ALIAS", raising=False)
    monkeypatch.delenv("KMS_ENCRYPTED_CREDENTIALS", raising=False)


@pytest.fixture()
def mock_boto3_module():
    """
    Inject a mock boto3 into sys.modules so that `import boto3` inside
    KMSAdapter methods picks up our mock instead of the real package.
    Returns the mock module.
    """
    mock_b3 = MagicMock()
    with patch.dict(sys.modules, {"boto3": mock_b3}):
        yield mock_b3


@pytest.fixture()
def adapter_and_client(kms_env, mock_boto3_module):
    """Return (adapter, mock_kms_client) with boto3 fully stubbed."""
    mock_client = MagicMock()
    mock_boto3_module.client.return_value = mock_client

    def _encrypt(KeyId, Plaintext, **_kw):
        return {"CiphertextBlob": Plaintext[::-1]}

    def _decrypt(CiphertextBlob, KeyId=None, **_kw):
        return {"Plaintext": CiphertextBlob[::-1]}

    mock_client.encrypt.side_effect = _encrypt
    mock_client.decrypt.side_effect = _decrypt

    adapter = KMSAdapter(key_id=_FAKE_KEY_ID, region_name=_FAKE_REGION)
    # Force the lazy client to our mock immediately.
    adapter._client = mock_client

    return adapter, mock_client


# ---------------------------------------------------------------------------
# __init__ — import guard
# ---------------------------------------------------------------------------

def test_init_raises_when_boto3_missing(monkeypatch, kms_env):
    """KMSAdapter.__init__ must raise ImportError when boto3 is absent."""
    with patch.dict(sys.modules, {"boto3": None}):
        with pytest.raises(ImportError, match="boto3"):
            KMSAdapter(key_id=_FAKE_KEY_ID)


def test_init_reads_key_from_env(kms_env, mock_boto3_module):
    adapter = KMSAdapter()
    assert adapter._key_id == _FAKE_KEY_ID


def test_init_reads_key_alias_when_key_id_missing(monkeypatch, mock_boto3_module):
    monkeypatch.delenv("KMS_KEY_ID", raising=False)
    monkeypatch.setenv("KMS_KEY_ALIAS", "alias/my-alias")
    adapter = KMSAdapter()
    assert adapter._key_id == "alias/my-alias"


def test_init_explicit_key_id_takes_precedence(kms_env, mock_boto3_module):
    adapter = KMSAdapter(key_id="explicit-key")
    assert adapter._key_id == "explicit-key"


# ---------------------------------------------------------------------------
# store — encrypts, caches, returns Credential with encrypted_blob tag
# ---------------------------------------------------------------------------

def test_store_returns_credential_with_encrypted_blob_tag(adapter_and_client):
    adapter, mock_client = adapter_and_client
    cred = adapter.store("MY_SECRET", "supersecret")

    assert cred.key == "MY_SECRET"
    assert "encrypted_blob" in cred.tags
    # Tag must be a valid base64 string that decodes to something non-empty.
    decoded = base64.b64decode(cred.tags["encrypted_blob"])
    assert len(decoded) > 0


def test_store_caches_plaintext_value(adapter_and_client):
    adapter, _client = adapter_and_client
    adapter.store("CACHED_KEY", "cached_value")
    assert adapter._cache["CACHED_KEY"] == "cached_value"


def test_store_calls_kms_encrypt(adapter_and_client):
    adapter, mock_client = adapter_and_client
    adapter.store("K", "V")
    mock_client.encrypt.assert_called_once_with(
        KeyId=_FAKE_KEY_ID,
        Plaintext=b"V",
    )


# ---------------------------------------------------------------------------
# retrieve — returns from cache after _load_encrypted_credentials
# ---------------------------------------------------------------------------

def test_retrieve_returns_cached_value(adapter_and_client):
    adapter, _client = adapter_and_client
    adapter.store("API_KEY", "token123")
    result = adapter.retrieve("API_KEY")
    assert result == "token123"


def test_retrieve_returns_none_for_missing_key(adapter_and_client):
    adapter, _client = adapter_and_client
    assert adapter.retrieve("DOES_NOT_EXIST") is None


def test_retrieve_loads_encrypted_credentials_from_env(
    kms_env, mock_boto3_module, monkeypatch
):
    mock_client = MagicMock()
    mock_boto3_module.client.return_value = mock_client

    plaintext = "env_secret_value"
    blob = plaintext.encode("utf-8")[::-1]
    encoded = base64.b64encode(blob).decode("utf-8")
    env_payload = json.dumps({"ENV_KEY": encoded})
    monkeypatch.setenv("KMS_ENCRYPTED_CREDENTIALS", env_payload)

    mock_client.decrypt.return_value = {"Plaintext": blob[::-1]}

    adapter = KMSAdapter(key_id=_FAKE_KEY_ID)
    adapter._client = mock_client

    result = adapter.retrieve("ENV_KEY")
    assert result == plaintext


# ---------------------------------------------------------------------------
# delete — removes from cache
# ---------------------------------------------------------------------------

def test_delete_existing_key_returns_true(adapter_and_client):
    adapter, _client = adapter_and_client
    adapter.store("DEL_KEY", "value")
    assert adapter.delete("DEL_KEY") is True
    assert "DEL_KEY" not in adapter._cache


def test_delete_missing_key_returns_false(adapter_and_client):
    adapter, _client = adapter_and_client
    assert adapter.delete("GHOST") is False


# ---------------------------------------------------------------------------
# list_keys — returns keys with optional prefix filter
# ---------------------------------------------------------------------------

def test_list_keys_returns_all_cached_keys(adapter_and_client):
    adapter, _client = adapter_and_client
    adapter.store("FOO_A", "1")
    adapter.store("FOO_B", "2")
    adapter.store("BAR_C", "3")

    keys = adapter.list_keys()
    assert set(keys) == {"FOO_A", "FOO_B", "BAR_C"}


def test_list_keys_with_prefix_filters(adapter_and_client):
    adapter, _client = adapter_and_client
    adapter.store("FOO_A", "1")
    adapter.store("FOO_B", "2")
    adapter.store("BAR_C", "3")

    keys = adapter.list_keys(prefix="FOO")
    assert set(keys) == {"FOO_A", "FOO_B"}
    assert "BAR_C" not in keys


def test_list_keys_empty_when_no_matches(adapter_and_client):
    adapter, _client = adapter_and_client
    adapter.store("FOO_A", "1")
    assert adapter.list_keys(prefix="ZZZ") == []


# ---------------------------------------------------------------------------
# rotate — delegates to store
# ---------------------------------------------------------------------------

def test_rotate_updates_cached_value(adapter_and_client):
    adapter, _client = adapter_and_client
    adapter.store("ROT_KEY", "old_value")
    cred = adapter.rotate("ROT_KEY", "new_value")

    assert cred.key == "ROT_KEY"
    assert adapter._cache["ROT_KEY"] == "new_value"


def test_rotate_calls_encrypt_with_new_value(adapter_and_client):
    adapter, mock_client = adapter_and_client
    mock_client.encrypt.reset_mock()
    adapter.rotate("ROT_KEY", "new_value")

    mock_client.encrypt.assert_called_once_with(
        KeyId=_FAKE_KEY_ID,
        Plaintext=b"new_value",
    )


# ---------------------------------------------------------------------------
# get_metadata — returns source/key_id/region dict
# ---------------------------------------------------------------------------

def test_get_metadata_returns_dict_for_existing_key(adapter_and_client):
    adapter, _client = adapter_and_client
    adapter.store("META_KEY", "value")
    meta = adapter.get_metadata("META_KEY")

    assert meta is not None
    assert meta["source"] == "kms"
    assert meta["key_id"] == _FAKE_KEY_ID
    assert meta["region"] == _FAKE_REGION
    assert meta["key"] == "META_KEY"
    assert "value" not in meta


def test_get_metadata_returns_none_for_missing_key(adapter_and_client):
    adapter, _client = adapter_and_client
    assert adapter.get_metadata("NO_SUCH") is None


# ---------------------------------------------------------------------------
# _load_encrypted_credentials — single-blob format (non-JSON base64 env var)
# ---------------------------------------------------------------------------

def test_load_encrypted_credentials_single_blob_format(
    kms_env, mock_boto3_module, monkeypatch
):
    mock_client = MagicMock()
    mock_boto3_module.client.return_value = mock_client

    inner = {"SINGLE_A": "alpha", "SINGLE_B": "beta"}
    inner_json = json.dumps(inner)
    # The outer env var is valid base64 but NOT valid JSON →
    # triggers the single-blob fallback path.
    blob = inner_json.encode("utf-8")[::-1]
    env_value = base64.b64encode(blob).decode("utf-8")
    monkeypatch.setenv("KMS_ENCRYPTED_CREDENTIALS", env_value)

    # KMS decrypts the blob back to the inner JSON bytes.
    mock_client.decrypt.return_value = {"Plaintext": blob[::-1]}

    adapter = KMSAdapter(key_id=_FAKE_KEY_ID)
    adapter._client = mock_client
    adapter._load_encrypted_credentials()

    assert adapter._cache.get("SINGLE_A") == "alpha"
    assert adapter._cache.get("SINGLE_B") == "beta"


# ---------------------------------------------------------------------------
# _load_encrypted_credentials — skips keys whose decryption fails
# ---------------------------------------------------------------------------

def test_load_encrypted_credentials_skips_failed_keys(
    kms_env, mock_boto3_module, monkeypatch
):
    mock_client = MagicMock()
    mock_boto3_module.client.return_value = mock_client

    good_blob = base64.b64encode(b"good_value"[::-1]).decode("utf-8")
    bad_blob = base64.b64encode(b"bad_value"[::-1]).decode("utf-8")
    env_payload = json.dumps({"GOOD_KEY": good_blob, "BAD_KEY": bad_blob})
    monkeypatch.setenv("KMS_ENCRYPTED_CREDENTIALS", env_payload)

    def _decrypt(CiphertextBlob, KeyId=None, **_kw):
        if CiphertextBlob == b"good_value"[::-1]:
            return {"Plaintext": b"good_value"}
        raise Exception("KMS decryption failed")

    mock_client.decrypt.side_effect = _decrypt

    adapter = KMSAdapter(key_id=_FAKE_KEY_ID)
    adapter._client = mock_client
    adapter._load_encrypted_credentials()

    assert adapter._cache.get("GOOD_KEY") == "good_value"
    assert "BAD_KEY" not in adapter._cache


# ---------------------------------------------------------------------------
# _load_encrypted_credentials — _loaded flag prevents double execution
# ---------------------------------------------------------------------------

def test_load_encrypted_credentials_runs_only_once(
    kms_env, mock_boto3_module, monkeypatch
):
    mock_client = MagicMock()
    mock_boto3_module.client.return_value = mock_client
    monkeypatch.setenv("KMS_ENCRYPTED_CREDENTIALS", json.dumps({}))

    adapter = KMSAdapter(key_id=_FAKE_KEY_ID)
    adapter._client = mock_client

    adapter._load_encrypted_credentials()
    adapter._load_encrypted_credentials()

    mock_client.decrypt.assert_not_called()
    assert adapter._loaded is True


# ---------------------------------------------------------------------------
# is_available — classmethod
# ---------------------------------------------------------------------------

def test_is_available_returns_false_when_no_key_env_vars(monkeypatch):
    monkeypatch.delenv("KMS_KEY_ID", raising=False)
    monkeypatch.delenv("KMS_KEY_ALIAS", raising=False)
    assert KMSAdapter.is_available() is False


def test_is_available_returns_false_when_boto3_missing(monkeypatch):
    monkeypatch.setenv("KMS_KEY_ID", _FAKE_KEY_ID)
    with patch.dict(sys.modules, {"boto3": None}):
        assert KMSAdapter.is_available() is False


def test_is_available_independent_of_sts(monkeypatch):
    """CORRECTED CONTRACT (was test_is_available_returns_false_when_sts_fails):
    is_available() no longer depends on STS. In the toughest lockdown STS is
    denied/blocked but kms:Decrypt works, so availability must NOT hinge on STS.
    A configured key + importable boto3 => available, regardless of STS."""
    monkeypatch.setenv("KMS_KEY_ID", _FAKE_KEY_ID)
    mock_b3 = MagicMock()
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = Exception("STS denied by policy")
    mock_b3.client.return_value = mock_sts
    with patch.dict(sys.modules, {"boto3": mock_b3}):
        assert KMSAdapter.is_available() is True
        mock_b3.client.assert_not_called()   # no client built, no STS call


def test_is_available_true_when_key_configured(monkeypatch):
    """Configured key + importable boto3 => available (no AWS call of any kind)."""
    monkeypatch.setenv("KMS_KEY_ID", _FAKE_KEY_ID)
    mock_b3 = MagicMock()
    with patch.dict(sys.modules, {"boto3": mock_b3}):
        assert KMSAdapter.is_available() is True
        mock_b3.client.assert_not_called()


# ---------------------------------------------------------------------------
# is_available — toughest-security: NO AWS query (regression guard)
# ---------------------------------------------------------------------------

def test_is_available_true_when_key_configured_no_aws_query(kms_env, mock_boto3_module):
    """KMS is available when a key is configured + boto3 imports — WITHOUT any
    AWS call. Guards the toughest-security fix (was calling sts.get_caller_identity,
    which is blocked/denied in a kms:Decrypt-only lockdown)."""
    assert KMSAdapter.is_available() is True
    # The load-bearing assertion: is_available made NO boto3 client / STS call.
    mock_boto3_module.client.assert_not_called()


def test_is_available_false_when_no_key(monkeypatch, mock_boto3_module):
    monkeypatch.delenv("KMS_KEY_ID", raising=False)
    monkeypatch.delenv("KMS_KEY_ALIAS", raising=False)
    assert KMSAdapter.is_available() is False


def test_is_available_true_even_when_sts_would_fail(kms_env, mock_boto3_module):
    """Explicit toughest-security case: even if STS is entirely broken/denied,
    KMS availability is unaffected (it never calls STS)."""
    mock_boto3_module.client.side_effect = Exception("STS blocked by corporate policy")
    assert KMSAdapter.is_available() is True   # STS irrelevant; no call made
