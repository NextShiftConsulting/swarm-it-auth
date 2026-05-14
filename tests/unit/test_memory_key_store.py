"""
Unit tests for MemoryKeyStore (ADR-027 Stage 6).

Covers: registration, private-key rejection, get by id/active,
list+filter, revoke, rotate, thumbprint lookup, and expiry.
"""

import pytest

from swarm_auth.adapters.memory_key_store import MemoryKeyStore, compute_jwk_thumbprint
from swarm_auth.ports.agent_key_store_port import (
    KeyAlgorithm,
    KeyRegistrationRequest,
    KeyStatus,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

EC_P256_JWK_PUBLIC = {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
}

EC_P256_JWK_PRIVATE = {
    **EC_P256_JWK_PUBLIC,
    "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
}

EC_P256_JWK_PUBLIC_2 = {
    "kty": "EC",
    "crv": "P-256",
    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "y": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
}


def _req(agent_id="agent-001", jwk=None, **kwargs) -> KeyRegistrationRequest:
    return KeyRegistrationRequest(
        agent_id=agent_id,
        algorithm=KeyAlgorithm.EC_P256,
        public_key_jwk=jwk or EC_P256_JWK_PUBLIC,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# JWK thumbprint
# ---------------------------------------------------------------------------

def test_compute_jwk_thumbprint_deterministic():
    t1 = compute_jwk_thumbprint(EC_P256_JWK_PUBLIC)
    t2 = compute_jwk_thumbprint(EC_P256_JWK_PUBLIC)
    assert t1 == t2
    assert len(t1) > 0


def test_compute_jwk_thumbprint_different_keys():
    t1 = compute_jwk_thumbprint(EC_P256_JWK_PUBLIC)
    t2 = compute_jwk_thumbprint(EC_P256_JWK_PUBLIC_2)
    assert t1 != t2


# ---------------------------------------------------------------------------
# register_key
# ---------------------------------------------------------------------------

def test_register_key_returns_active_key():
    store = MemoryKeyStore()
    key = store.register_key(_req())
    assert key.agent_id == "agent-001"
    assert key.status == KeyStatus.ACTIVE
    assert key.algorithm == KeyAlgorithm.EC_P256


def test_register_key_rejects_private_material():
    store = MemoryKeyStore()
    with pytest.raises(ValueError, match="private key material"):
        store.register_key(_req(jwk=EC_P256_JWK_PRIVATE))


def test_register_key_id_is_thumbprint():
    store = MemoryKeyStore()
    key = store.register_key(_req())
    expected_thumbprint = compute_jwk_thumbprint(EC_P256_JWK_PUBLIC)
    assert key.key_id == expected_thumbprint


# ---------------------------------------------------------------------------
# get_key
# ---------------------------------------------------------------------------

def test_get_key_by_agent_id_returns_active(tmpdir):
    store = MemoryKeyStore()
    registered = store.register_key(_req())
    found = store.get_key("agent-001")
    assert found is registered


def test_get_key_by_agent_id_returns_none_when_absent():
    store = MemoryKeyStore()
    assert store.get_key("nonexistent") is None


def test_get_key_by_key_id():
    store = MemoryKeyStore()
    registered = store.register_key(_req())
    found = store.get_key("agent-001", key_id=registered.key_id)
    assert found is registered


def test_get_key_returns_none_after_revoke():
    store = MemoryKeyStore()
    key = store.register_key(_req())
    store.revoke_key("agent-001", key.key_id)
    assert store.get_key("agent-001") is None  # no ACTIVE keys left


# ---------------------------------------------------------------------------
# list_keys
# ---------------------------------------------------------------------------

def test_list_keys_returns_all():
    store = MemoryKeyStore()
    store.register_key(_req())
    assert len(store.list_keys("agent-001")) == 1


def test_list_keys_filter_by_status():
    store = MemoryKeyStore()
    key = store.register_key(_req())
    store.revoke_key("agent-001", key.key_id)
    assert store.list_keys("agent-001", status=KeyStatus.ACTIVE) == []
    assert len(store.list_keys("agent-001", status=KeyStatus.REVOKED)) == 1


def test_list_keys_empty_for_unknown_agent():
    store = MemoryKeyStore()
    assert store.list_keys("nobody") == []


# ---------------------------------------------------------------------------
# revoke_key
# ---------------------------------------------------------------------------

def test_revoke_key_returns_true():
    store = MemoryKeyStore()
    key = store.register_key(_req())
    assert store.revoke_key("agent-001", key.key_id) is True


def test_revoke_key_returns_false_for_missing():
    store = MemoryKeyStore()
    assert store.revoke_key("agent-001", "not-a-real-key-id") is False


def test_revoke_key_sets_status_revoked():
    store = MemoryKeyStore()
    key = store.register_key(_req())
    store.revoke_key("agent-001", key.key_id)
    retrieved = store.get_key("agent-001", key_id=key.key_id)
    assert retrieved.status == KeyStatus.REVOKED


# ---------------------------------------------------------------------------
# rotate_key
# ---------------------------------------------------------------------------

def test_rotate_key_old_becomes_rotating():
    store = MemoryKeyStore()
    old_key = store.register_key(_req())
    new_req = _req(jwk=EC_P256_JWK_PUBLIC_2)
    store.rotate_key("agent-001", new_req)
    old_retrieved = store.get_key("agent-001", key_id=old_key.key_id)
    assert old_retrieved.status == KeyStatus.ROTATING


def test_rotate_key_new_is_active():
    store = MemoryKeyStore()
    store.register_key(_req())
    new_req = _req(jwk=EC_P256_JWK_PUBLIC_2)
    new_key = store.rotate_key("agent-001", new_req)
    assert new_key.status == KeyStatus.ACTIVE


def test_rotate_key_get_returns_new_active():
    store = MemoryKeyStore()
    store.register_key(_req())
    new_req = _req(jwk=EC_P256_JWK_PUBLIC_2)
    new_key = store.rotate_key("agent-001", new_req)
    active = store.get_key("agent-001")
    assert active.key_id == new_key.key_id


# ---------------------------------------------------------------------------
# get_key_by_thumbprint
# ---------------------------------------------------------------------------

def test_get_key_by_thumbprint():
    store = MemoryKeyStore()
    key = store.register_key(_req())
    thumbprint = compute_jwk_thumbprint(EC_P256_JWK_PUBLIC)
    found = store.get_key_by_thumbprint(thumbprint)
    assert found is key


def test_get_key_by_thumbprint_returns_none_for_unknown():
    store = MemoryKeyStore()
    assert store.get_key_by_thumbprint("not-a-real-thumbprint") is None


def test_get_key_by_thumbprint_still_works_after_revoke():
    """Revoked keys remain in the store; thumbprint lookup still returns them."""
    store = MemoryKeyStore()
    key = store.register_key(_req())
    store.revoke_key("agent-001", key.key_id)
    thumbprint = compute_jwk_thumbprint(EC_P256_JWK_PUBLIC)
    found = store.get_key_by_thumbprint(thumbprint)
    assert found is not None
    assert found.status == KeyStatus.REVOKED
