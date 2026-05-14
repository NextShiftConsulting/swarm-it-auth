"""
Unit tests for StrictDPoPValidator (ADR-027 Stage 6).

Tests cover all RFC 9449 §4.2 validation steps:
  - Happy path (all checks pass, with and without signature)
  - typ mismatch
  - Disallowed algorithm (HS256, "none")
  - JTI replay prevention
  - IAT clock skew (too old, too new)
  - HTM mismatch
  - HTU mismatch (including query-string stripping)
  - Nonce mismatch
  - ATH mismatch
  - Key not found
  - Key revoked
  - Signature verification (with real EC P-256 key pair)
"""

import base64
import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta, timezone

import pytest

from swarm_auth.adapters.memory_key_store import MemoryKeyStore, compute_jwk_thumbprint
from swarm_auth.adapters.strict_dpop_validator import StrictDPoPValidator
from swarm_auth.ports.agent_key_store_port import KeyAlgorithm, KeyRegistrationRequest, KeyStatus
from swarm_auth.ports.dpop_validator_port import DPoPErrorCode, DPoPProof


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

EC_P256_JWK_PUBLIC = {
    "kty": "EC",
    "crv": "P-256",
    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
}


@pytest.fixture
def store():
    return MemoryKeyStore()


@pytest.fixture
def registered_key(store):
    return store.register_key(KeyRegistrationRequest(
        agent_id="agent-001",
        algorithm=KeyAlgorithm.EC_P256,
        public_key_jwk=EC_P256_JWK_PUBLIC,
    ))


@pytest.fixture
def validator(store):
    return StrictDPoPValidator(key_lookup=store.get_key_by_thumbprint)


def _proof(
    typ="dpop+jwt",
    alg="ES256",
    jwk=None,
    jti=None,
    htm="POST",
    htu="https://auth.swarms.network/token",
    iat=None,
    nonce=None,
    ath=None,
    raw_jwt=None,
):
    return DPoPProof(
        typ=typ,
        alg=alg,
        jwk=jwk or EC_P256_JWK_PUBLIC,
        jti=jti or secrets.token_hex(16),
        htm=htm,
        htu=htu,
        iat=iat or datetime.now(timezone.utc),
        nonce=nonce,
        ath=ath,
        raw_jwt=raw_jwt,
    )


# ---------------------------------------------------------------------------
# Happy path (key registered, no raw_jwt — skips sig verification)
# ---------------------------------------------------------------------------

def test_validate_proof_allows_valid_proof(validator, registered_key):
    proof = _proof()
    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is True
    assert result.agent_id == "agent-001"
    assert result.key_id == registered_key.key_id


# ---------------------------------------------------------------------------
# typ check (RFC 9449 §4.1)
# ---------------------------------------------------------------------------

def test_validate_wrong_typ_denied(validator, registered_key):
    proof = _proof(typ="JWT")
    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.INVALID_DPOP_PROOF


# ---------------------------------------------------------------------------
# Algorithm check (RFC 9449 §4.1 — no symmetric / no "none")
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_alg", ["HS256", "HS512", "none"])
def test_validate_symmetric_alg_denied(validator, registered_key, bad_alg):
    proof = _proof(alg=bad_alg)
    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.ALGORITHM_REJECTED


# ---------------------------------------------------------------------------
# Replay prevention (RFC 9449 §11.1)
# ---------------------------------------------------------------------------

def test_replay_detected_on_second_use(validator, registered_key):
    proof = _proof()
    r1 = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert r1.valid is True
    r2 = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert r2.valid is False
    assert r2.error_code == DPoPErrorCode.REPLAY_DETECTED


def test_different_jti_not_replay(validator, registered_key):
    r1 = validator.validate_proof(_proof(), "POST", "https://auth.swarms.network/token")
    r2 = validator.validate_proof(_proof(), "POST", "https://auth.swarms.network/token")
    assert r1.valid is True
    assert r2.valid is True


# ---------------------------------------------------------------------------
# IAT clock skew (RFC 9449 §4.2)
# ---------------------------------------------------------------------------

def test_iat_too_old_denied(validator, registered_key):
    old_iat = datetime.now(timezone.utc) - timedelta(seconds=120)
    proof = _proof(iat=old_iat)
    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.CLOCK_SKEW


def test_iat_too_far_future_denied(validator, registered_key):
    future_iat = datetime.now(timezone.utc) + timedelta(seconds=120)
    proof = _proof(iat=future_iat)
    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.CLOCK_SKEW


# ---------------------------------------------------------------------------
# HTM check (RFC 9449 §4.2)
# ---------------------------------------------------------------------------

def test_htm_mismatch_denied(validator, registered_key):
    proof = _proof(htm="GET")
    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.HTM_MISMATCH


def test_htm_case_insensitive(validator, registered_key):
    proof = _proof(htm="post")
    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is True


# ---------------------------------------------------------------------------
# HTU check (RFC 9449 §4.2)
# ---------------------------------------------------------------------------

def test_htu_mismatch_denied(validator, registered_key):
    proof = _proof(htu="https://other.example.com/token")
    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.HTU_MISMATCH


def test_htu_query_string_stripped(validator, registered_key):
    """RFC 9449 §4.2: query string and fragment are ignored in htu comparison."""
    proof = _proof(htu="https://auth.swarms.network/token?foo=bar#frag")
    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is True


# ---------------------------------------------------------------------------
# Nonce check (RFC 9449 §8)
# ---------------------------------------------------------------------------

def test_nonce_mismatch_denied(validator, registered_key):
    proof = _proof(nonce="wrong-nonce")
    result = validator.validate_proof(
        proof, "POST", "https://auth.swarms.network/token",
        expected_nonce="correct-nonce",
    )
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.NONCE_MISMATCH


def test_nonce_correct_allowed(validator, registered_key):
    proof = _proof(nonce="server-nonce-xyz")
    result = validator.validate_proof(
        proof, "POST", "https://auth.swarms.network/token",
        expected_nonce="server-nonce-xyz",
    )
    assert result.valid is True


def test_issue_nonce_returns_string(validator):
    nonce = validator.issue_nonce("agent-001")
    assert isinstance(nonce, str)
    assert len(nonce) > 10


# ---------------------------------------------------------------------------
# ATH check (RFC 9449 §5)
# ---------------------------------------------------------------------------

def test_ath_mismatch_denied(validator, registered_key):
    proof = _proof(ath="wrong-ath-value")
    result = validator.validate_proof(
        proof, "POST", "https://auth.swarms.network/token",
        access_token_hash="correct-ath-value",
    )
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.ATH_MISMATCH


def test_ath_correct_allowed(validator, registered_key):
    ath = base64.urlsafe_b64encode(hashlib.sha256(b"my-access-token").digest()).rstrip(b"=").decode()
    proof = _proof(ath=ath)
    result = validator.validate_proof(
        proof, "POST", "https://auth.swarms.network/token",
        access_token_hash=ath,
    )
    assert result.valid is True


# ---------------------------------------------------------------------------
# Key not found / revoked
# ---------------------------------------------------------------------------

def test_key_not_registered_denied(validator):
    """No registered key → KEY_NOT_FOUND."""
    proof = _proof()  # uses EC_P256_JWK_PUBLIC but nothing registered
    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.KEY_NOT_FOUND


def test_revoked_key_denied(validator, store, registered_key):
    store.revoke_key("agent-001", registered_key.key_id)
    proof = _proof()
    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.KEY_REVOKED


# ---------------------------------------------------------------------------
# Signature verification with a real EC P-256 key pair
# ---------------------------------------------------------------------------

def test_signature_verification_valid_proof():
    """Full round-trip: generate EC key, register, sign DPoP proof, validate."""
    pytest.importorskip("cryptography")
    pytest.importorskip("jwt")

    from cryptography.hazmat.primitives.asymmetric.ec import (
        generate_private_key, SECP256R1, ECDSA
    )
    from cryptography.hazmat.primitives import serialization
    import jwt as pyjwt
    import json

    # Generate real EC P-256 key pair
    private_key = generate_private_key(SECP256R1())
    public_key = private_key.public_key()

    # Export public key as JWK
    from jwt.algorithms import ECAlgorithm
    public_jwk = json.loads(ECAlgorithm.to_jwk(public_key))

    # Register the public key
    store = MemoryKeyStore()
    store.register_key(KeyRegistrationRequest(
        agent_id="real-agent",
        algorithm=KeyAlgorithm.EC_P256,
        public_key_jwk=public_jwk,
    ))
    validator = StrictDPoPValidator(key_lookup=store.get_key_by_thumbprint)

    # Build a real DPoP proof JWT
    jti = secrets.token_hex(16)
    now = int(time.time())
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk}
    payload = {
        "jti": jti,
        "htm": "POST",
        "htu": "https://auth.swarms.network/token",
        "iat": now,
    }
    raw_jwt = pyjwt.encode(payload, private_key, algorithm="ES256", headers=header)

    proof = DPoPProof(
        typ="dpop+jwt",
        alg="ES256",
        jwk=public_jwk,
        jti=jti,
        htm="POST",
        htu="https://auth.swarms.network/token",
        iat=datetime.fromtimestamp(now, tz=timezone.utc),
        raw_jwt=raw_jwt,
    )

    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is True
    assert result.agent_id == "real-agent"


def test_signature_verification_wrong_key_denied():
    """Proof signed with wrong key → signature verification fails."""
    pytest.importorskip("cryptography")
    pytest.importorskip("jwt")

    from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
    from jwt.algorithms import ECAlgorithm
    import jwt as pyjwt
    import json

    # Two distinct key pairs
    private_key_A = generate_private_key(SECP256R1())
    public_key_A = private_key_A.public_key()
    private_key_B = generate_private_key(SECP256R1())
    public_key_B = private_key_B.public_key()

    public_jwk_A = json.loads(ECAlgorithm.to_jwk(public_key_A))
    public_jwk_B = json.loads(ECAlgorithm.to_jwk(public_key_B))

    store = MemoryKeyStore()
    # Register key A
    store.register_key(KeyRegistrationRequest(
        agent_id="real-agent",
        algorithm=KeyAlgorithm.EC_P256,
        public_key_jwk=public_jwk_A,
    ))
    validator = StrictDPoPValidator(key_lookup=store.get_key_by_thumbprint)

    # Sign proof with key A but claim JWK is key B (thumbprint mismatch → KEY_NOT_FOUND)
    jti = secrets.token_hex(16)
    now = int(time.time())
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk_B}
    payload = {"jti": jti, "htm": "POST", "htu": "https://auth.swarms.network/token", "iat": now}
    raw_jwt = pyjwt.encode(payload, private_key_A, algorithm="ES256", headers=header)

    proof = DPoPProof(
        typ="dpop+jwt", alg="ES256", jwk=public_jwk_B,
        jti=jti, htm="POST", htu="https://auth.swarms.network/token",
        iat=datetime.fromtimestamp(now, tz=timezone.utc),
        raw_jwt=raw_jwt,
    )

    # Key B is not registered → KEY_NOT_FOUND (not a signature error, but still denied)
    result = validator.validate_proof(proof, "POST", "https://auth.swarms.network/token")
    assert result.valid is False
