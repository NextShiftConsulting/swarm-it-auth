"""
Unit tests for StrictDPoPValidator (ADR-027 Stage 6, blocker-fix pass).

Tests cover all RFC 9449 §4.2 validation steps.

raw_jwt discipline
------------------
- Tests that expect valid=True MUST supply raw_jwt (signed with a real key).
- Tests that expect valid=False for structural reasons (steps 1-9) MAY use
  raw_jwt=None; they fail before reaching the signature step.
- test_dpop_rejects_missing_raw_jwt explicitly tests the Blocker 1 fix.

Fixtures ec_private_key / ec_public_jwk / store_with_real_key / validator_real
provide a real EC P-256 key pair for all valid=True tests.
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

# All tests in this file require cryptography + PyJWT[crypto]
pytest.importorskip("cryptography")
pytest.importorskip("jwt")

from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
import jwt as pyjwt
from jwt.algorithms import ECAlgorithm


# ---------------------------------------------------------------------------
# Key fixtures (module-scoped — generate once per test session)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ec_private_key():
    return generate_private_key(SECP256R1())


@pytest.fixture(scope="module")
def ec_public_jwk(ec_private_key):
    return json.loads(ECAlgorithm.to_jwk(ec_private_key.public_key()))


@pytest.fixture
def store():
    return MemoryKeyStore()


@pytest.fixture
def store_with_real_key(store, ec_public_jwk):
    """Store with a real EC P-256 public key registered for 'agent-001'."""
    store.register_key(KeyRegistrationRequest(
        agent_id="agent-001",
        algorithm=KeyAlgorithm.EC_P256,
        public_key_jwk=ec_public_jwk,
    ))
    return store


@pytest.fixture
def validator(store_with_real_key):
    return StrictDPoPValidator(key_lookup=store_with_real_key.get_key_by_thumbprint)


@pytest.fixture
def registered_key(store_with_real_key):
    return store_with_real_key.get_key("agent-001")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HTM = "POST"
_HTU = "https://auth.swarms.network/token"


def _make_signed_proof(
    ec_private_key,
    ec_public_jwk,
    *,
    jti=None,
    htm=_HTM,
    htu=_HTU,
    iat_offset=0,
    nonce=None,
    ath=None,
) -> DPoPProof:
    """Create a real, signed DPoP proof JWT using the given EC P-256 key."""
    jti = jti or secrets.token_hex(16)
    now = int(time.time()) + iat_offset
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": ec_public_jwk}
    payload: dict = {
        "jti": jti,
        "htm": htm,
        "htu": htu,
        "iat": now,
    }
    if nonce is not None:
        payload["nonce"] = nonce
    if ath is not None:
        payload["ath"] = ath
    raw_jwt = pyjwt.encode(payload, ec_private_key, algorithm="ES256", headers=header)
    return DPoPProof(
        typ="dpop+jwt",
        alg="ES256",
        jwk=ec_public_jwk,
        jti=jti,
        htm=htm,
        htu=htu,
        iat=datetime.fromtimestamp(now, tz=timezone.utc),
        nonce=nonce,
        ath=ath,
        raw_jwt=raw_jwt,
    )


def _unsigned_proof(
    typ="dpop+jwt",
    alg="ES256",
    jwk=None,
    jti=None,
    htm=_HTM,
    htu=_HTU,
    iat=None,
    nonce=None,
    ath=None,
) -> DPoPProof:
    """Unsigned proof (raw_jwt=None). Use only for tests that expect DENY before step 10."""
    return DPoPProof(
        typ=typ,
        alg=alg,
        jwk=jwk or {"kty": "EC", "crv": "P-256",
                    "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                    "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},
        jti=jti or secrets.token_hex(16),
        htm=htm,
        htu=htu,
        iat=iat or datetime.now(timezone.utc),
        nonce=nonce,
        ath=ath,
        raw_jwt=None,
    )


# ---------------------------------------------------------------------------
# Blocker 1 fix: raw_jwt=None must be rejected (fail closed)
# ---------------------------------------------------------------------------

def test_dpop_rejects_missing_raw_jwt(validator, registered_key, ec_public_jwk):
    """
    Blocker 1 fix: proof without raw_jwt is rejected.
    RFC 9449 §4.2 signature verification is mandatory — a proof-of-possession
    without a verifiable JWT is not a valid DPoP proof.

    Uses ec_public_jwk so the key lookup (step 9) succeeds and the
    raw_jwt check (step 10) fires rather than KEY_NOT_FOUND (step 9).
    """
    proof = _unsigned_proof(jwk=ec_public_jwk)
    result = validator.validate_proof(proof, _HTM, _HTU)
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.INVALID_DPOP_PROOF
    assert "raw_jwt" in result.error_description


# ---------------------------------------------------------------------------
# Happy path (real EC P-256 signed proof)
# ---------------------------------------------------------------------------

def test_validate_proof_allows_valid_proof(validator, registered_key, ec_private_key, ec_public_jwk):
    proof = _make_signed_proof(ec_private_key, ec_public_jwk)
    result = validator.validate_proof(proof, _HTM, _HTU)
    assert result.valid is True
    assert result.agent_id == "agent-001"
    assert result.key_id == registered_key.key_id


# ---------------------------------------------------------------------------
# typ check — fails at step 1 (raw_jwt=None is fine here)
# ---------------------------------------------------------------------------

def test_validate_wrong_typ_denied(validator, registered_key):
    proof = _unsigned_proof(typ="JWT")
    result = validator.validate_proof(proof, _HTM, _HTU)
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.INVALID_DPOP_PROOF


# ---------------------------------------------------------------------------
# Algorithm check — fails at step 2 (raw_jwt=None is fine here)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_alg", ["HS256", "HS512", "none"])
def test_validate_symmetric_alg_denied(validator, registered_key, bad_alg):
    proof = _unsigned_proof(alg=bad_alg)
    result = validator.validate_proof(proof, _HTM, _HTU)
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.ALGORITHM_REJECTED


# ---------------------------------------------------------------------------
# Replay prevention — needs signed proof so jti is actually recorded
# ---------------------------------------------------------------------------

def test_replay_detected_on_second_use(validator, registered_key, ec_private_key, ec_public_jwk):
    jti = secrets.token_hex(16)
    proof = _make_signed_proof(ec_private_key, ec_public_jwk, jti=jti)
    r1 = validator.validate_proof(proof, _HTM, _HTU)
    assert r1.valid is True
    # Second use of the same proof (same jti, same raw_jwt)
    r2 = validator.validate_proof(proof, _HTM, _HTU)
    assert r2.valid is False
    assert r2.error_code == DPoPErrorCode.REPLAY_DETECTED


def test_different_jti_not_replay(validator, registered_key, ec_private_key, ec_public_jwk):
    r1 = validator.validate_proof(
        _make_signed_proof(ec_private_key, ec_public_jwk), _HTM, _HTU
    )
    r2 = validator.validate_proof(
        _make_signed_proof(ec_private_key, ec_public_jwk), _HTM, _HTU
    )
    assert r1.valid is True
    assert r2.valid is True


# ---------------------------------------------------------------------------
# IAT clock skew — fails at step 4 (raw_jwt=None is fine here)
# ---------------------------------------------------------------------------

def test_iat_too_old_denied(validator, registered_key):
    proof = _unsigned_proof(iat=datetime.now(timezone.utc) - timedelta(seconds=120))
    result = validator.validate_proof(proof, _HTM, _HTU)
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.CLOCK_SKEW


def test_iat_too_far_future_denied(validator, registered_key):
    proof = _unsigned_proof(iat=datetime.now(timezone.utc) + timedelta(seconds=120))
    result = validator.validate_proof(proof, _HTM, _HTU)
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.CLOCK_SKEW


# ---------------------------------------------------------------------------
# HTM check — fails at step 5 (raw_jwt=None is fine here)
# ---------------------------------------------------------------------------

def test_htm_mismatch_denied(validator, registered_key):
    proof = _unsigned_proof(htm="GET")
    result = validator.validate_proof(proof, "POST", _HTU)
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.HTM_MISMATCH


def test_htm_case_insensitive(validator, registered_key, ec_private_key, ec_public_jwk):
    proof = _make_signed_proof(ec_private_key, ec_public_jwk, htm="post")
    result = validator.validate_proof(proof, "POST", _HTU)
    assert result.valid is True


# ---------------------------------------------------------------------------
# HTU check — fails at step 6 (raw_jwt=None is fine for mismatch case)
# ---------------------------------------------------------------------------

def test_htu_mismatch_denied(validator, registered_key):
    proof = _unsigned_proof(htu="https://other.example.com/token")
    result = validator.validate_proof(proof, _HTM, _HTU)
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.HTU_MISMATCH


def test_htu_query_string_stripped(validator, registered_key, ec_private_key, ec_public_jwk):
    """RFC 9449 §4.2: query string and fragment are ignored in htu comparison."""
    proof = _make_signed_proof(
        ec_private_key, ec_public_jwk,
        htu="https://auth.swarms.network/token?foo=bar#frag",
    )
    result = validator.validate_proof(proof, _HTM, _HTU)
    assert result.valid is True


# ---------------------------------------------------------------------------
# Nonce check — step 7
# ---------------------------------------------------------------------------

def test_nonce_mismatch_denied(validator, registered_key):
    proof = _unsigned_proof(nonce="wrong-nonce")
    result = validator.validate_proof(proof, _HTM, _HTU, expected_nonce="correct-nonce")
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.NONCE_MISMATCH


def test_nonce_correct_allowed(validator, registered_key, ec_private_key, ec_public_jwk):
    proof = _make_signed_proof(ec_private_key, ec_public_jwk, nonce="server-nonce-xyz")
    result = validator.validate_proof(proof, _HTM, _HTU, expected_nonce="server-nonce-xyz")
    assert result.valid is True


def test_issue_nonce_returns_string(validator):
    nonce = validator.issue_nonce("agent-001")
    assert isinstance(nonce, str)
    assert len(nonce) > 10


# ---------------------------------------------------------------------------
# ATH check — step 8
# ---------------------------------------------------------------------------

def test_ath_mismatch_denied(validator, registered_key):
    proof = _unsigned_proof(ath="wrong-ath-value")
    result = validator.validate_proof(proof, _HTM, _HTU, access_token_hash="correct-ath-value")
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.ATH_MISMATCH


def test_ath_correct_allowed(validator, registered_key, ec_private_key, ec_public_jwk):
    ath = base64.urlsafe_b64encode(
        hashlib.sha256(b"my-access-token").digest()
    ).rstrip(b"=").decode()
    proof = _make_signed_proof(ec_private_key, ec_public_jwk, ath=ath)
    result = validator.validate_proof(proof, _HTM, _HTU, access_token_hash=ath)
    assert result.valid is True


# ---------------------------------------------------------------------------
# Key not found / revoked — step 9 (raw_jwt=None is fine; fails before step 10)
# ---------------------------------------------------------------------------

def test_key_not_registered_denied(store):
    """No registered key → KEY_NOT_FOUND (unregistered JWK thumbprint)."""
    validator_no_keys = StrictDPoPValidator(key_lookup=store.get_key_by_thumbprint)
    proof = _unsigned_proof()
    result = validator_no_keys.validate_proof(proof, _HTM, _HTU)
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.KEY_NOT_FOUND


def test_revoked_key_denied(validator, store_with_real_key, registered_key, ec_public_jwk):
    """Revoked key is found in the store but rejected with KEY_REVOKED (not KEY_NOT_FOUND).

    Uses ec_public_jwk so the thumbprint matches the now-revoked key entry.
    """
    store_with_real_key.revoke_key("agent-001", registered_key.key_id)
    proof = _unsigned_proof(jwk=ec_public_jwk)
    result = validator.validate_proof(proof, _HTM, _HTU)
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.KEY_REVOKED


# ---------------------------------------------------------------------------
# Signature verification with real EC P-256 key pair (end-to-end)
# ---------------------------------------------------------------------------

def test_signature_verification_valid_proof(validator, registered_key, ec_private_key, ec_public_jwk):
    """Full round-trip: sign DPoP proof with registered key → valid."""
    proof = _make_signed_proof(ec_private_key, ec_public_jwk)
    result = validator.validate_proof(proof, _HTM, _HTU)
    assert result.valid is True
    assert result.agent_id == "agent-001"


def test_signature_verification_wrong_key_denied():
    """Proof JWK claims key B but key B is not registered → KEY_NOT_FOUND."""
    private_A = generate_private_key(SECP256R1())
    private_B = generate_private_key(SECP256R1())
    public_jwk_A = json.loads(ECAlgorithm.to_jwk(private_A.public_key()))
    public_jwk_B = json.loads(ECAlgorithm.to_jwk(private_B.public_key()))

    store = MemoryKeyStore()
    # Register key A, but proof will claim key B
    store.register_key(KeyRegistrationRequest(
        agent_id="real-agent",
        algorithm=KeyAlgorithm.EC_P256,
        public_key_jwk=public_jwk_A,
    ))
    validator = StrictDPoPValidator(key_lookup=store.get_key_by_thumbprint)

    # Proof claims key B (not registered)
    jti = secrets.token_hex(16)
    now = int(time.time())
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk_B}
    payload = {"jti": jti, "htm": "POST", "htu": _HTU, "iat": now}
    raw_jwt = pyjwt.encode(payload, private_A, algorithm="ES256", headers=header)

    proof = DPoPProof(
        typ="dpop+jwt", alg="ES256", jwk=public_jwk_B,
        jti=jti, htm="POST", htu=_HTU,
        iat=datetime.fromtimestamp(now, tz=timezone.utc),
        raw_jwt=raw_jwt,
    )
    result = validator.validate_proof(proof, "POST", _HTU)
    assert result.valid is False
    assert result.error_code == DPoPErrorCode.KEY_NOT_FOUND
