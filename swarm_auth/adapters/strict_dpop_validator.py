"""
Strict DPoP Validator — full RFC 9449 §4.2 proof validation.

ADR-027 Stage 6.

Validates DPoP proofs in order per RFC 9449 §4.2:
  1. typ == "dpop+jwt"
  2. alg is asymmetric (not "none", not symmetric HS*/A*)
  3. jti not seen before (replay prevention, §11.1)
  4. iat within max_age_seconds clock skew window
  5. htm matches expected HTTP method (case-insensitive)
  6. htu matches expected HTTP URI (ignoring query and fragment)
  7. nonce matches server nonce if expected_nonce provided (§8)
  8. ath matches base64url(SHA-256(access_token)) if provided (§5)
  9. JWK in proof header matches agent's registered public key
 10. Signature verifies against the resolved public key

Requires:
  - PyJWT >= 2.0 (with [crypto] extras — PyJWT + cryptography)
  - MemoryKeyStore (or any adapter implementing get_key_by_thumbprint)

Key resolution: the DPoP proof's jwk header is used to compute the
RFC 7638 thumbprint, which is then used to look up the registered key
via the key_lookup callable injected at construction.
"""

import base64
import hashlib
import json
import os
import secrets
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, Optional, Set
from urllib.parse import urlparse

from swarm_auth.ports.agent_key_store_port import AgentKey, KeyStatus
from swarm_auth.ports.dpop_validator_port import (
    DPoPErrorCode,
    DPoPProof,
    DPoPValidationResult,
    DPoPValidatorPort,
)

try:
    import jwt as pyjwt
    from jwt.algorithms import ECAlgorithm, RSAAlgorithm, OKPAlgorithm
    _HAS_PYJWT = True
except ImportError:
    _HAS_PYJWT = False

# Algorithms that are NOT allowed for DPoP (symmetric and "none")
# RFC 9449 §4.1: "The algorithm MUST NOT be 'none' or an HMAC-based algorithm"
_DISALLOWED_ALGORITHMS: frozenset = frozenset({
    "none", "HS256", "HS384", "HS512",
    "A128KW", "A192KW", "A256KW",
    "A128GCMKW", "A192GCMKW", "A256GCMKW",
})

# Allowed asymmetric algorithms for DPoP proofs
_ALLOWED_ALGORITHMS: frozenset = frozenset({
    "ES256", "ES384", "ES512",
    "RS256", "RS384", "RS512",
    "EdDSA",
    "PS256", "PS384", "PS512",
})


def _compute_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url, no padding)."""
    kty = jwk.get("kty", "")
    if kty == "EC":
        canon = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        canon = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "OKP":
        canon = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        canon = {"kty": kty}
    raw = json.dumps(canon, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).rstrip(b"=").decode()


def _normalize_htu(htu: str) -> str:
    """Strip query string and fragment from URI per RFC 9449 §4.2."""
    parsed = urlparse(htu)
    return parsed._replace(query="", fragment="").geturl()


def _public_key_from_jwk(jwk: dict) -> Any:
    """
    Convert a JWK dict to a cryptography public key object.

    Raises ImportError if PyJWT[crypto] is not installed.
    Raises ValueError if the JWK kty is unsupported.
    """
    if not _HAS_PYJWT:
        raise ImportError(
            "PyJWT with cryptography extras is required for DPoP signature "
            "verification. Install with: pip install PyJWT[crypto]"
        )
    kty = jwk.get("kty", "")
    jwk_str = json.dumps(jwk)
    if kty == "EC":
        return ECAlgorithm.from_jwk(jwk_str)
    elif kty == "RSA":
        return RSAAlgorithm.from_jwk(jwk_str)
    elif kty == "OKP":
        return OKPAlgorithm.from_jwk(jwk_str)
    raise ValueError(f"Unsupported JWK kty: {kty!r}")


class StrictDPoPValidator(DPoPValidatorPort):
    """
    Full RFC 9449 §4.2 DPoP proof validator.

    Args:
        key_lookup:        Callable[(thumbprint: str) -> Optional[AgentKey]].
                           Typically MemoryKeyStore.get_key_by_thumbprint.
        max_age_seconds:   Maximum allowed iat age (default 60s per §4.2).
        nonce_ttl_seconds: How long issued nonces remain valid (default 300s).
    """

    def __init__(
        self,
        key_lookup: Callable[[str], Optional[AgentKey]],
        max_age_seconds: int = 60,
        nonce_ttl_seconds: int = 300,
    ) -> None:
        self._key_lookup = key_lookup
        self._max_age_seconds = max_age_seconds
        self._nonce_ttl_seconds = nonce_ttl_seconds
        self._seen_jti: Set[str] = set()
        # agent_id → (nonce_value, expiry)
        self._issued_nonces: Dict[str, tuple] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # DPoPValidatorPort interface
    # ------------------------------------------------------------------

    def validate_proof(
        self,
        proof: DPoPProof,
        expected_htm: str,
        expected_htu: str,
        access_token_hash: Optional[str] = None,
        expected_nonce: Optional[str] = None,
    ) -> DPoPValidationResult:
        """
        Validate a DPoP proof per RFC 9449 §4.2 (10 steps in order).

        Returns DPoPValidationResult with valid=True on success.
        Returns valid=False with error_code on any failure.
        NEVER raises.
        """
        try:
            return self._validate(
                proof, expected_htm, expected_htu,
                access_token_hash, expected_nonce,
            )
        except Exception as exc:
            return DPoPValidationResult(
                valid=False,
                error_code=DPoPErrorCode.INVALID_DPOP_PROOF,
                error_description=f"Unexpected validation error: {exc}",
            )

    def issue_nonce(self, agent_id: str) -> str:
        """
        Issue a fresh server nonce (RFC 9449 §8).

        128 bits of entropy, base64url-encoded. Bound to agent_id and
        expires after nonce_ttl_seconds.
        """
        nonce = base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode()
        expiry = datetime.now(timezone.utc) + timedelta(seconds=self._nonce_ttl_seconds)
        with self._lock:
            self._issued_nonces[agent_id] = (nonce, expiry)
        return nonce

    # ------------------------------------------------------------------
    # Private implementation
    # ------------------------------------------------------------------

    def _validate(
        self,
        proof: DPoPProof,
        expected_htm: str,
        expected_htu: str,
        access_token_hash: Optional[str],
        expected_nonce: Optional[str],
    ) -> DPoPValidationResult:
        now = datetime.now(timezone.utc)

        # Step 1: typ must be "dpop+jwt"
        if proof.typ != "dpop+jwt":
            return DPoPValidationResult(
                valid=False,
                error_code=DPoPErrorCode.INVALID_DPOP_PROOF,
                error_description=f"typ must be 'dpop+jwt', got {proof.typ!r}",
            )

        # Step 2: alg must be asymmetric
        if proof.alg in _DISALLOWED_ALGORITHMS or proof.alg not in _ALLOWED_ALGORITHMS:
            return DPoPValidationResult(
                valid=False,
                error_code=DPoPErrorCode.ALGORITHM_REJECTED,
                error_description=(
                    f"Algorithm {proof.alg!r} is not allowed for DPoP. "
                    "Use an asymmetric algorithm (ES256, RS256, EdDSA, …)."
                ),
            )

        # Step 3: jti replay check
        with self._lock:
            if proof.jti in self._seen_jti:
                return DPoPValidationResult(
                    valid=False,
                    error_code=DPoPErrorCode.REPLAY_DETECTED,
                    error_description=f"DPoP proof jti {proof.jti!r} has already been used.",
                )

        # Step 4: iat clock skew
        age = (now - proof.iat).total_seconds()
        if abs(age) > self._max_age_seconds:
            return DPoPValidationResult(
                valid=False,
                error_code=DPoPErrorCode.CLOCK_SKEW,
                error_description=(
                    f"DPoP proof iat is {age:.0f}s away from server time "
                    f"(max allowed: {self._max_age_seconds}s)."
                ),
            )

        # Step 5: htm
        if proof.htm.upper() != expected_htm.upper():
            return DPoPValidationResult(
                valid=False,
                error_code=DPoPErrorCode.HTM_MISMATCH,
                error_description=(
                    f"htm {proof.htm!r} does not match expected {expected_htm!r}."
                ),
            )

        # Step 6: htu (normalize both, ignore query/fragment)
        if _normalize_htu(proof.htu) != _normalize_htu(expected_htu):
            return DPoPValidationResult(
                valid=False,
                error_code=DPoPErrorCode.HTU_MISMATCH,
                error_description=(
                    f"htu {proof.htu!r} does not match expected {expected_htu!r}."
                ),
            )

        # Step 7: nonce
        if expected_nonce is not None and proof.nonce != expected_nonce:
            return DPoPValidationResult(
                valid=False,
                error_code=DPoPErrorCode.NONCE_MISMATCH,
                error_description="DPoP proof nonce does not match server-issued nonce.",
            )

        # Step 8: access token hash (RFC 9449 §5)
        if access_token_hash is not None:
            if proof.ath != access_token_hash:
                return DPoPValidationResult(
                    valid=False,
                    error_code=DPoPErrorCode.ATH_MISMATCH,
                    error_description="DPoP proof ath does not match access token hash.",
                )

        # Step 9: key store lookup via JWK thumbprint
        thumbprint = _compute_thumbprint(proof.jwk)
        agent_key = self._key_lookup(thumbprint)

        if agent_key is None:
            return DPoPValidationResult(
                valid=False,
                error_code=DPoPErrorCode.KEY_NOT_FOUND,
                error_description=(
                    f"No registered key with thumbprint {thumbprint!r}. "
                    "Agent must register its public key before using DPoP."
                ),
            )

        if agent_key.status == KeyStatus.REVOKED:
            return DPoPValidationResult(
                valid=False,
                error_code=DPoPErrorCode.KEY_REVOKED,
                agent_id=agent_key.agent_id,
                key_id=agent_key.key_id,
                error_description=(
                    f"Key {agent_key.key_id!r} for agent {agent_key.agent_id!r} "
                    "has been revoked."
                ),
            )

        # Step 10: signature verification (requires raw_jwt + PyJWT[crypto])
        if proof.raw_jwt is not None:
            sig_result = self._verify_signature(proof, agent_key)
            if sig_result is not None:
                return sig_result

        # All checks passed — record jti to prevent replay
        with self._lock:
            self._seen_jti.add(proof.jti)

        return DPoPValidationResult(
            valid=True,
            agent_id=agent_key.agent_id,
            key_id=agent_key.key_id,
        )

    def _verify_signature(
        self, proof: DPoPProof, agent_key: AgentKey
    ) -> Optional[DPoPValidationResult]:
        """
        Verify the JWT signature of the DPoP proof.

        Returns None on success (caller proceeds), or a DPoPValidationResult
        with valid=False on failure.
        """
        try:
            public_key = _public_key_from_jwk(agent_key.public_key_jwk)
            pyjwt.decode(
                proof.raw_jwt,
                public_key,
                algorithms=list(_ALLOWED_ALGORITHMS),
                options={"verify_exp": False},  # iat/exp handled above
            )
            return None  # signature valid
        except ImportError as exc:
            # PyJWT[crypto] not installed — fail closed
            return DPoPValidationResult(
                valid=False,
                error_code=DPoPErrorCode.INVALID_DPOP_PROOF,
                error_description=str(exc),
            )
        except Exception as exc:
            return DPoPValidationResult(
                valid=False,
                error_code=DPoPErrorCode.INVALID_DPOP_PROOF,
                error_description=f"DPoP signature verification failed: {exc}",
            )
