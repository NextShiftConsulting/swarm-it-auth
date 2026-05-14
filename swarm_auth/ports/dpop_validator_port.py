"""
DPoP Validator Port — Demonstrating Proof of Possession verification.

ADR-027 Stage 5 / ADR-028 Sub-decision 4 (Gap 3: bearer-only JWTs).

Standards references:
  - RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)
    §4.1: DPoP Proof JWT syntax and required claims
    §4.2: DPoP Proof JWT validation rules (server side)
    §4.3: Checking DPoP Proofs (nonce, ath, htu, htm)
    §5:   DPoP Access Tokens (ath claim)
    §11:  Security considerations (replay prevention, nonce binding)

DPoP converts bearer tokens into sender-constrained tokens. A DPoP proof is
a short-lived, single-use JWT signed with the agent's private key. The server
verifies the proof against the agent's registered public key (AgentKeyStorePort)
and the current request context (method, URL, nonce).

Gap closed: ADR-027 Gap 3 — all credential vending currently uses bearer tokens.
A DPoP-validated flow requires this port before the credential broker is invoked.

No implementation in this file. Adapters live in swarm_auth/adapters/:
  - Stage 6: StrictDPoPValidator (full RFC 9449 §4.2 compliance)

Usage (Stage 7+):
    from swarm_auth.ports.dpop_validator_port import DPoPValidatorPort, DPoPProof

    validator: DPoPValidatorPort = StrictDPoPValidator(key_store=key_store)
    result = validator.validate_proof(
        proof=DPoPProof(header=..., payload=...),
        expected_htm="POST",
        expected_htu="https://auth.swarms.network/token",
        access_token_hash=ath,
    )
    if not result.valid:
        raise HTTPException(401, result.error_description)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional


class DPoPErrorCode(Enum):
    """
    RFC 9449 §7.1 error codes for DPoP proof validation failures.

    These map directly to the error values defined in the RFC and are
    used in WWW-Authenticate response headers on validation failure.
    """
    # RFC 9449 §7.1 defined errors
    USE_DPOP_NONCE = "use_dpop_nonce"       # Server requires a fresh nonce
    INVALID_DPOP_PROOF = "invalid_dpop_proof"  # Proof is malformed or invalid
    # Internal error codes (not in RFC, used for adapter-level diagnostics)
    KEY_NOT_FOUND = "key_not_found"             # agent has no registered key
    KEY_REVOKED = "key_revoked"                 # proof signed with revoked key
    REPLAY_DETECTED = "replay_detected"         # jti already seen (§11.1)
    CLOCK_SKEW = "clock_skew"                   # iat too old or in future (§4.2)
    HTM_MISMATCH = "htm_mismatch"               # HTTP method mismatch (§4.2)
    HTU_MISMATCH = "htu_mismatch"               # HTTP URL mismatch (§4.2)
    ATH_MISMATCH = "ath_mismatch"               # Access token hash mismatch (§5)
    NONCE_MISMATCH = "nonce_mismatch"           # Nonce value mismatch (§4.3)
    ALGORITHM_REJECTED = "algorithm_rejected"   # alg not allowed (§4.1)


@dataclass
class DPoPProof:
    """
    A parsed DPoP proof JWT (RFC 9449 §4.1).

    The proof arrives as a compact-serialized JWT in the DPoP HTTP header.
    The validator parses it into header and payload before validating.

    Required header claims (RFC 9449 §4.1):
      typ: "dpop+jwt"
      alg: asymmetric algorithm (not "none", not symmetric)
      jwk: the public key used to sign the proof

    Required payload claims (RFC 9449 §4.1):
      jti: unique identifier (replay prevention)
      htm: HTTP method of the request
      htu: HTTP URI of the request (without query/fragment)
      iat: issued-at timestamp

    Optional payload claims:
      nonce: server-issued nonce (RFC 9449 §8)
      ath:   base64url(SHA-256(access_token)) — RFC 9449 §5
    """
    # Header
    typ: str                        # MUST be "dpop+jwt"
    alg: str                        # Signing algorithm (RFC 7518)
    jwk: Dict[str, Any]             # Public key (JWK, RFC 7517)

    # Required payload
    jti: str                        # Unique token ID (RFC 9449 §4.1)
    htm: str                        # HTTP method ("GET", "POST", …)
    htu: str                        # HTTP URI (scheme + authority + path)
    iat: datetime                   # Issued-at

    # Optional payload
    nonce: Optional[str] = None     # Server nonce (RFC 9449 §8)
    ath: Optional[str] = None       # Access token hash (RFC 9449 §5)

    # Raw compact JWT (kept for signature verification)
    raw_jwt: Optional[str] = None


@dataclass
class DPoPValidationResult:
    """Result of a DPoP proof validation check."""
    valid: bool
    agent_id: Optional[str] = None          # Resolved from JWK thumbprint
    key_id: Optional[str] = None            # AgentKey.key_id used

    # Failure details (populated when valid=False)
    error_code: Optional[DPoPErrorCode] = None
    error_description: Optional[str] = None

    # Populated when USE_DPOP_NONCE is returned (RFC 9449 §8)
    server_nonce: Optional[str] = None

    validated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class DPoPValidatorPort(ABC):
    """
    Port: DPoP proof validator (RFC 9449).

    Validates inbound DPoP proofs against:
      1. The agent's registered public key (from AgentKeyStorePort)
      2. The current request context (method, URL)
      3. An optional server-issued nonce (replay prevention)
      4. The access token hash when a bound token is present (§5)

    Called before credential vending to confirm the caller holds the private
    key corresponding to the registered public key. Converts bearer tokens
    into sender-constrained tokens per Gap 3 (ADR-027).
    """

    @abstractmethod
    def validate_proof(
        self,
        proof: DPoPProof,
        expected_htm: str,
        expected_htu: str,
        access_token_hash: Optional[str] = None,
        expected_nonce: Optional[str] = None,
    ) -> DPoPValidationResult:
        """
        Validate a DPoP proof against the current request context.

        RFC 9449 §4.2 validation steps (in order):
          1. typ header is "dpop+jwt"
          2. alg is an asymmetric algorithm (not "none", not symmetric)
          3. jwk header contains a valid public key
          4. Signature verifies against jwk
          5. jti has not been seen before (replay, §11.1)
          6. iat is within acceptable clock skew window (§4.2, default ±60s)
          7. htm matches expected_htm (case-insensitive)
          8. htu matches expected_htu (ignoring query and fragment)
          9. If expected_nonce is set: nonce matches
          10. If access_token_hash is set: ath matches SHA-256(access_token)
          11. Public key in jwk matches agent's registered key (AgentKeyStorePort)

        Args:
            proof:              Parsed DPoP proof JWT
            expected_htm:       HTTP method of the request being authorized
            expected_htu:       HTTP URI of the request being authorized
            access_token_hash:  base64url(SHA-256(access_token)) when binding to a token
            expected_nonce:     Server-issued nonce (RFC 9449 §8)

        Returns:
            DPoPValidationResult with valid=True or False + error details.
            MUST NOT raise — callers branch on result.valid.
        """
        pass

    @abstractmethod
    def issue_nonce(self, agent_id: str) -> str:
        """
        Issue a fresh server nonce for the agent (RFC 9449 §8).

        The nonce is bound to the agent and expires after a short TTL.
        Returned in the DPoP-Nonce response header when USE_DPOP_NONCE
        is returned by validate_proof().

        Returns:
            Opaque nonce string (min 128 bits entropy, base64url-encoded).
        """
        pass
