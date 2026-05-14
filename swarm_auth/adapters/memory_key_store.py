"""
Memory Key Store — in-process AgentKeyStorePort for testing.

ADR-027 Stage 6.

Never persists across process restarts. Use DynamoDBKeyStore (Stage 7)
for production.

Extra method not on the port:
  get_key_by_thumbprint(thumbprint: str) -> Optional[AgentKey]
    Used by StrictDPoPValidator to look up a key from the JWK thumbprint
    embedded in the DPoP proof header (RFC 9449 §4.2, RFC 7638).
"""

import base64
import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from swarm_auth.ports.agent_key_store_port import (
    AgentKey,
    AgentKeyStorePort,
    KeyAlgorithm,
    KeyRegistrationRequest,
    KeyStatus,
)

# JWK parameters that indicate private key material (must be rejected at registration)
_PRIVATE_PARAMS: frozenset = frozenset({"d", "p", "q", "dp", "dq", "qi", "k"})


def compute_jwk_thumbprint(jwk: dict) -> str:
    """
    Compute the JWK Thumbprint (RFC 7638 §3).

    SHA-256 of the canonical JSON representation of the required JWK
    members in lexicographic key order, base64url-encoded without padding.

    Supported key types: EC (P-256, P-384), RSA, OKP (Ed25519).
    """
    kty = jwk.get("kty", "")
    if kty == "EC":
        canonical_members = {
            "crv": jwk["crv"],
            "kty": "EC",
            "x": jwk["x"],
            "y": jwk["y"],
        }
    elif kty == "RSA":
        canonical_members = {
            "e": jwk["e"],
            "kty": "RSA",
            "n": jwk["n"],
        }
    elif kty == "OKP":
        canonical_members = {
            "crv": jwk["crv"],
            "kty": "OKP",
            "x": jwk["x"],
        }
    else:
        canonical_members = {"kty": kty}

    raw = json.dumps(
        canonical_members, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    digest = hashlib.sha256(raw).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class MemoryKeyStore(AgentKeyStorePort):
    """
    Thread-safe in-memory key store.

    Keys are stored in a dict keyed by (agent_id, key_id). A secondary
    index maps JWK thumbprint → (agent_id, key_id) for DPoP proof lookup.
    """

    def __init__(self) -> None:
        self._keys: Dict[Tuple[str, str], AgentKey] = {}
        # thumbprint → (agent_id, key_id)
        self._thumbprint_index: Dict[str, Tuple[str, str]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # AgentKeyStorePort interface
    # ------------------------------------------------------------------

    def register_key(self, request: KeyRegistrationRequest) -> AgentKey:
        """
        Register a public key for an agent.

        Raises:
            ValueError: if JWK contains private key material (field "d", "p", etc.)
                        or if the JWK is missing required fields for its kty.
        """
        if _PRIVATE_PARAMS & set(request.public_key_jwk.keys()):
            raise ValueError(
                "JWK registration rejected: private key material detected "
                f"({_PRIVATE_PARAMS & set(request.public_key_jwk.keys())}). "
                "Register public key only."
            )

        jwk = dict(request.public_key_jwk)
        thumbprint = compute_jwk_thumbprint(jwk)

        key = AgentKey(
            agent_id=request.agent_id,
            key_id=thumbprint,  # key_id derived from RFC 7638 thumbprint
            algorithm=request.algorithm,
            public_key_jwk=jwk,
            status=KeyStatus.ACTIVE,
            registered_at=datetime.now(timezone.utc),
            not_after=request.not_after,
            description=request.description,
            registered_by=request.registered_by,
        )

        with self._lock:
            self._keys[(request.agent_id, thumbprint)] = key
            self._thumbprint_index[thumbprint] = (request.agent_id, thumbprint)

        return key

    def get_key(
        self, agent_id: str, key_id: Optional[str] = None
    ) -> Optional[AgentKey]:
        """
        Return the agent's key.

        If key_id is None, returns the first ACTIVE key for the agent
        (most recently registered). If key_id is provided, returns that
        specific key regardless of status.
        """
        with self._lock:
            if key_id is not None:
                return self._keys.get((agent_id, key_id))

            # Scan for ACTIVE key; prefer most recent (insertion order via dict)
            candidates = [
                k for (aid, _), k in self._keys.items()
                if aid == agent_id and k.status == KeyStatus.ACTIVE
            ]

        if not candidates:
            return None
        # Return most recently registered
        return max(candidates, key=lambda k: k.registered_at)

    def list_keys(
        self, agent_id: str, status: Optional[KeyStatus] = None
    ) -> List[AgentKey]:
        """List all keys for agent, optionally filtered by status. Newest first."""
        with self._lock:
            keys = [
                k for (aid, _), k in self._keys.items() if aid == agent_id
            ]

        if status is not None:
            keys = [k for k in keys if k.status == status]

        keys.sort(key=lambda k: k.registered_at, reverse=True)
        return keys

    def revoke_key(
        self, agent_id: str, key_id: str, reason: Optional[str] = None
    ) -> bool:
        """
        Revoke a key immediately.

        Returns False if (agent_id, key_id) not found. Sets status to
        REVOKED; the key remains in the store for audit purposes.
        """
        with self._lock:
            key = self._keys.get((agent_id, key_id))
            if key is None:
                return False
            key.status = KeyStatus.REVOKED
        return True

    def rotate_key(
        self,
        agent_id: str,
        new_key_request: KeyRegistrationRequest,
        grace_period_seconds: int = 300,
    ) -> AgentKey:
        """
        Register a new key and mark the current ACTIVE key as ROTATING.

        The ROTATING key remains valid for grace_period_seconds to allow
        in-flight requests to complete. In MemoryKeyStore, grace period
        expiry is not actively enforced — callers must call revoke_key()
        explicitly after the grace period. Production adapters (DynamoDB)
        will enforce expiry via TTL.
        """
        with self._lock:
            for (aid, kid), key in self._keys.items():
                if aid == agent_id and key.status == KeyStatus.ACTIVE:
                    key.status = KeyStatus.ROTATING
                    break

        return self.register_key(new_key_request)

    # ------------------------------------------------------------------
    # DPoP lookup helper (not on AgentKeyStorePort)
    # ------------------------------------------------------------------

    def get_key_by_thumbprint(self, thumbprint: str) -> Optional[AgentKey]:
        """
        Look up a key by its JWK thumbprint (RFC 7638).

        Called by StrictDPoPValidator to resolve the key from the JWK
        embedded in the DPoP proof header (RFC 9449 §4.2 step 11).

        Not part of the AgentKeyStorePort interface — this method is
        specific to implementations that maintain a thumbprint index.
        A future AgentKeyStorePort amendment may add this to the port.
        """
        with self._lock:
            coords = self._thumbprint_index.get(thumbprint)
            if coords is None:
                return None
            return self._keys.get(coords)
