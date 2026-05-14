"""
Agent Key Store Port — per-agent public key registry for DPoP and JWT verification.

ADR-027 Stage 5 / ADR-028 Sub-decision 3.

Standards references:
  - RFC 7517 §4: JSON Web Key (JWK) parameters
  - RFC 7518 §6: Cryptographic Algorithms for Keys (JWA)
  - RFC 9449 §6.1: DPoP — server retrieves agent's public key for proof verification
  - RFC 7638: JWK Thumbprint (key identifier derivation)

An agent registers its public key at provisioning time. The DPoPValidatorPort
retrieves the key here to verify DPoP proofs on inbound requests.

No implementation in this file. Adapters live in swarm_auth/adapters/:
  - Stage 6: MemoryKeyStore (testing)
  - Stage 7: DynamoDBKeyStore (production)

Usage (Stage 6+):
    from swarm_auth.ports.agent_key_store_port import AgentKeyStorePort, AgentKey

    key_store: AgentKeyStorePort = DynamoDBKeyStore(table="swarm-agent-keys")
    agent_key = key_store.get_key(agent_id="orch-001")
    # DPoPValidatorPort uses agent_key.public_key_jwk to verify the DPoP proof
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class KeyAlgorithm(Enum):
    """
    Supported key algorithms.

    RFC 7518 §6.2 (EC) and §6.3 (RSA). Only algorithms approved for use with
    DPoP (RFC 9449 §4.1: alg MUST NOT be "none" or symmetric).
    """
    EC_P256 = "EC_P256"     # ECDSA P-256 — recommended for new agents
    EC_P384 = "EC_P384"     # ECDSA P-384
    RSA_2048 = "RSA_2048"   # RSA 2048-bit — legacy; prefer EC
    RSA_4096 = "RSA_4096"   # RSA 4096-bit — high-assurance contexts
    OKP_ED25519 = "OKP_Ed25519"  # Edwards curve — high performance


class KeyStatus(Enum):
    """Lifecycle status of a registered key."""
    ACTIVE = "active"           # Current signing key
    ROTATING = "rotating"       # Active but being phased out (grace period)
    REVOKED = "revoked"         # No longer valid; any proof signed with it fails
    EXPIRED = "expired"         # Past not_after timestamp


@dataclass
class AgentKey:
    """
    A registered public key for an agent principal.

    The public_key_jwk field holds the JWK representation (RFC 7517) of the
    agent's public key. The DPoPValidatorPort uses this to verify incoming
    DPoP proofs without holding or trusting the private key.

    key_id is derived from the JWK Thumbprint (RFC 7638 §3) when not supplied.
    """
    agent_id: str               # AgentIdentity.user_id
    key_id: str                 # Unique key identifier ("kid" in JWK, RFC 7517 §4.5)
    algorithm: KeyAlgorithm
    public_key_jwk: Dict[str, Any]  # RFC 7517 JWK object (public parameters only)
    status: KeyStatus = KeyStatus.ACTIVE

    # Lifecycle
    registered_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    not_before: Optional[datetime] = None   # RFC 7519 nbf analogue
    not_after: Optional[datetime] = None    # Key expiry; None = no expiry

    # Rotation
    superseded_by: Optional[str] = None     # key_id of the replacement key

    # Metadata
    description: Optional[str] = None
    registered_by: Optional[str] = None     # Principal.user_id of the registrant


@dataclass
class KeyRegistrationRequest:
    """Input to AgentKeyStorePort.register_key()."""
    agent_id: str
    algorithm: KeyAlgorithm
    public_key_jwk: Dict[str, Any]         # Must contain only public parameters
    description: Optional[str] = None
    not_after: Optional[datetime] = None    # Optional expiry
    registered_by: Optional[str] = None


class AgentKeyStorePort(ABC):
    """
    Port: Per-agent public key registry.

    Agents register a public key at provisioning. The DPoPValidatorPort
    calls get_key() to retrieve the current active key for proof verification.
    Key rotation follows a two-step process: register the new key, then
    revoke the old one after a grace period.

    RFC 9449 §6.1 requires the server to associate a DPoP key with a token;
    this port is the server-side registry that makes that association durable.
    """

    @abstractmethod
    def register_key(self, request: KeyRegistrationRequest) -> AgentKey:
        """
        Register a new public key for an agent.

        Raises:
            ValueError: if public_key_jwk contains private key material,
                        or if algorithm is not supported.
            KeyConflictError: if the agent already has an ACTIVE key and
                              force_rotate is not set.
        """
        pass

    @abstractmethod
    def get_key(self, agent_id: str, key_id: Optional[str] = None) -> Optional[AgentKey]:
        """
        Retrieve the agent's public key.

        If key_id is None, returns the current ACTIVE key for the agent.
        If key_id is specified, returns that specific key regardless of status.

        Returns:
            AgentKey if found, None if the agent has no registered key.
        """
        pass

    @abstractmethod
    def list_keys(
        self,
        agent_id: str,
        status: Optional[KeyStatus] = None,
    ) -> List[AgentKey]:
        """
        List all keys for an agent, optionally filtered by status.

        Returns:
            List of AgentKey ordered by registered_at descending.
        """
        pass

    @abstractmethod
    def revoke_key(self, agent_id: str, key_id: str, reason: Optional[str] = None) -> bool:
        """
        Revoke a key immediately.

        After revocation, any DPoP proof signed with this key MUST be rejected.

        Returns:
            True if the key was found and revoked, False if not found.
        """
        pass

    @abstractmethod
    def rotate_key(
        self,
        agent_id: str,
        new_key_request: KeyRegistrationRequest,
        grace_period_seconds: int = 300,
    ) -> AgentKey:
        """
        Atomically register a new key and mark the old one as ROTATING.

        The old key remains valid during the grace period to allow in-flight
        requests to complete. After the grace period, the old key is revoked.

        Returns:
            The newly registered AgentKey.
        """
        pass
