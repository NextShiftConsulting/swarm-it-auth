"""
Audit Port — structured event emission for every authorization decision.

ADR-027 Stage 5 / ADR-028 Sub-decision 6.

Standards references:
  - OpenTelemetry Semantic Conventions for Security Events (OTEL-SEC-1.0)
  - NIST SP 800-92 §4: Guide to Computer Security Log Management
  - RFC 8259 §8: UTF-8 encoding for JSON audit payloads

No implementation in this file. Adapters live in swarm_auth/adapters/:
  - Stage 6: MemoryAuditAdapter (testing)
  - Stage 6: LoggingAuditAdapter (stdout/CloudWatch)

Usage (Stage 6+):
    from swarm_auth.ports.audit_port import AuditPort, AuditEvent, AuditEventType

    class MyBroker(CredentialBrokerPort):
        def __init__(self, audit: AuditPort, ...): ...

        def vend_credential(self, principal, tool_request):
            cred = self._inner.vend_credential(principal, tool_request)
            self._audit.emit(AuditEvent(
                event_type=AuditEventType.CREDENTIAL_VENDED,
                principal_id=principal.user_id,
                ...
            ))
            return cred
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class AuditEventType(Enum):
    """Enumeration of auditable event categories."""
    # Authentication
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    TOKEN_ISSUED = "auth.token_issued"
    TOKEN_REVOKED = "auth.token_revoked"

    # Authorization
    POLICY_ALLOW = "authz.allow"
    POLICY_DENY = "authz.deny"
    SCOPE_ALLOW = "authz.scope_allow"
    SCOPE_DENY = "authz.scope_deny"

    # Credential lifecycle
    CREDENTIAL_VENDED = "credential.vended"
    CREDENTIAL_REVOKED = "credential.revoked"
    CREDENTIAL_EXPIRED = "credential.expired"
    CREDENTIAL_REFRESHED = "credential.refreshed"

    # Delegation (RFC 8693)
    DELEGATION_ACCEPTED = "delegation.accepted"
    DELEGATION_REJECTED = "delegation.rejected"

    # DPoP (RFC 9449)
    DPOP_VALID = "dpop.valid"
    DPOP_INVALID = "dpop.invalid"


@dataclass
class ActorChainSnapshot:
    """
    Immutable snapshot of an RFC 8693 act chain at the moment of an event.

    Stored verbatim in the audit log so a SIEM can reconstruct the full
    delegation path without custom mappers.
    """
    subject: str                    # JWT sub — the principal being acted for
    actor: Optional[str] = None     # JWT act.sub — the immediate acting agent
    chain_depth: int = 0            # Number of act hops (0 = no delegation)
    raw_act_claim: Optional[Dict[str, Any]] = None  # Full act claim (RFC 8693 §4)


@dataclass
class AuditEvent:
    """
    A single auditable event.

    Required fields are the minimum for a SIEM-parseable log entry.
    All optional fields SHOULD be populated when the data is available.
    """
    # Required
    event_type: AuditEventType
    principal_id: str               # Principal.user_id of the requesting principal
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # Request context
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    # Resource context
    provider: Optional[str] = None          # ProviderType.value
    action: Optional[str] = None            # ToolRequest.action
    resource: Optional[str] = None          # ToolRequest.resource (sanitized)
    constraint_id: Optional[str] = None     # ScopeConstraint.id that matched

    # Decision context
    decision_reason: Optional[str] = None
    policy_ids: List[str] = field(default_factory=list)

    # Delegation context (ADR-026 Rule 6)
    actor_chain: Optional[ActorChainSnapshot] = None

    # Extensible metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditQuery:
    """
    Filter for querying stored audit events.

    Used by read-path adapters (CloudWatch Insights, DynamoDB, etc.).
    All fields are optional — omitting a field means no filter on that dimension.
    """
    principal_id: Optional[str] = None
    event_type: Optional[AuditEventType] = None
    provider: Optional[str] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    limit: int = 100


class AuditPort(ABC):
    """
    Port: Audit event sink.

    Receives AuditEvents from every authorization decision point and persists
    them in an append-only store. All writes are fire-and-forget from the
    caller's perspective — implementations MUST NOT raise on emit() in the
    hot path (log the failure and continue).

    Adapters in Stage 6:
      - MemoryAuditAdapter: in-process list (tests only)
      - LoggingAuditAdapter: Python logging / CloudWatch
    """

    @abstractmethod
    def emit(self, event: AuditEvent) -> None:
        """
        Emit a single audit event.

        MUST NOT raise. If the underlying store is unavailable the
        implementation should log the failure internally and return normally.
        """
        pass

    @abstractmethod
    def query(self, query: AuditQuery) -> List[AuditEvent]:
        """
        Query stored audit events.

        Returns events matching all specified filter criteria, ordered
        by timestamp descending. May return an empty list — never raises.
        """
        pass
