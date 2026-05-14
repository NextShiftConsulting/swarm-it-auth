"""
Unit tests for ACPOrchestrator (ADR-027 Stage 7).

Tests cover:
  - Happy path: delegated token → broker call with act chain context
  - Scope deny: prevents broker call, emits DENY audit event
  - DPoP deny: prevents broker call, emits DENY audit event
  - Missing token_exchange: actor_token present but port not wired → deny
  - Missing dpop_validator: dpop_proof present but port not wired → deny
  - Subject token invalid / expired → deny
  - Broker exception → deny
  - Audit event emitted on allow and on deny
  - ADR-026 Rule 6: credential comes from broker, not ACPOrchestrator
"""

import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
from unittest.mock import MagicMock

import jwt as pyjwt
import pytest

from swarm_auth.acp.orchestrator import ACPOrchestrator, DelegatedCredentialRequest
from swarm_auth.adapters.memory_audit import MemoryAuditAdapter
from swarm_auth.adapters.rfc8693_token_exchange import RFC8693TokenExchangeAdapter
from swarm_auth.acp.adapters.scope_policy_adapter import ScopePolicyAdapter, ScopeConstraint
from swarm_auth.ports.audit_port import AuditEventType
from swarm_auth.ports.credential_broker_port import ProviderCredential, ProviderType, ToolRequest
from swarm_auth.ports.dpop_validator_port import (
    DPoPErrorCode,
    DPoPProof,
    DPoPValidationResult,
)
from swarm_auth.ports.policy_port import Decision, PolicyDecision

_KEY = "test-orchestrator-signing-key-32b!!"
_ALG = "HS256"


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _human_token(sub: str = "alice", exp_offset: int = 3600) -> str:
    now = int(time.time())
    return pyjwt.encode(
        {"sub": sub, "principal_kind": "human", "iat": now, "exp": now + exp_offset},
        _KEY, algorithm=_ALG,
    )


def _agent_token(
    sub: str = "orch-001",
    agent_type: str = "orchestrator",
    exp_offset: int = 3600,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    now = int(time.time())
    payload: Dict[str, Any] = {
        "sub": sub,
        "principal_kind": "agent",
        "agent_type": agent_type,
        "iat": now,
        "exp": now + exp_offset,
    }
    if extra:
        payload.update(extra)
    return pyjwt.encode(payload, _KEY, algorithm=_ALG)


def _fake_credential(principal_id: str = "alice") -> ProviderCredential:
    return ProviderCredential(
        provider=ProviderType.AWS,
        credential_type="aws_sts",
        credentials={"access_key": "AKIA...", "secret_key": "abc", "session_token": "tok"},
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        scope="s3:GetObject",
        issued_to=principal_id,
    )


def _tool_request(action: str = "s3:GetObject", resource: str = "arn:aws:s3:::bucket/*") -> ToolRequest:
    return ToolRequest(
        tool_name="s3_get",
        provider=ProviderType.AWS,
        action=action,
        resource=resource,
    )


@pytest.fixture
def audit():
    return MemoryAuditAdapter()


@pytest.fixture
def allow_broker(request):
    """Mock broker that always allows and returns a fake credential."""
    broker = MagicMock()
    broker.vend_credential.return_value = _fake_credential()
    return broker


@pytest.fixture
def deny_scope_policy():
    """Mock PolicyDecisionPoint that always denies."""
    policy = MagicMock()
    policy.evaluate.return_value = PolicyDecision(
        decision=Decision.DENY,
        reason="scope constraint violated",
    )
    return policy


@pytest.fixture
def allow_scope_policy():
    """Mock PolicyDecisionPoint that always allows."""
    policy = MagicMock()
    policy.evaluate.return_value = PolicyDecision(
        decision=Decision.ALLOW,
        reason="",
    )
    return policy


@pytest.fixture
def token_exchange():
    return RFC8693TokenExchangeAdapter(signing_key=_KEY)


@pytest.fixture
def orchestrator(allow_broker, allow_scope_policy, audit, token_exchange):
    """Fully wired orchestrator with real token exchange adapter."""
    return ACPOrchestrator(
        broker=allow_broker,
        scope_policy=allow_scope_policy,
        audit=audit,
        signing_key=_KEY,
        token_exchange=token_exchange,
    )


# ---------------------------------------------------------------------------
# Happy path: delegated credential request
# ---------------------------------------------------------------------------


def test_delegated_credential_allows_and_returns_credential(orchestrator, allow_broker, audit):
    """Delegated request with actor_token → broker called → credential returned."""
    req = DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        actor_token=_agent_token("orch-001"),
    )
    response = orchestrator.request_credential(req)
    assert response.credential is not None
    assert response.error is None
    allow_broker.vend_credential.assert_called_once()


def test_delegated_token_broker_call_includes_act_chain_context(
    orchestrator, allow_broker, audit
):
    """
    Delegated token → token exchange produces act claim → audit event records
    actor chain with correct depth and actor sub.

    Contract: ADR-027 Stage 7 — broker call includes actor chain context via
    audit trail (ActorChainSnapshot in CREDENTIAL_VENDED event).
    """
    req = DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        actor_token=_agent_token("orch-001"),
    )
    response = orchestrator.request_credential(req)
    assert response.credential is not None

    # Audit event must record the actor chain
    allow_events = [
        e for e in audit.recorded()
        if e.event_type == AuditEventType.CREDENTIAL_VENDED
    ]
    assert len(allow_events) == 1
    chain = allow_events[0].actor_chain
    assert chain is not None
    assert chain.actor == "orch-001"
    assert chain.subject == "alice"
    assert chain.chain_depth >= 1


def test_no_actor_token_no_act_chain(orchestrator, allow_broker, audit):
    """Subject-only request (no actor_token) → credential issued, no act chain in audit."""
    req = DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
    )
    response = orchestrator.request_credential(req)
    assert response.credential is not None

    events = [e for e in audit.recorded() if e.event_type == AuditEventType.CREDENTIAL_VENDED]
    assert len(events) == 1
    # No delegation → no actor chain in audit
    assert events[0].actor_chain is None


# ---------------------------------------------------------------------------
# Scope deny prevents broker call
# ---------------------------------------------------------------------------


def test_scope_deny_prevents_broker_call(deny_scope_policy, allow_broker, audit):
    """Scope policy denies → broker.vend_credential() NOT called → deny response."""
    orchestrator = ACPOrchestrator(
        broker=allow_broker,
        scope_policy=deny_scope_policy,
        audit=audit,
        signing_key=_KEY,
    )
    req = DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
    )
    response = orchestrator.request_credential(req)
    assert response.credential is None
    assert response.error == "access_denied"
    allow_broker.vend_credential.assert_not_called()


def test_scope_deny_emits_audit_deny_event(deny_scope_policy, allow_broker, audit):
    """Scope deny must emit a POLICY_DENY audit event."""
    orchestrator = ACPOrchestrator(
        broker=allow_broker,
        scope_policy=deny_scope_policy,
        audit=audit,
        signing_key=_KEY,
    )
    orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
    ))
    deny_events = [
        e for e in audit.recorded() if e.event_type == AuditEventType.POLICY_DENY
    ]
    assert len(deny_events) == 1
    assert "scope" in deny_events[0].decision_reason.lower()


# ---------------------------------------------------------------------------
# DPoP deny prevents broker call
# ---------------------------------------------------------------------------


def test_dpop_deny_prevents_broker_call(allow_scope_policy, allow_broker, audit):
    """DPoP proof invalid → broker NOT called → deny response."""
    dpop_validator = MagicMock()
    dpop_validator.validate_proof.return_value = DPoPValidationResult(
        valid=False,
        error_code=DPoPErrorCode.INVALID_DPOP_PROOF,
        error_description="signature verification failed",
    )
    orchestrator = ACPOrchestrator(
        broker=allow_broker,
        scope_policy=allow_scope_policy,
        audit=audit,
        signing_key=_KEY,
        dpop_validator=dpop_validator,
    )

    # Build a minimal DPoP proof (raw_jwt content doesn't matter — validator is mocked)
    dpop_proof = DPoPProof(
        typ="dpop+jwt",
        alg="ES256",
        jwk={"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
        jti="test-jti",
        htm="POST",
        htu="https://auth.swarms.network/credentials",
        iat=datetime.now(timezone.utc),
        raw_jwt="header.payload.sig",
    )
    req = DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        dpop_proof=dpop_proof,
        expected_htm="POST",
        expected_htu="https://auth.swarms.network/credentials",
    )
    response = orchestrator.request_credential(req)
    assert response.credential is None
    assert response.error == "invalid_dpop_proof"
    allow_broker.vend_credential.assert_not_called()


def test_dpop_proof_not_validated_without_validator(allow_scope_policy, allow_broker, audit):
    """dpop_proof present but no dpop_validator wired → deny (fail closed)."""
    orchestrator = ACPOrchestrator(
        broker=allow_broker,
        scope_policy=allow_scope_policy,
        audit=audit,
        signing_key=_KEY,
        # dpop_validator intentionally omitted
    )
    dpop_proof = DPoPProof(
        typ="dpop+jwt", alg="ES256",
        jwk={"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
        jti="jti", htm="POST", htu="https://example.com",
        iat=datetime.now(timezone.utc), raw_jwt="h.p.s",
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        dpop_proof=dpop_proof,
    ))
    assert response.credential is None
    assert response.error == "invalid_request"
    assert "dpop_validator" in response.error_description.lower()
    allow_broker.vend_credential.assert_not_called()


# ---------------------------------------------------------------------------
# Actor token without exchange port → deny
# ---------------------------------------------------------------------------


def test_actor_token_without_exchange_port_denied(allow_scope_policy, allow_broker, audit):
    """actor_token present but token_exchange not wired → deny (fail closed)."""
    orchestrator = ACPOrchestrator(
        broker=allow_broker,
        scope_policy=allow_scope_policy,
        audit=audit,
        signing_key=_KEY,
        # token_exchange intentionally omitted
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        actor_token=_agent_token("orch-001"),
    ))
    assert response.credential is None
    assert response.error == "invalid_request"
    assert "token_exchange" in response.error_description.lower()
    allow_broker.vend_credential.assert_not_called()


# ---------------------------------------------------------------------------
# Invalid / expired subject token
# ---------------------------------------------------------------------------


def test_invalid_subject_token_denied(orchestrator, allow_broker):
    """Non-JWT subject_token → deny."""
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token="not.a.jwt",
    ))
    assert response.credential is None
    assert response.error == "invalid_request"
    assert "subject_token" in response.error_description.lower()
    allow_broker.vend_credential.assert_not_called()


def test_expired_subject_token_denied(orchestrator, allow_broker):
    """Expired subject_token → deny."""
    expired = _human_token(exp_offset=-10)
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=expired,
    ))
    assert response.credential is None
    assert response.error == "invalid_request"
    allow_broker.vend_credential.assert_not_called()


# ---------------------------------------------------------------------------
# Broker exception → deny
# ---------------------------------------------------------------------------


def test_broker_exception_returns_error_response(allow_scope_policy, audit):
    """Broker raises → CredentialResponse with error, not propagated exception."""
    failing_broker = MagicMock()
    failing_broker.vend_credential.side_effect = RuntimeError("STS call failed")
    orchestrator = ACPOrchestrator(
        broker=failing_broker,
        scope_policy=allow_scope_policy,
        audit=audit,
        signing_key=_KEY,
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
    ))
    assert response.credential is None
    assert response.error == "server_error"
    # Audit must still record the deny event
    deny_events = [e for e in audit.recorded() if e.event_type == AuditEventType.POLICY_DENY]
    assert len(deny_events) == 1


# ---------------------------------------------------------------------------
# Audit event emitted on allow and deny
# ---------------------------------------------------------------------------


def test_audit_event_emitted_on_allow(orchestrator, audit):
    """Successful credential request → CREDENTIAL_VENDED event in audit log."""
    orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
    ))
    allow_events = [
        e for e in audit.recorded() if e.event_type == AuditEventType.CREDENTIAL_VENDED
    ]
    assert len(allow_events) == 1
    assert allow_events[0].principal_id == "alice"
    assert allow_events[0].provider == "aws"


def test_audit_event_emitted_on_deny(deny_scope_policy, allow_broker, audit):
    """Scope deny → POLICY_DENY event in audit log."""
    orchestrator = ACPOrchestrator(
        broker=allow_broker,
        scope_policy=deny_scope_policy,
        audit=audit,
        signing_key=_KEY,
    )
    orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
    ))
    deny_events = [
        e for e in audit.recorded() if e.event_type == AuditEventType.POLICY_DENY
    ]
    assert len(deny_events) == 1


# ---------------------------------------------------------------------------
# ADR-026 Rule 6: credential only from broker
# ---------------------------------------------------------------------------


def test_adr026_credential_only_from_broker(orchestrator):
    """
    ADR-026 Rule 6: ACPOrchestrator never instantiates ProviderCredential.

    The returned credential must be the exact object returned by
    broker.vend_credential() — not a copy, re-wrap, or new instance.
    """
    expected = _fake_credential("alice")
    orchestrator._broker.vend_credential.return_value = expected

    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
    ))
    assert response.credential is expected, (
        "Returned credential must be the exact object from broker — "
        "ACPOrchestrator must not create ProviderCredential directly (ADR-026 Rule 6)"
    )
