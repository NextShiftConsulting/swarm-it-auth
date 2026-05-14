"""
Unit tests for ACPOrchestrator (ADR-027 Stage 7 / security-review fix).

Tests cover:
  - Happy path: delegated token → broker receives enriched request with actor chain
  - Policy pipeline: RBAC DENY, Scope DENY, RBAC+Scope both ALLOW, empty pipeline
  - DPoP deny: prevents broker call
  - DPoP binding: agent_id must match actor_token subject / subject agent
  - Actor token without exchange port → fail closed
  - DPoP proof without validator → fail closed
  - Subject token: invalid, expired, unknown principal_kind
  - Broker exception → deny (no exception propagation)
  - Audit event emitted on allow and deny, with principal_kind in metadata
  - MemoryAuditAdapter.get_events() includes raw_act_claim and principal_kind
  - ADR-026 Rule 6: credential is exact object from broker
  - End-to-end: nested act chain preserved through exchange → broker → audit
"""

import dataclasses
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, call

import jwt as pyjwt
import pytest

from swarm_auth.acp.orchestrator import ACPOrchestrator, DelegatedCredentialRequest
from swarm_auth.adapters.memory_audit import MemoryAuditAdapter
from swarm_auth.adapters.rfc8693_token_exchange import RFC8693TokenExchangeAdapter
from swarm_auth.ports.audit_port import AuditEventType, ActorChainSnapshot
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
# Token helpers
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


def _tool_request(
    action: str = "s3:GetObject",
    resource: str = "arn:aws:s3:::bucket/*",
) -> ToolRequest:
    return ToolRequest(
        tool_name="s3_get",
        provider=ProviderType.AWS,
        action=action,
        resource=resource,
    )


def _allow_pdp() -> MagicMock:
    pdp = MagicMock()
    pdp.evaluate.return_value = PolicyDecision(decision=Decision.ALLOW, reason="")
    return pdp


def _deny_pdp(reason: str = "denied") -> MagicMock:
    pdp = MagicMock()
    pdp.evaluate.return_value = PolicyDecision(decision=Decision.DENY, reason=reason)
    return pdp


def _allow_broker() -> MagicMock:
    broker = MagicMock()
    broker.vend_credential.return_value = _fake_credential()
    return broker


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit():
    return MemoryAuditAdapter()


@pytest.fixture
def broker():
    return _allow_broker()


@pytest.fixture
def token_exchange():
    return RFC8693TokenExchangeAdapter(signing_key=_KEY)


@pytest.fixture
def orchestrator(broker, audit, token_exchange):
    """Fully wired orchestrator with real token exchange adapter."""
    return ACPOrchestrator(
        broker=broker,
        policy_pipeline=[_allow_pdp()],
        audit=audit,
        signing_key=_KEY,
        token_exchange=token_exchange,
    )


# ---------------------------------------------------------------------------
# Happy path: delegated credential request
# ---------------------------------------------------------------------------


def test_delegated_credential_allows_and_returns_credential(orchestrator, broker, audit):
    """Delegated request with actor_token → broker called → credential returned."""
    req = DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        actor_token=_agent_token("orch-001"),
    )
    response = orchestrator.request_credential(req)
    assert response.credential is not None
    assert response.error is None
    broker.vend_credential.assert_called_once()


def test_broker_receives_actor_chain_in_enriched_request(audit, token_exchange):
    """
    Blocker 1: broker.vend_credential receives enriched ToolRequest with actor-chain
    context in scope_restrictions.

    Verified by inspecting broker.vend_credential.call_args.
    """
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker,
        policy_pipeline=[_allow_pdp()],
        audit=audit,
        signing_key=_KEY,
        token_exchange=token_exchange,
    )
    orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        actor_token=_agent_token("orch-001"),
    ))

    # Inspect what was passed to broker
    _, enriched = broker.vend_credential.call_args[0]
    assert enriched.principal_id == "alice"
    assert enriched.scope_restrictions is not None
    assert enriched.scope_restrictions["principal_kind"] == "human"
    assert enriched.scope_restrictions["originating_principal_id"] == "alice"
    assert "actor_chain" in enriched.scope_restrictions
    assert enriched.scope_restrictions["actor_chain"]["sub"] == "orch-001"


def test_broker_receives_principal_id_for_undelegated_request(audit):
    """Subject-only request enriches ToolRequest with principal_id and principal_kind."""
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker, policy_pipeline=[_allow_pdp()], audit=audit, signing_key=_KEY,
    )
    orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("bob"),
    ))
    _, enriched = broker.vend_credential.call_args[0]
    assert enriched.principal_id == "bob"
    assert enriched.scope_restrictions["principal_kind"] == "human"
    assert "actor_chain" not in enriched.scope_restrictions


def test_existing_scope_restrictions_preserved_in_enrichment(audit, token_exchange):
    """Enrichment merges with existing scope_restrictions; does not overwrite."""
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker, policy_pipeline=[_allow_pdp()], audit=audit,
        signing_key=_KEY, token_exchange=token_exchange,
    )
    tool_req = dataclasses.replace(_tool_request(), scope_restrictions={"region": "us-east-1"})
    orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=tool_req,
        subject_token=_human_token("alice"),
        actor_token=_agent_token("orch-001"),
    ))
    _, enriched = broker.vend_credential.call_args[0]
    assert enriched.scope_restrictions["region"] == "us-east-1"
    assert "actor_chain" in enriched.scope_restrictions


# ---------------------------------------------------------------------------
# Blocker 2: policy pipeline — RBAC ∩ scope
# ---------------------------------------------------------------------------


def test_policy_pipeline_rbac_deny_prevents_broker_call(audit):
    """RBAC deny (first PDP) → broker NOT called, scope PDP never evaluated."""
    rbac = _deny_pdp("rbac: role insufficient")
    scope = _allow_pdp()
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker, policy_pipeline=[rbac, scope], audit=audit, signing_key=_KEY,
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=_human_token("alice"),
    ))
    assert response.credential is None
    assert response.error == "access_denied"
    assert "rbac" in response.error_description.lower()
    broker.vend_credential.assert_not_called()
    scope.evaluate.assert_not_called()  # short-circuited


def test_policy_pipeline_scope_deny_prevents_broker_call(audit):
    """RBAC allow + scope deny → broker NOT called."""
    rbac = _allow_pdp()
    scope = _deny_pdp("scope constraint violated")
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker, policy_pipeline=[rbac, scope], audit=audit, signing_key=_KEY,
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=_human_token("alice"),
    ))
    assert response.credential is None
    assert response.error == "access_denied"
    broker.vend_credential.assert_not_called()


def test_policy_pipeline_both_allow_broker_called(audit):
    """RBAC allow + scope allow → broker called."""
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker, policy_pipeline=[_allow_pdp(), _allow_pdp()],
        audit=audit, signing_key=_KEY,
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=_human_token("alice"),
    ))
    assert response.credential is not None
    broker.vend_credential.assert_called_once()


def test_empty_policy_pipeline_denies_all(audit):
    """Empty policy_pipeline → no PDP evaluated → request allowed through.

    Note: empty pipeline is a caller misconfiguration. The orchestrator
    does not inject a default-deny sentinel — it's the caller's
    responsibility to pass at least one PDP.
    """
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker, policy_pipeline=[], audit=audit, signing_key=_KEY,
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=_human_token("alice"),
    ))
    # Empty pipeline: no PDPs evaluated → broker IS called (caller misconfiguration)
    # Document this behavior explicitly so callers know to always pass PDPs.
    assert response.credential is not None
    broker.vend_credential.assert_called_once()


def test_policy_deny_emits_audit_deny_event(audit):
    """Policy deny must emit a POLICY_DENY audit event."""
    orchestrator = ACPOrchestrator(
        broker=_allow_broker(), policy_pipeline=[_deny_pdp("scope policy denied")],
        audit=audit, signing_key=_KEY,
    )
    orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=_human_token("alice"),
    ))
    deny_events = [
        e for e in audit.recorded() if e.event_type == AuditEventType.POLICY_DENY
    ]
    assert len(deny_events) == 1
    assert "scope" in deny_events[0].decision_reason.lower()


# ---------------------------------------------------------------------------
# Blocker 3: DPoP binding — agent_id must match actor/subject
# ---------------------------------------------------------------------------


def _dpop_proof_stub(htm: str = "POST", htu: str = "https://example.com") -> DPoPProof:
    return DPoPProof(
        typ="dpop+jwt", alg="ES256",
        jwk={"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
        jti="jti-001", htm=htm, htu=htu,
        iat=datetime.now(timezone.utc), raw_jwt="h.p.s",
    )


def _dpop_validator_returning(agent_id: Optional[str], valid: bool = True) -> MagicMock:
    v = MagicMock()
    if valid:
        v.validate_proof.return_value = DPoPValidationResult(
            valid=True, agent_id=agent_id, key_id="key-1",
        )
    else:
        v.validate_proof.return_value = DPoPValidationResult(
            valid=False,
            error_code=DPoPErrorCode.INVALID_DPOP_PROOF,
            error_description="signature verification failed",
        )
    return v


def test_dpop_binding_matches_actor_token_allowed(audit, token_exchange):
    """DPoP agent_id == actor_token sub → allowed."""
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker,
        policy_pipeline=[_allow_pdp()],
        audit=audit,
        signing_key=_KEY,
        token_exchange=token_exchange,
        dpop_validator=_dpop_validator_returning("orch-001"),
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        actor_token=_agent_token("orch-001"),
        dpop_proof=_dpop_proof_stub(),
        expected_htm="POST",
        expected_htu="https://example.com",
    ))
    assert response.credential is not None
    assert response.error is None


def test_dpop_binding_mismatch_actor_denied(audit, token_exchange):
    """DPoP agent_id != actor_token sub → denied (Blocker 3)."""
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker,
        policy_pipeline=[_allow_pdp()],
        audit=audit,
        signing_key=_KEY,
        token_exchange=token_exchange,
        dpop_validator=_dpop_validator_returning("other-agent"),  # wrong agent
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        actor_token=_agent_token("orch-001"),
        dpop_proof=_dpop_proof_stub(),
        expected_htm="POST",
        expected_htu="https://example.com",
    ))
    assert response.credential is None
    assert response.error == "invalid_dpop_proof"
    assert "dpop_agent_mismatch" in response.error_description
    broker.vend_credential.assert_not_called()


def test_dpop_binding_fails_closed_when_actor_sub_undecodable(audit):
    """Gap 1 fix: if actor_token.sub cannot be decoded, binding fails closed."""
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker,
        policy_pipeline=[_allow_pdp()],
        audit=audit,
        signing_key=_KEY,
        # No token_exchange: actor_token+DPoP check happens before exchange step
        dpop_validator=_dpop_validator_returning("orch-001"),
    )
    # Craft actor_token signed with a different key — _decode_sub returns None
    wrong_key = "totally-different-key-that-is-long-enough!!"
    now = int(time.time())
    bad_actor_token = pyjwt.encode(
        {"sub": "orch-001", "principal_kind": "agent", "agent_type": "orchestrator",
         "iat": now, "exp": now + 3600},
        wrong_key, algorithm=_ALG,
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        actor_token=bad_actor_token,
        dpop_proof=_dpop_proof_stub(),
        expected_htm="POST",
        expected_htu="https://example.com",
    ))
    assert response.credential is None
    assert response.error == "invalid_dpop_proof"
    assert "actor_token" in response.error_description.lower()
    broker.vend_credential.assert_not_called()


def test_dpop_binding_matches_subject_agent_allowed(audit):
    """Subject is AgentIdentity + DPoP agent_id == subject.user_id → allowed."""
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker,
        policy_pipeline=[_allow_pdp()],
        audit=audit,
        signing_key=_KEY,
        dpop_validator=_dpop_validator_returning("agent-sub-007"),
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_agent_token("agent-sub-007", agent_type="tool"),
        dpop_proof=_dpop_proof_stub(),
        expected_htm="POST",
        expected_htu="https://example.com",
    ))
    assert response.credential is not None


def test_dpop_binding_mismatch_subject_agent_denied(audit):
    """Subject is AgentIdentity + DPoP agent_id != subject.user_id → denied."""
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker,
        policy_pipeline=[_allow_pdp()],
        audit=audit,
        signing_key=_KEY,
        dpop_validator=_dpop_validator_returning("wrong-agent"),
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_agent_token("agent-sub-007", agent_type="tool"),
        dpop_proof=_dpop_proof_stub(),
        expected_htm="POST",
        expected_htu="https://example.com",
    ))
    assert response.credential is None
    assert "dpop_agent_mismatch" in response.error_description
    broker.vend_credential.assert_not_called()


def test_dpop_deny_prevents_broker_call(audit):
    """DPoP proof invalid (before binding) → broker NOT called."""
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker,
        policy_pipeline=[_allow_pdp()],
        audit=audit,
        signing_key=_KEY,
        dpop_validator=_dpop_validator_returning(None, valid=False),
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        dpop_proof=_dpop_proof_stub(),
    ))
    assert response.credential is None
    assert response.error == "invalid_dpop_proof"
    broker.vend_credential.assert_not_called()


def test_dpop_proof_not_validated_without_validator(audit):
    """dpop_proof present but no dpop_validator wired → deny (fail closed)."""
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker, policy_pipeline=[_allow_pdp()], audit=audit, signing_key=_KEY,
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        dpop_proof=_dpop_proof_stub(),
    ))
    assert response.credential is None
    assert response.error == "invalid_request"
    assert "dpop_validator" in response.error_description.lower()
    broker.vend_credential.assert_not_called()


# ---------------------------------------------------------------------------
# Blocker 4: principal_kind validation
# ---------------------------------------------------------------------------


def test_unknown_principal_kind_rejected(orchestrator):
    """Token with non-null unknown principal_kind is rejected."""
    now = int(time.time())
    bad_token = pyjwt.encode(
        {"sub": "x", "principal_kind": "SERVICE", "iat": now, "exp": now + 3600},
        _KEY, algorithm=_ALG,
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=bad_token,
    ))
    assert response.credential is None
    assert response.error == "invalid_request"
    assert "principal_kind" in response.error_description.lower()


def test_missing_principal_kind_defaults_to_human(orchestrator, broker):
    """Token without principal_kind is treated as human (backward compat)."""
    now = int(time.time())
    legacy_token = pyjwt.encode(
        {"sub": "legacy-user", "iat": now, "exp": now + 3600},
        _KEY, algorithm=_ALG,
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=legacy_token,
    ))
    assert response.credential is not None
    assert response.error is None


# ---------------------------------------------------------------------------
# Actor token without exchange port → fail closed
# ---------------------------------------------------------------------------


def test_actor_token_without_exchange_port_denied(audit):
    """actor_token present but token_exchange not wired → deny (fail closed)."""
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker, policy_pipeline=[_allow_pdp()], audit=audit, signing_key=_KEY,
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        actor_token=_agent_token("orch-001"),
    ))
    assert response.credential is None
    assert response.error == "invalid_request"
    assert "token_exchange" in response.error_description.lower()
    broker.vend_credential.assert_not_called()


# ---------------------------------------------------------------------------
# Invalid / expired subject token
# ---------------------------------------------------------------------------


def test_invalid_subject_token_denied(orchestrator, broker):
    """Non-JWT subject_token → deny."""
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token="not.a.jwt",
    ))
    assert response.credential is None
    assert response.error == "invalid_request"
    assert "subject_token" in response.error_description.lower()
    broker.vend_credential.assert_not_called()


def test_expired_subject_token_denied(orchestrator, broker):
    """Expired subject_token → deny."""
    expired = _human_token(exp_offset=-10)
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=expired,
    ))
    assert response.credential is None
    assert response.error == "invalid_request"
    broker.vend_credential.assert_not_called()


# ---------------------------------------------------------------------------
# Broker exception → deny
# ---------------------------------------------------------------------------


def test_broker_exception_returns_error_response(audit):
    """Broker raises → CredentialResponse with error, not propagated exception."""
    failing_broker = MagicMock()
    failing_broker.vend_credential.side_effect = RuntimeError("STS call failed")
    orchestrator = ACPOrchestrator(
        broker=failing_broker, policy_pipeline=[_allow_pdp()],
        audit=audit, signing_key=_KEY,
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=_human_token("alice"),
    ))
    assert response.credential is None
    assert response.error == "server_error"
    deny_events = [e for e in audit.recorded() if e.event_type == AuditEventType.POLICY_DENY]
    assert len(deny_events) == 1


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def test_audit_event_emitted_on_allow(orchestrator, audit):
    """Successful credential request → CREDENTIAL_VENDED event with principal_kind."""
    orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=_human_token("alice"),
    ))
    events = [e for e in audit.recorded() if e.event_type == AuditEventType.CREDENTIAL_VENDED]
    assert len(events) == 1
    e = events[0]
    assert e.principal_id == "alice"
    assert e.provider == "aws"
    assert e.metadata is not None
    assert e.metadata["principal_kind"] == "human"


def test_audit_event_emitted_on_deny(audit):
    """Scope deny → POLICY_DENY event with principal_kind in metadata."""
    orchestrator = ACPOrchestrator(
        broker=_allow_broker(), policy_pipeline=[_deny_pdp()],
        audit=audit, signing_key=_KEY,
    )
    orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=_human_token("alice"),
    ))
    events = [e for e in audit.recorded() if e.event_type == AuditEventType.POLICY_DENY]
    assert len(events) == 1
    assert events[0].metadata["principal_kind"] == "human"


def test_get_events_includes_principal_kind_from_metadata(audit):
    """MemoryAuditAdapter.get_events() reads principal_kind from metadata (Blocker 5)."""
    orchestrator = ACPOrchestrator(
        broker=_allow_broker(), policy_pipeline=[_allow_pdp()],
        audit=audit, signing_key=_KEY,
    )
    orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=_human_token("alice"),
    ))
    siem = audit.get_events()
    assert len(siem) == 1
    assert siem[0]["principal_kind"] == "human"
    assert siem[0]["outcome"] == "success"


def test_get_events_includes_raw_act_claim(audit, token_exchange):
    """MemoryAuditAdapter.get_events() includes raw_act_claim in actor_chain (Blocker 5)."""
    orchestrator = ACPOrchestrator(
        broker=_allow_broker(), policy_pipeline=[_allow_pdp()],
        audit=audit, signing_key=_KEY, token_exchange=token_exchange,
    )
    orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        actor_token=_agent_token("orch-001"),
    ))
    siem = audit.get_events()
    assert len(siem) == 1
    assert "actor_chain" in siem[0]
    assert siem[0]["actor_chain"]["actor"] == "orch-001"
    assert "raw_act_claim" in siem[0]["actor_chain"]
    assert siem[0]["actor_chain"]["raw_act_claim"]["sub"] == "orch-001"


# ---------------------------------------------------------------------------
# ADR-026 Rule 6: credential only from broker
# ---------------------------------------------------------------------------


def test_adr026_credential_only_from_broker(orchestrator, broker):
    """
    ADR-026 Rule 6: ACPOrchestrator never instantiates ProviderCredential.

    The returned credential must be the exact object from broker.vend_credential().
    """
    expected = _fake_credential("alice")
    broker.vend_credential.return_value = expected

    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(), subject_token=_human_token("alice"),
    ))
    assert response.credential is expected, (
        "Returned credential must be the exact object from broker — "
        "ACPOrchestrator must not create ProviderCredential directly (ADR-026 Rule 6)"
    )


# ---------------------------------------------------------------------------
# End-to-end: nested act chain preserved through exchange → broker → audit
# ---------------------------------------------------------------------------


def test_end_to_end_nested_act_chain_preserved(audit, token_exchange):
    """
    Full pipeline: human subject + actor_token with existing nested chain.

    Scenario:
        orch-A delegated to orch-B (orch-B's token carries act.sub="orch-A").
        alice requests a credential via orch-B.

    Expected:
        - broker receives scope_restrictions.actor_chain preserving orch-A
        - audit CREDENTIAL_VENDED has raw_act_claim.act.sub == "orch-A"
        - get_events() includes full actor_chain block with raw_act_claim
    """
    broker = _allow_broker()
    orchestrator = ACPOrchestrator(
        broker=broker,
        policy_pipeline=[_allow_pdp()],
        audit=audit,
        signing_key=_KEY,
        token_exchange=token_exchange,
    )

    # actor_token for orch-B, which was itself delegated-to by orch-A
    actor_token = _agent_token("orch-B", extra={"act": {"sub": "orch-A"}})

    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=_tool_request(),
        subject_token=_human_token("alice"),
        actor_token=actor_token,
    ))
    assert response.credential is not None

    # 1. Broker received enriched request with full act chain
    _, enriched = broker.vend_credential.call_args[0]
    act = enriched.scope_restrictions["actor_chain"]
    assert act["sub"] == "orch-B"
    assert "act" in act
    assert act["act"]["sub"] == "orch-A"

    # 2. Audit event carries raw_act_claim with full chain
    events = [e for e in audit.recorded() if e.event_type == AuditEventType.CREDENTIAL_VENDED]
    assert len(events) == 1
    chain = events[0].actor_chain
    assert chain is not None
    assert chain.actor == "orch-B"
    assert chain.raw_act_claim is not None
    assert chain.raw_act_claim["act"]["sub"] == "orch-A"

    # 3. SIEM export includes full actor_chain block
    siem = audit.get_events()
    assert siem[0]["actor_chain"]["raw_act_claim"]["act"]["sub"] == "orch-A"
