"""
Stage 0 xfail: Audit chain and SIEM-parseable JSON.

Stage 7 status:
  - test_three_hop_act_chain_recorded_in_audit_log: CONVERTED — Stage 7
  - test_audit_event_schema_is_siem_parseable:      CONVERTED — Stage 7

Stage 8 status:
  - test_audit_port_is_required_constructor_argument: CONVERTED — Stage 8
    (rewritten to test canonical swarm_auth.ports.audit_port path)

Contract (ADR-028 SD-1, SD-2):
- A three-hop act chain (human -> orchestrator -> tool) is recorded in
  MemoryAuditAdapter as structured AuditEvent objects.
- Each event is SIEM-parseable: get_events() returns JSON-serializable dicts
  with all required SIEM fields present.
- principal_kind is always "human" or "agent" — never SERVICE (ADR-027 Gap 1 fix).
"""

import json

import pytest


def test_three_hop_act_chain_recorded_in_audit_log() -> None:
    """
    Three-hop delegation chain (human -> orchestrator -> tool) emits
    structured AuditEvents via MemoryAuditAdapter.

    Chain:
        human "alice" (subject) delegates to
        "orch-001" (actor, chain_depth=1) which delegates to
        "tool-001" (actor, chain_depth=2) — credential vended at chain_depth=3

    Success criteria:
    1. MemoryAuditAdapter records one event per delegation hop
    2. Events carry ActorChainSnapshot with correct depth and actor subs
    3. raw_act_claim is preserved in deep-hop events (data loss check)
    4. No data loss: subject, actor.sub, actor.actor.sub all present
    5. All events are JSON-serializable via LoggingAuditAdapter._to_dict()

    Contract reference: ADR-027 Gap 4, ADR-028 SD-1 (principal_kind discriminator)
    """
    from swarm_auth.adapters.memory_audit import MemoryAuditAdapter
    from swarm_auth.adapters.logging_audit import LoggingAuditAdapter
    from swarm_auth.ports.audit_port import AuditEvent, AuditEventType, ActorChainSnapshot

    audit = MemoryAuditAdapter()

    # Hop 1: human alice delegates authority to orch-001
    audit.emit(AuditEvent(
        event_type=AuditEventType.DELEGATION_ACCEPTED,
        principal_id="alice",
        actor_chain=ActorChainSnapshot(
            subject="alice",
            actor="orch-001",
            chain_depth=1,
        ),
    ))

    # Hop 2: orch-001 re-delegates to tool-001 (two-hop chain)
    audit.emit(AuditEvent(
        event_type=AuditEventType.DELEGATION_ACCEPTED,
        principal_id="orch-001",
        actor_chain=ActorChainSnapshot(
            subject="orch-001",
            actor="tool-001",
            chain_depth=2,
            raw_act_claim={"sub": "tool-001", "act": {"sub": "orch-001"}},
        ),
    ))

    # Hop 3: credential vended to tool-001 at the end of the chain
    audit.emit(AuditEvent(
        event_type=AuditEventType.CREDENTIAL_VENDED,
        principal_id="tool-001",
        provider="aws",
        resource="arn:aws:s3:::swarm-data/*",
        actor_chain=ActorChainSnapshot(
            subject="alice",
            actor="tool-001",
            chain_depth=3,
            raw_act_claim={
                "sub": "tool-001",
                "act": {"sub": "orch-001", "act": {"sub": "alice"}},
            },
        ),
    ))

    events = audit.recorded()
    assert len(events) == 3, f"Expected 3 events, got {len(events)}"

    # Chain depth progression
    chain_events = [e for e in events if e.actor_chain is not None]
    depths = [e.actor_chain.chain_depth for e in chain_events]
    assert depths == [1, 2, 3], f"Expected depths [1,2,3], got {depths}"

    # All actors present throughout the chain
    actors = [e.actor_chain.actor for e in chain_events]
    assert "orch-001" in actors
    assert "tool-001" in actors

    # raw_act_claim preserved in deep-hop events (no data loss)
    last = events[-1]
    assert last.actor_chain.raw_act_claim is not None
    assert last.actor_chain.raw_act_claim["sub"] == "tool-001"
    assert last.actor_chain.raw_act_claim["act"]["sub"] == "orch-001"
    assert last.actor_chain.raw_act_claim["act"]["act"]["sub"] == "alice"

    # Every event is JSON-serializable (SIEM requirement — RFC 8259)
    for event in events:
        d = LoggingAuditAdapter._to_dict(event)
        serialized = json.dumps(d, default=str)
        parsed = json.loads(serialized)
        assert "event_type" in parsed
        assert "principal_id" in parsed
        assert "timestamp" in parsed


def test_audit_event_schema_is_siem_parseable() -> None:
    """
    Each audit event from MemoryAuditAdapter.get_events() is valid SIEM-parseable JSON.

    Required fields per event:
        - timestamp: ISO-8601 UTC
        - event_type: str (e.g., "delegation.accepted", "credential.vended")
        - principal_kind: "human" | "agent" (ADR-028 SD-1 discriminator)
        - subject: str (sub claim of the subject token)
        - actor: str | None (sub claim of the acting agent, if delegation present)
        - resource: str | None (RFC 8707 resource indicator, if present)
        - outcome: "success" | "failure"
        - reason: str | None (failure reason)

    Success criteria:
    1. MemoryAuditAdapter.get_events() returns a list of dicts
    2. Each dict passes json.dumps() without error
    3. Each dict has all required SIEM fields
    4. principal_kind is always "human" or "agent" — never SERVICE (ADR-027 Gap 1 fix)

    Contract reference: ADR-027 Gap 1 (SERVICE role conflation), ADR-028 SD-1
    """
    from swarm_auth.adapters.memory_audit import MemoryAuditAdapter
    from swarm_auth.ports.audit_port import AuditEvent, AuditEventType, ActorChainSnapshot

    REQUIRED_FIELDS = {
        "timestamp", "event_type", "principal_kind",
        "subject", "actor", "resource", "outcome", "reason",
    }

    audit = MemoryAuditAdapter()

    # Emit a delegation event to exercise the SIEM field schema
    audit.emit(AuditEvent(
        event_type=AuditEventType.DELEGATION_ACCEPTED,
        principal_id="alice",
        resource="arn:aws:s3:::swarm-data/*",
        actor_chain=ActorChainSnapshot(
            subject="alice",
            actor="orch-001",
            chain_depth=1,
        ),
    ))

    # Emit a deny event to verify outcome=failure mapping
    audit.emit(AuditEvent(
        event_type=AuditEventType.POLICY_DENY,
        principal_id="alice",
        decision_reason="scope policy denied",
    ))

    events = audit.get_events()
    assert len(events) == 2

    for event in events:
        # Must be JSON-serializable (RFC 8259)
        serialized = json.dumps(event)
        parsed = json.loads(serialized)

        # All required SIEM fields present
        missing = REQUIRED_FIELDS - set(parsed.keys())
        assert not missing, f"Audit event missing required SIEM fields: {missing}"

        # principal_kind must be "human" or "agent" — never SERVICE (ADR-027 Gap 1)
        assert parsed["principal_kind"] in ("human", "agent"), (
            f"principal_kind must be 'human' or 'agent', "
            f"got {parsed['principal_kind']!r}. "
            "SERVICE is not a valid principal_kind (ADR-027 Gap 1)."
        )

    # Verify outcome field mapping
    allow_event = events[0]  # DELEGATION_ACCEPTED → success
    deny_event = events[1]   # POLICY_DENY → failure
    assert allow_event["outcome"] == "success"
    assert deny_event["outcome"] == "failure"


def test_audit_port_is_required_constructor_argument() -> None:
    """
    ACPOrchestrator requires AuditPort as a mandatory constructor argument.

    This enforces the ADR-028 hex-arch convention: no ACP orchestrator can be
    instantiated without an audit trail sink. AuditPort is abstract (ABC) and
    lives at swarm_auth.ports.audit_port (canonical path, implemented Stage 5).

    Success criteria:
    1. Omitting audit raises TypeError
    2. AuditPort is an ABC — cannot instantiate directly
    3. Instantiating with MemoryAuditAdapter() (concrete) succeeds
    """
    from swarm_auth.ports.audit_port import AuditPort
    from swarm_auth.adapters.memory_audit import MemoryAuditAdapter
    from swarm_auth.acp.orchestrator import ACPOrchestrator
    from unittest.mock import MagicMock
    from swarm_auth.ports.policy_port import Action, Decision, PolicyDecision, PolicyDecisionPoint, Resource
    from swarm_auth.ports.credential_broker_port import CredentialBrokerPort

    # AuditPort must be abstract — cannot instantiate directly
    with pytest.raises(TypeError):
        AuditPort()  # type: ignore[abstract]

    # Omitting audit keyword raises TypeError (no default)
    broker = MagicMock(spec=CredentialBrokerPort)
    allow_pdp = MagicMock(spec=PolicyDecisionPoint)
    allow_pdp.evaluate.return_value = PolicyDecision(decision=Decision.ALLOW, reason="ok")
    with pytest.raises(TypeError, match="audit"):
        ACPOrchestrator(broker=broker, policy_pipeline=[allow_pdp], signing_key="key")  # type: ignore[call-arg]

    # Instantiating with MemoryAuditAdapter succeeds
    orch = ACPOrchestrator(
        broker=broker, policy_pipeline=[allow_pdp],
        audit=MemoryAuditAdapter(), signing_key="key",
    )
    assert orch is not None
