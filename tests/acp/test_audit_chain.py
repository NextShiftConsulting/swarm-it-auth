"""
Stage 0 xfail: Audit chain and SIEM-parseable JSON.

This test is expected to fail until Stage 2 (AuditPort + MemoryAuditAdapter)
is implemented. It defines the contract for the audit trail requirement
in ADR-027 Gap 1 (SERVICE role conflation) and Gap 4 (flat delegation chains).

Contract (ADR-028 SD-1, SD-2):
- A three-hop act chain (human -> orchestrator -> tool) is recorded in
  MemoryAuditAdapter as structured JSON events.
- Each event is SIEM-parseable: has `timestamp`, `event_type`, `principal_kind`,
  `subject`, `actor`, and `resource` fields.
- The full chain is reconstructable from audit events without querying the token.

When this test passes unexpectedly (xpass), it means the implementation
landed outside the plan — treat as a build break and investigate.
"""

import json
import pytest


@pytest.mark.xfail(
    reason=(
        "MemoryAuditAdapter not yet implemented — Stage 0 placeholder. "
        "Implement in Stage 2 per ADR-027-implementation-plan.md."
    ),
    strict=True,
)
def test_three_hop_act_chain_recorded_in_audit_log() -> None:
    """
    Three-hop delegation chain (human -> orchestrator -> tool) emits
    SIEM-parseable JSON audit events via MemoryAuditAdapter.

    Chain:
        human (HumanUser, subject) delegates to
        orchestrator (AgentIdentity, actor) which delegates to
        tool (AgentIdentity, actor.actor)

    Success criteria:
    1. MemoryAuditAdapter records one event per delegation hop
    2. Each event is valid JSON with required SIEM fields
    3. Events can be replayed to reconstruct the full act chain
    4. No data loss: subject.sub, actor.sub, actor.actor.sub all present

    Contract reference: ADR-027 Gap 4, ADR-028 SD-1 (principal_kind discriminator)
    """
    from swarm_auth.acp.adapters.memory_audit_adapter import MemoryAuditAdapter  # noqa: F401
    # domain is authoritative — ActorChain/AgentIdentity/HumanUser live in swarm_auth.domain
    from swarm_auth.domain.agent_identity import ActorChain, AgentIdentity  # noqa: F401
    from swarm_auth.domain.human_user import HumanUser  # noqa: F401

    raise NotImplementedError("MemoryAuditAdapter not implemented (Stage 2)")


@pytest.mark.xfail(
    reason=(
        "MemoryAuditAdapter not yet implemented — Stage 0 placeholder. "
        "Implement in Stage 2 per ADR-027-implementation-plan.md."
    ),
    strict=True,
)
def test_audit_event_schema_is_siem_parseable() -> None:
    """
    Each audit event emitted by MemoryAuditAdapter is valid SIEM-parseable JSON.

    Required fields per event:
        - timestamp: ISO-8601 UTC
        - event_type: str (e.g., "token_exchange", "credential_request", "delegation")
        - principal_kind: "human" | "agent" (ADR-028 SD-1 discriminator)
        - subject: str (sub claim of the subject token)
        - actor: str | None (sub claim of the acting agent, if delegation present)
        - resource: str | None (RFC 8707 resource indicator, if present)
        - outcome: "success" | "failure"
        - reason: str | None (failure reason)

    Success criteria:
    1. MemoryAuditAdapter.get_events() returns a list of dicts
    2. Each dict passes json.dumps() without error
    3. Each dict has all required fields (extra fields allowed)
    4. `principal_kind` is always "human" or "agent" — never SERVICE (ADR-027 Gap 1 fix)

    Contract reference: ADR-027 Gap 1 (SERVICE role conflation), ADR-028 SD-1
    """
    from swarm_auth.acp.adapters.memory_audit_adapter import MemoryAuditAdapter  # noqa: F401

    REQUIRED_FIELDS = {
        "timestamp", "event_type", "principal_kind",
        "subject", "actor", "resource", "outcome", "reason",
    }

    adapter = MemoryAuditAdapter()
    events = adapter.get_events()

    # No events yet — but the schema contract is what matters here
    for event in events:
        serialized = json.dumps(event)  # must not raise
        parsed = json.loads(serialized)
        missing = REQUIRED_FIELDS - set(parsed.keys())
        assert not missing, f"Audit event missing required SIEM fields: {missing}"
        assert parsed["principal_kind"] in ("human", "agent"), (
            f"principal_kind must be 'human' or 'agent', got {parsed['principal_kind']!r}. "
            "SERVICE is not a valid principal_kind (ADR-027 Gap 1)."
        )

    raise NotImplementedError("MemoryAuditAdapter not implemented (Stage 2)")


@pytest.mark.xfail(
    reason=(
        "AuditPort ABC not yet defined — Stage 0 placeholder. "
        "Implement in Stage 2 per ADR-027-implementation-plan.md."
    ),
    strict=True,
)
def test_audit_port_is_required_constructor_argument() -> None:
    """
    All ACP adapters require AuditPort as a constructor argument.

    This enforces the ADR-028 hex-arch convention: no adapter can be
    instantiated without an audit trail sink. This prevents silent
    credential vending without an audit record.

    Success criteria:
    1. Instantiating any ACP adapter without audit_port raises TypeError
    2. Instantiating with audit_port=MemoryAuditAdapter() succeeds
    3. AuditPort is an ABC (cannot instantiate directly)

    Contract reference: ADR-028 (hex-arch conventions, Section: Adapter Rules)
    """
    from swarm_auth.acp.ports.audit_port import AuditPort  # noqa: F401
    from swarm_auth.acp.adapters.memory_audit_adapter import MemoryAuditAdapter  # noqa: F401

    # AuditPort must be abstract — cannot instantiate directly
    with pytest.raises(TypeError):
        AuditPort()  # type: ignore[abstract]

    raise NotImplementedError("AuditPort ABC not implemented (Stage 2)")
