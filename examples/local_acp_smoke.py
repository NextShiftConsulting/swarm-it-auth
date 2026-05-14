"""
Local ACP smoke test — Mode 1 (no OAuth server, no DPoP infrastructure).

Verifies the complete local script path for ACPOrchestrator:
  create_jwt_auth → mint tokens → undelegated request → delegated RFC 8693
  request → act chain in broker call → policy deny → empty pipeline guard →
  SIEM export.

Usage:
    python examples/local_acp_smoke.py

No external services required. All adapters are in-process.
See swarm_auth/acp/README.md for the two-mode usage guide.
"""

import warnings
warnings.filterwarnings("ignore")

from unittest.mock import MagicMock

from swarm_auth.factory import create_jwt_auth
from swarm_auth.domain.agent_identity import AgentIdentity, AgentType
from swarm_auth.domain.human_user import HumanUser
from swarm_auth.domain.roles import UserRole
from swarm_auth.acp.orchestrator import ACPOrchestrator, DelegatedCredentialRequest
from swarm_auth.adapters.memory_audit import MemoryAuditAdapter
from swarm_auth.adapters.rfc8693_token_exchange import RFC8693TokenExchangeAdapter
from swarm_auth.ports.composite_pdp import make_acp_pipeline
from swarm_auth.ports.credential_broker_port import CredentialBrokerPort, ProviderType, ToolRequest
from swarm_auth.ports.policy_port import Decision, PolicyDecision
from swarm_auth.ports.audit_port import AuditEventType

SECRET = "local-dev-secret-32-bytes-minimum!"

# ---------------------------------------------------------------------------
# 1. Auth adapter + principal round-trip
# ---------------------------------------------------------------------------

auth = create_jwt_auth(secret=SECRET)

human = HumanUser(user_id="alice", username="alice", role=UserRole.DEVELOPER)
agent = AgentIdentity(
    user_id="orch-001", username="orch-001",
    role=UserRole.SERVICE, agent_type=AgentType.ORCHESTRATOR,
)
human_token = auth.create_token(human)
agent_token = auth.create_token(agent)

assert auth.authenticate(human_token).user_id == "alice"
assert auth.authenticate(agent_token).user_id == "orch-001"
print("  1. auth round-trip: OK")

# ---------------------------------------------------------------------------
# 2. Wire orchestrator (local mode)
# ---------------------------------------------------------------------------

fake_credential = MagicMock()
broker = MagicMock(spec=CredentialBrokerPort)
broker.vend_credential.return_value = fake_credential

allow_pdp = MagicMock()
allow_pdp.evaluate.return_value = PolicyDecision(decision=Decision.ALLOW, reason="ok")

audit = MemoryAuditAdapter()

orchestrator = ACPOrchestrator(
    broker=broker,
    policy_pipeline=[make_acp_pipeline(rbac=allow_pdp, scope=allow_pdp)],  # wrap in list
    audit=audit,
    signing_key=SECRET,
    auth=auth,
    token_exchange=RFC8693TokenExchangeAdapter(signing_key=SECRET),  # required for actor_token
    require_dpop_for_delegation=False,  # no DPoP infra locally
)

tr = ToolRequest(
    tool_name="s3_get",
    provider=ProviderType.AWS,
    action="s3:GetObject",
    resource="arn:aws:s3:::my-bucket/key",
)

# ---------------------------------------------------------------------------
# 3. Undelegated request (human subject, no actor)
# ---------------------------------------------------------------------------

r = orchestrator.request_credential(DelegatedCredentialRequest(
    tool_request=tr,
    subject_token=human_token,
))
assert r.credential is fake_credential, f"expected credential, got error: {r.error}"
assert r.error is None
assert any(e.event_type == AuditEventType.CREDENTIAL_VENDED for e in audit.recorded())
print("  2. undelegated request: credential issued, CREDENTIAL_VENDED OK")

# ---------------------------------------------------------------------------
# 4. Delegated request (RFC 8693 token exchange, no DPoP)
# ---------------------------------------------------------------------------

audit.clear()
broker.reset_mock()

r2 = orchestrator.request_credential(DelegatedCredentialRequest(
    tool_request=tr,
    subject_token=human_token,
    actor_token=agent_token,
))
assert r2.credential is fake_credential, f"expected credential, got error: {r2.error}: {r2.error_description}"
broker.vend_credential.assert_called_once()

# act chain must reach the broker's ToolRequest
enriched_tr = broker.vend_credential.call_args[0][1]
assert enriched_tr.scope_restrictions is not None
assert "actor_chain" in enriched_tr.scope_restrictions
print("  3. delegated request: credential issued, act chain in broker ToolRequest OK")

# actor_chain must be in CREDENTIAL_VENDED audit event
vended = [e for e in audit.recorded() if e.event_type == AuditEventType.CREDENTIAL_VENDED]
assert len(vended) == 1 and vended[0].actor_chain is not None
print("  4. delegated audit: actor_chain in CREDENTIAL_VENDED event OK")

# ---------------------------------------------------------------------------
# 5. Policy deny does not reach the broker
# ---------------------------------------------------------------------------

audit.clear()
broker.reset_mock()

deny_pdp = MagicMock()
deny_pdp.evaluate.return_value = PolicyDecision(decision=Decision.DENY, reason="scope denied")

orch_deny = ACPOrchestrator(
    broker=broker, policy_pipeline=[deny_pdp],
    audit=audit, signing_key=SECRET, auth=auth,
    require_dpop_for_delegation=False,
)
r3 = orch_deny.request_credential(DelegatedCredentialRequest(
    tool_request=tr, subject_token=human_token,
))
assert r3.credential is None
broker.vend_credential.assert_not_called()
assert any(e.event_type == AuditEventType.POLICY_DENY for e in audit.recorded())
print("  5. policy deny: broker not called, POLICY_DENY emitted OK")

# ---------------------------------------------------------------------------
# 6. Empty policy pipeline fails closed at construction
# ---------------------------------------------------------------------------

try:
    ACPOrchestrator(
        broker=broker, policy_pipeline=[],
        audit=MemoryAuditAdapter(), signing_key=SECRET,
    )
    raise AssertionError("expected ValueError")
except ValueError as e:
    assert "policy_pipeline" in str(e)
print("  6. empty pipeline: ValueError at construction OK")

# ---------------------------------------------------------------------------
# 7. SIEM export
# ---------------------------------------------------------------------------

audit.clear()
orchestrator.request_credential(DelegatedCredentialRequest(
    tool_request=tr, subject_token=human_token,
))
siem_events = audit.get_events()
assert len(siem_events) == 1
ev = siem_events[0]
for field in ("timestamp", "event_type", "principal_kind", "subject", "outcome", "reason"):
    assert field in ev, f"SIEM field missing: {field}"
assert ev["principal_kind"] == "human"
assert ev["outcome"] == "success"
print("  7. SIEM export: all fields present, principal_kind=human, outcome=success OK")

# ---------------------------------------------------------------------------

print()
print("Local ACP smoke test: ALL CHECKS PASSED")
