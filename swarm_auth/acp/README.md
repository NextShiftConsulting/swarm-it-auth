# ACP — Agentic Credential Protocol

**Status:** Stage 8 local hardening ACCEPTED (`adr-027-stage8-accepted`). Stage 8.4 (external protocol test harness) open.
**ADR:** ADR-027 (Agentic Identity and Delegation), ADR-028 (Principal and ACP Architecture)
**Issues:** [#2 authlib](https://github.com/NextShiftConsulting/swarm-it-auth/issues/2) · [#3 MCP accept](https://github.com/NextShiftConsulting/swarm-it-auth/issues/3) · [#4 MCP reject](https://github.com/NextShiftConsulting/swarm-it-auth/issues/4)

---

## Core Invariant

> ACP enriches credential requests. `CredentialBrokerPort` still vends credentials.

ACP does not replace the credential broker. It adds the protocol layer that:
- Carries delegation context (who is acting on behalf of whom)
- Validates resource indicators (RFC 8707) before routing to the broker
- Attaches DPoP proof (RFC 9449) to outbound bearer tokens
- Emits structured audit events (SIEM-parseable JSON) to `AuditPort`

The `CredentialBrokerPort` remains the single exit point for credential material.
ACP sits between callers and the broker — it never holds secrets itself.

---

## Usage

There are two modes. Choose based on your context:

### Mode 1 — Local script / in-process testing (no OAuth server, no DPoP)

Use this for local development, unit tests, and smoke tests. No external server required.
`create_jwt_auth()` builds `JWTAuthAdapter` with an in-memory blacklist — do not instantiate
`JWTAuthAdapter` directly (it requires a blacklist adapter; the factory provides one).

```python
from unittest.mock import MagicMock
from swarm_auth.factory import create_jwt_auth
from swarm_auth.domain.agent_identity import AgentIdentity, AgentType
from swarm_auth.domain.human_user import HumanUser
from swarm_auth.domain.roles import UserRole
from swarm_auth.acp.orchestrator import ACPOrchestrator, DelegatedCredentialRequest
from swarm_auth.adapters.memory_audit import MemoryAuditAdapter
from swarm_auth.ports.composite_pdp import make_acp_pipeline
from swarm_auth.ports.credential_broker_port import CredentialBrokerPort, ToolRequest

SECRET = "dev-secret"  # HS256 shared key — never use in production

# 1. Auth adapter (in-memory blacklist, no Redis required)
auth = create_jwt_auth(secret=SECRET)

# 2. Mint tokens for your principals
human = HumanUser(user_id="alice", username="alice", role=UserRole.DEVELOPER)
human_token = auth.create_token(human)

agent = AgentIdentity(
    user_id="orch-001", username="orch-001",
    role=UserRole.SERVICE, agent_type=AgentType.ORCHESTRATOR,
)
agent_token = auth.create_token(agent)

# 3. Authenticate (verify round-trip)
principal = auth.authenticate(human_token)
print(principal.user_id)   # "alice"

# 4. Wire up the orchestrator (swap mocks for real adapters as needed)
from swarm_auth.ports.policy_port import Decision, PolicyDecision

broker = MagicMock(spec=CredentialBrokerPort)
broker.vend_credential.return_value = MagicMock()  # swap in a real broker adapter

allow_pdp = MagicMock()
allow_pdp.evaluate.return_value = PolicyDecision(decision=Decision.ALLOW, reason="ok")

orchestrator = ACPOrchestrator(
    broker=broker,
    policy_pipeline=make_acp_pipeline(rbac=allow_pdp, scope=allow_pdp),
    audit=MemoryAuditAdapter(),
    signing_key=SECRET,
    auth=auth,
    require_dpop_for_delegation=False,  # set False for local smoke tests (no DPoP infra)
)

# 5. Make a credential request
response = orchestrator.request_credential(DelegatedCredentialRequest(
    tool_request=ToolRequest(
        provider="aws", service="s3", action="s3:GetObject",
        resource_arn="arn:aws:s3:::my-bucket/key",
    ),
    subject_token=human_token,
))
print(response.credential)  # ProviderCredential from broker
```

**Key points for local mode:**
- Use `create_jwt_auth(secret=...)` — not `JWTAuthAdapter(...)` directly.
- Set `require_dpop_for_delegation=False` when testing delegated flows without DPoP infrastructure.
- `MemoryAuditAdapter` records all events; call `.recorded()` or `.get_events()` to inspect them.
- `policy_pipeline` must not be empty — `ACPOrchestrator` raises `ValueError` at construction.

---

### Mode 2 — Full wired mode (DPoP, token exchange, CompositePDP)

Use this for staging and production. Wire real adapters for all ports.

```python
from swarm_auth.factory import create_jwt_auth
from swarm_auth.acp.orchestrator import ACPOrchestrator, DelegatedCredentialRequest
from swarm_auth.adapters.memory_audit import MemoryAuditAdapter        # swap for LoggingAuditAdapter
from swarm_auth.adapters.rfc8693_token_exchange import RFC8693TokenExchangeAdapter
from swarm_auth.adapters.strict_dpop_validator import StrictDPoPValidator
from swarm_auth.adapters.agent_key_store import MemoryAgentKeyStore
from swarm_auth.adapters.rbac_policy import RBACPolicyAdapter
from swarm_auth.adapters.scope_policy_adapter import ScopePolicyAdapter
from swarm_auth.ports.composite_pdp import make_acp_pipeline
from swarm_auth.ports.credential_broker_port import ToolRequest

SECRET = "production-hs256-key"   # load from swarm_auth.get_credential() in real code

# Auth adapter
auth = create_jwt_auth(secret=SECRET)

# DPoP: key store + validator
key_store = MemoryAgentKeyStore()      # replace with persistent store in production
dpop_validator = StrictDPoPValidator(key_store=key_store, signing_key=SECRET)

# Token exchange (RFC 8693)
token_exchange = RFC8693TokenExchangeAdapter(signing_key=SECRET, issuer="https://auth.example.com")

# Policy pipeline: RBAC first, scope second (both must ALLOW)
pipeline = make_acp_pipeline(
    rbac=RBACPolicyAdapter(),
    scope=ScopePolicyAdapter(constraints_path="scope_constraints.yaml"),
)

# Audit (swap MemoryAuditAdapter for LoggingAuditAdapter in production)
audit = MemoryAuditAdapter()

# Broker (supply your real adapter)
from swarm_auth.adapters.aws_credential_broker import AWSCredentialBrokerAdapter
broker = AWSCredentialBrokerAdapter(...)

orchestrator = ACPOrchestrator(
    broker=broker,
    policy_pipeline=[pipeline],
    audit=audit,
    signing_key=SECRET,
    auth=auth,
    token_exchange=token_exchange,
    dpop_validator=dpop_validator,
    require_dpop_for_delegation=True,  # default — enforces RFC 9449 for all delegated flows
)
```

**Key points for wired mode:**
- `require_dpop_for_delegation=True` (default) — `actor_token` without `dpop_proof` is rejected.
- `make_acp_pipeline(rbac, scope)` composes RBAC ∩ scope; first DENY short-circuits.
- `CompositePDP([])` and `policy_pipeline=[]` both fail closed (DENY / `ValueError` respectively).
- Replace `MemoryAuditAdapter` with `LoggingAuditAdapter` for production SIEM output.

---

### What is NOT available yet (Stage 8.4)

These require external server infrastructure (tracked in issues #2-#4):

| Feature | Issue | Status |
|---------|-------|--------|
| authlib RFC 8693 token exchange against real OAuth server | [#2](https://github.com/NextShiftConsulting/swarm-it-auth/issues/2) | `xfail` |
| MCP server accepts ACP token with resource indicator | [#3](https://github.com/NextShiftConsulting/swarm-it-auth/issues/3) | `xfail` |
| MCP server rejects token without resource indicator | [#4](https://github.com/NextShiftConsulting/swarm-it-auth/issues/4) | `xfail` |

Both modes above work fully without these. The xfails are protocol compliance gates,
not prerequisites for using the orchestrator.

---

## Hexagonal Architecture Conventions

This module follows the ADR-001 hexagonal pattern established in `swarm_auth`:

```
swarm_auth/
├── acp/
│   ├── __init__.py                   # Re-exports ACP public surface
│   ├── README.md                     # This file
│   └── orchestrator.py               # ACPOrchestrator — the ACP pipeline
├── ports/
│   ├── audit_port.py                 # AuditPort ABC (required in all adapters)
│   ├── composite_pdp.py              # CompositePDP + make_acp_pipeline
│   ├── policy_port.py                # PolicyDecisionPoint ABC
│   ├── token_exchange_port.py        # TokenExchangePort ABC (RFC 8693)
│   └── dpop_validator_port.py        # DPoPValidatorPort ABC (RFC 9449)
└── adapters/
    ├── memory_audit.py               # In-memory AuditPort (tests only)
    ├── rfc8693_token_exchange.py     # RFC 8693 token exchange adapter
    ├── strict_dpop_validator.py      # RFC 9449 DPoP proof validation
    ├── scope_policy_adapter.py       # scope_constraints.yaml enforcement
    └── rbac_policy.py                # Role-based access control
```

**Domain entities live in `swarm_auth/domain/`, not in `acp/domain/`.**

```python
# Correct import paths
from swarm_auth.domain.agent_identity import ActorChain, AgentIdentity, AgentType
from swarm_auth.domain.human_user import HumanUser
from swarm_auth.domain.principal import Principal

# Also valid — re-exported from acp surface
from swarm_auth.acp import ActorChain
```

**Rules:**
1. `acp/` never defines domain entities — it imports from `swarm_auth.domain.*`.
2. `ports/` imports only from `swarm_auth.domain.*` and Python stdlib.
3. `adapters/` may import third-party libs (authlib, jose, pydantic) but never redefine domain types.
4. All adapter constructors take `audit: AuditPort` as a required argument.
5. No adapter holds credential material. Secrets pass through to `CredentialBrokerPort` immediately.

---

## Protocol Commitments (ADR-028 SD-1 through SD-6)

| SD | Standard | Status |
|----|----------|--------|
| SD-1 | `Principal` ABC → `HumanUser` / `AgentIdentity`; `principal_kind` JWT discriminator | IMPLEMENTED |
| SD-2 | OAuth 2.1 + RFC 8693 token exchange; `act` claim in JWT | IMPLEMENTED (local); authlib integration test pending (#2) |
| SD-3 | RFC 8707 resource indicators | IMPLEMENTED |
| SD-4 | RFC 9449 DPoP — required for delegated flows by default | IMPLEMENTED |
| SD-5 | MCP auth spec (2025-06-18) — ACP tokens accepted by MCP server | PENDING (#3, #4) |
| SD-6 | A2A passthrough — `act` chain preserved to downstream calls | IMPLEMENTED |
