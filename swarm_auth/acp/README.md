# ACP — Agentic Credential Protocol

**Status:** EXPERIMENTAL — Stage 0 scaffold. No production code depends on this module.
**ADR:** ADR-027 (Agentic Identity and Delegation), ADR-028 (Principal and ACP Architecture)
**Gate:** Stage 0 complete when three xfail tests exist and build is green.

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

## Hexagonal Architecture Conventions

This module follows the ADR-001 hexagonal pattern established in `swarm_auth`:

```
swarm_auth/acp/
├── __init__.py                  # Re-exports ACP public surface (ActorChain, etc.)
├── README.md                    # This file
├── ports/                       # ABCs only — no concrete implementations
│   ├── audit_port.py            # AuditPort ABC (required constructor arg in all adapters)
│   └── token_exchange_port.py  # TokenExchangePort ABC (RFC 8693)
└── adapters/                    # Concrete implementations
    ├── memory_audit_adapter.py  # In-memory ring buffer (tests only)
    ├── logging_audit_adapter.py # Structured JSON → Python logger
    ├── jwt_dpop_validator.py    # RFC 9449 DPoP proof validation
    ├── scope_policy_adapter.py  # scope_constraints.yaml enforcement
    └── rfc8693_token_exchange.py # authlib-backed RFC 8693 exchange
```

**Domain entities live in `swarm_auth/domain/`, not in `acp/domain/`.**

`Principal`, `HumanUser`, `AgentIdentity`, `AgentType`, and `ActorChain` are defined in
`swarm_auth/domain/` (established in Stage 1). ACP re-exports what callers need via
`acp/__init__.py`. There is no `acp/domain/` subdirectory — creating one would undo
the domain-authoritative decision made in Stage 1.

```python
# Correct import paths
from swarm_auth.domain.agent_identity import ActorChain, AgentIdentity, AgentType
from swarm_auth.domain.human_user import HumanUser
from swarm_auth.domain.principal import Principal

# Also valid — re-exported from acp surface
from swarm_auth.acp import ActorChain

# WRONG — acp/domain/ does not exist
# from swarm_auth.acp.domain.actor_chain import ActorChain  # NO
# from swarm_auth.acp.domain.principal import HumanUser     # NO
```

**Rules (enforced by review, not yet by lint):**

1. `acp/` never defines domain entities — it imports them from `swarm_auth.domain.*`.
2. `ports/` imports only from `swarm_auth.domain.*` and Python stdlib.
3. `adapters/` may import third-party libs (authlib, jose, pydantic) but never redefine domain types.
4. All adapter constructors take `audit_port: AuditPort` as a required argument.
5. No adapter holds credential material. Secrets pass through to `CredentialBrokerPort` immediately.

---

## Protocol Commitments (ADR-028 SD-1 through SD-6)

| SD | Standard | What ACP must implement |
|----|----------|------------------------|
| SD-1 | Principal hierarchy | `Principal` ABC → `HumanUser` / `AgentIdentity`; `principal_kind` JWT discriminator |
| SD-2 | OAuth 2.1 + RFC 8693 | Token exchange endpoint; `act` claim in JWT |
| SD-3 | RFC 8707 resource indicators | `resource` param in token requests; broker validates before vending |
| SD-4 | RFC 9449 DPoP | DPoP proof required for agent-to-agent tokens; bearer-only allowed for human→service |
| SD-5 | MCP auth spec (2025-06-18) | ACP tokens accepted by MCP server `Authorization` header |
| SD-6 | A2A passthrough | ACP tokens pass `act` chain to downstream A2A calls unchanged |

---

## Success Criteria (Stage 0 Gate)

Stage 0 is complete — and Stage 1 (domain refactor) may begin — when:

1. `tests/acp/test_rfc8693_compat.py` exists and is marked `xfail` (expected failure).
2. `tests/acp/test_mcp_compat.py` exists and is marked `xfail` (expected failure).
3. `tests/acp/test_audit_chain.py` exists and is marked `xfail` (expected failure).
4. `pytest tests/acp/` exits 0 (all three tests fail as expected — `xfail` not `FAILED`).
5. No import in `swarm_auth/__init__.py` or any adapter references `swarm_auth.acp`.

The xfail tests are the contract. They define what Stage 1-5 must deliver, expressed
as runnable assertions. A test that unexpectedly passes (`xpass`) is a build break —
it means the implementation landed without going through the plan.

---

## Stage Roadmap

| Stage | Deliverable | Gate |
|-------|-------------|------|
| 0 | This README + three xfail tests | Build green, no prod deps |
| 1 | `Principal` ABC, `HumanUser`, `AgentIdentity`, `ActorChain` in domain/ | All domain unit tests pass |
| 2 | `AuditPort` ABC + `MemoryAuditAdapter` + `LoggingAuditAdapter` | Audit tests pass |
| 3 | JWT `principal_kind` discriminator wired into `jwt_auth.py` | Auth round-trip tests pass |
| 4 | `ScopePolicyAdapter` + `scope_constraints.yaml` schema | Policy enforcement tests pass |
| 5 | `RFC8693TokenExchange` + `JWTDPoPValidator` + adapter registry | Protocol tests pass |
| 6 | `DiscoveryOrchestrator` wired: `act` chain in broker calls | SD-4 xfail → pass |
| 7 | MCP server integration test | SD-5 xfail → pass |
| 8 | A2A passthrough test | SD-6 xfail → pass |
| 9 | `DiscoveryOrchestrator` full re-certification (ADR-027 Stage 9) | SD-4 load-bearing test |

See `rsct-governance/adr/adr-027/ADR-027-implementation-plan.md` for per-stage details.
