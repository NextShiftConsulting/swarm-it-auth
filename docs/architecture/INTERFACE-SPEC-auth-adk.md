# Interface Specification: swarm-it-auth ↔ swarm-it-adk

**Version:** 1.0.0
**Date:** 2026-03-31
**Status:** Draft

## Overview

This document defines the contract between:

| Repo | Role |
|------|------|
| **swarm-it-auth** | Identity & Credential Control Plane |
| **swarm-it-adk** | Runtime Enforcement & Telemetry Plane |

The boundary principle:

> **swarm-it-auth** mints mission-scoped agent authority.
> **swarm-it-adk** continuously enforces it at each runtime step.

---

## 1. Agent Identity Token

### Token Claims Schema

```json
{
  "iss": "swarm-it-auth",
  "sub": "agent:agent_abc123",
  "iat": 1711900800,
  "exp": 1711901700,

  "agent": {
    "agent_id": "agent_abc123",
    "agent_type": "task_executor",
    "parent_principal": "user:rudy@example.com",
    "delegation_chain": [
      "user:rudy@example.com",
      "agent:orchestrator_001",
      "agent:agent_abc123"
    ]
  },

  "mission": {
    "task_id": "task_xyz789",
    "tools_allowed": ["s3_upload", "openai_chat", "web_fetch"],
    "resources_allowed": ["arn:aws:s3:::bucket/*", "project:proj_123"],
    "max_cost_usd": 1.00,
    "max_tokens": 10000
  },

  "constraints": {
    "ttl_seconds": 900,
    "execution_environment": "lambda",
    "region": "us-east-1",
    "require_certificate": true,
    "min_kappa": 0.7
  },

  "proof": {
    "type": "dpop",
    "thumbprint": "sha256:abc123..."
  }
}
```

### Token Types

| Type | TTL | Use Case |
|------|-----|----------|
| `mission_token` | 5-15 min | Single task execution |
| `session_token` | 1 hour | Multi-task agent session |
| `bootstrap_token` | 30 sec | Initial agent registration |

### Field Name Authority

**Canonical external field name for certificate quality gate: `kappa`**

| Context | Field Name | Notes |
|---------|------------|-------|
| Token claims | `min_kappa` | Threshold in constraints |
| Event schema | `kappa` | Certificate metric |
| API responses | `kappa` | All external interfaces |
| Internal code | `kappa_gate` | Allowed as internal alias only |

All external interfaces (tokens, events, APIs, dashboards) use `kappa`. Internal code may use `kappa_gate` as an alias but must translate to `kappa` at serialization boundaries.

### Token vs Live Policy Precedence

**The signed mission token is authoritative for mission scope at execution time.**

| Source | Authoritative For |
|--------|-------------------|
| Mission token claims | Current mission scope, tools, resources, constraints |
| Live policy (`GET /v1/policy`) | Refresh decisions, inspection, future missions |

**Rationale:** Runtime must be deterministic and auditable. The token captures what was authorized at mission start. Live policy may change during execution, but the executing agent operates under the authority granted in its signed token. This prevents mid-mission policy changes from causing inconsistent enforcement.

**Exception:** Revocation is immediate. A revoked token fails validation regardless of its claims.

---

## 2. Broker API Endpoints (swarm-it-auth)

### POST /v1/agent/register

Register a new agent and get bootstrap token.

**Request:**
```json
{
  "agent_type": "task_executor",
  "parent_principal": "user:rudy@example.com",
  "requested_capabilities": ["s3", "openai"],
  "execution_environment": "lambda"
}
```

**Response:**
```json
{
  "agent_id": "agent_abc123",
  "bootstrap_token": "eyJ...",
  "expires_in": 30
}
```

### POST /v1/agent/mission

Request mission-scoped credentials for a specific task.

**Request:**
```json
{
  "agent_id": "agent_abc123",
  "task_id": "task_xyz789",
  "tools_requested": [
    {
      "tool_name": "s3_upload",
      "provider": "aws",
      "action": "s3:PutObject",
      "resource": "arn:aws:s3:::my-bucket/prefix/*"
    },
    {
      "tool_name": "openai_chat",
      "provider": "openai",
      "action": "chat.completions.create",
      "resource": "project:proj_123"
    }
  ],
  "duration_seconds": 900,
  "constraints": {
    "max_cost_usd": 1.00,
    "require_certificate": true
  }
}
```

**Response:**
```json
{
  "mission_token": "eyJ...",
  "credentials": {
    "s3_upload": {
      "provider": "aws",
      "type": "sts",
      "access_key_id": "ASIA...",
      "secret_access_key": "...",
      "session_token": "...",
      "expires_at": "2026-03-31T12:30:00Z"
    },
    "openai_chat": {
      "provider": "openai",
      "type": "api_key",
      "api_key": "<YOUR_OPENAI_KEY>",
      "project_id": "proj_123",
      "expires_at": "2026-03-31T12:30:00Z"
    }
  },
  "policy": {
    "tools_allowed": ["s3_upload", "openai_chat"],
    "max_cost_usd": 1.00,
    "max_tokens": 10000,
    "require_certificate": true,
    "min_kappa": 0.7
  },
  "expires_at": "2026-03-31T12:30:00Z"
}
```

### POST /v1/agent/delegate

Create a child agent with narrower scope.

**Request:**
```json
{
  "parent_agent_id": "agent_abc123",
  "parent_mission_token": "eyJ...",
  "child_agent_type": "subtask_executor",
  "scope_reduction": {
    "tools_allowed": ["openai_chat"],
    "max_cost_usd": 0.25,
    "ttl_seconds": 300
  }
}
```

**Response:**
```json
{
  "child_agent_id": "agent_def456",
  "child_mission_token": "eyJ...",
  "delegation_chain": [
    "user:rudy@example.com",
    "agent:orchestrator_001",
    "agent:agent_abc123",
    "agent:agent_def456"
  ]
}
```

### POST /v1/agent/revoke

Revoke an agent's credentials immediately.

**Request:**
```json
{
  "agent_id": "agent_abc123",
  "reason": "task_completed"
}
```

### GET /v1/policy/{agent_id}

Fetch current policy for an agent.

**Response:**
```json
{
  "agent_id": "agent_abc123",
  "tools_allowed": ["s3_upload", "openai_chat"],
  "actions_allowed": {
    "s3_upload": ["s3:PutObject"],
    "openai_chat": ["chat.completions.create"]
  },
  "resources_allowed": {
    "s3_upload": ["arn:aws:s3:::my-bucket/*"],
    "openai_chat": ["project:proj_123"]
  },
  "constraints": {
    "max_cost_usd": 1.00,
    "require_certificate": true,
    "min_kappa": 0.7
  }
}
```

---

## 3. Runtime Enforcement Hooks (swarm-it-adk)

### Tool Call Interceptor

ADK intercepts every tool call and enforces policy:

```python
class ToolInterceptor:
    def __init__(self, auth_client: AuthClient, policy: Policy):
        self.auth = auth_client
        self.policy = policy

    async def intercept(
        self,
        agent_id: str,
        mission_token: str,
        tool_call: ToolCall,
    ) -> InterceptResult:
        """
        Called before every tool execution.

        Returns:
            ALLOW: Proceed with tool call
            DENY: Block with reason
            ELEVATE: Request additional credentials
        """
        # 1. Validate token not expired
        if not self.auth.validate_token(mission_token):
            return InterceptResult.DENY("token_expired")

        # 2. Check tool is allowed
        if tool_call.tool_name not in self.policy.tools_allowed:
            return InterceptResult.DENY("tool_not_allowed")

        # 3. Check action is allowed
        allowed_actions = self.policy.actions_allowed.get(tool_call.tool_name, [])
        if tool_call.action not in allowed_actions:
            return InterceptResult.DENY("action_not_allowed")

        # 4. Check resource is allowed
        if not self._resource_matches(tool_call.resource, self.policy.resources_allowed):
            return InterceptResult.DENY("resource_not_allowed")

        # 5. Check cost budget
        if self.policy.cost_spent + tool_call.estimated_cost > self.policy.max_cost_usd:
            return InterceptResult.DENY("cost_budget_exceeded")

        # 6. Log for audit
        self._emit_audit_event(agent_id, tool_call, "allowed")

        return InterceptResult.ALLOW
```

### Certificate Gate

ADK enforces RSCT certificate requirements:

```python
class CertificateGate:
    def __init__(self, policy: Policy):
        self.policy = policy

    def check(self, certificate: RSCTCertificate) -> GateResult:
        """
        Called after tool execution to validate output quality.
        """
        if not self.policy.require_certificate:
            return GateResult.PASS

        if certificate.kappa < self.policy.min_kappa:
            return GateResult.FAIL(
                f"kappa {certificate.kappa} < min {self.policy.min_kappa}"
            )

        if certificate.R < 0.3:
            return GateResult.FAIL(f"relevance {certificate.R} < 0.3")

        return GateResult.PASS
```

---

## 4. Shared Event Schema

All events flow into a unified audit trail:

```json
{
  "event_id": "evt_abc123",
  "timestamp": "2026-03-31T12:15:00.000Z",
  "event_type": "tool_call",

  "principal": {
    "type": "agent",
    "id": "agent_abc123",
    "delegation_chain": ["user:rudy", "agent:orch", "agent:abc123"]
  },

  "task": {
    "task_id": "task_xyz789",
    "mission_token_hash": "sha256:def456..."
  },

  "tool": {
    "name": "openai_chat",
    "provider": "openai",
    "action": "chat.completions.create",
    "resource": "project:proj_123"
  },

  "result": {
    "status": "success",
    "duration_ms": 1250,
    "tokens_used": 500,
    "cost_usd": 0.015
  },

  "certificate": {
    "R": 0.72,
    "S": 0.18,
    "N": 0.10,
    "kappa": 0.85,
    "gate_passed": true
  },

  "audit": {
    "interceptor_decision": "allow",
    "policy_version": "v1.2.3",
    "enforcement_point": "adk_sidecar"
  }
}
```

### Event Types

| Type | Source | Description |
|------|--------|-------------|
| `agent_registered` | auth | New agent created |
| `mission_issued` | auth | Mission credentials vended |
| `delegation_created` | auth | Child agent delegated |
| `credential_revoked` | auth | Agent credentials revoked |
| `tool_call` | adk | Tool execution (allowed) |
| `tool_denied` | adk | Tool execution blocked |
| `certificate_issued` | adk | RSCT certificate generated |
| `gate_failed` | adk | Certificate gate failed |

---

## 5. Error Codes

| Code | Source | Description |
|------|--------|-------------|
| `AUTH_001` | auth | Invalid or expired token |
| `AUTH_002` | auth | Agent not found |
| `AUTH_003` | auth | Delegation chain broken |
| `AUTH_004` | auth | Scope elevation denied |
| `POLICY_001` | auth/adk | Tool not allowed |
| `POLICY_002` | auth/adk | Action not allowed |
| `POLICY_003` | auth/adk | Resource not allowed |
| `POLICY_004` | adk | Cost budget exceeded |
| `POLICY_005` | adk | Token budget exceeded |
| `CERT_001` | adk | Certificate required but missing |
| `CERT_002` | adk | Kappa below threshold |
| `CERT_003` | adk | Relevance below threshold |

---

## 6. Implementation Phases

### Phase 1: Foundation (Current)
- [x] AccessScript credential triage
- [x] CredentialPort adapters (env, dotenv, kms, k8s, vault, aws)
- [x] Basic JWT/API key auth
- [ ] Agent identity token schema

### Phase 2: Mission Credentials
- [ ] `/v1/agent/register` endpoint
- [ ] `/v1/agent/mission` endpoint
- [ ] Tool-scoped credential vending
- [ ] TTL enforcement

### Phase 3: Delegation
- [ ] `/v1/agent/delegate` endpoint
- [ ] Delegation chain tracking
- [ ] Scope reduction enforcement
- [ ] `/v1/agent/revoke` endpoint

### Phase 4: Runtime Enforcement (ADK)
- [ ] ToolInterceptor hook
- [ ] CertificateGate hook
- [ ] Policy sync from auth
- [ ] Unified event emission

### Phase 5: Observability
- [ ] Shared event schema implementation
- [ ] Audit trail aggregation
- [ ] Delegation graph visualization
- [ ] Cost/token tracking dashboards

---

## 7. Security Considerations

1. **Proof of Possession**: Mission tokens should use DPoP or similar binding
2. **Delegation Depth**: Limit delegation chain to 5 levels
3. **Scope Only Narrows**: Child agents can never exceed parent scope
4. **Short TTLs**: Mission tokens < 15 min, session tokens < 1 hour
5. **Revocation Propagation**: Revoking parent revokes all children
6. **Audit Everything**: Every decision logged with full context

---

## References

- [ADR-001: AccessScript Hexagonal Architecture](./ADR-001-AccessScript-Hexagonal.md)
- [Google ADK Authentication](https://google.github.io/adk-docs/tools-custom/authentication/)
- [Strata: 8 Strategies for AI Agent Security](https://www.strata.io/blog/agentic-identity/8-strategies-for-ai-agent-security/)
