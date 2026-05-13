# Gap Analysis: agentic-auth vs swarm-it-auth

**Date**: 2026-05-13
**Scope**: strongdm/agentic-auth behavioral analysis vs swarm-it-auth full source inventory
**Goal**: Identify improvements to swarm-it-auth for agentic identity and delegation

---

## What Each System Does Well

### swarm-it-auth strengths

| Capability | Implementation | Value |
|------------|---------------|-------|
| Multi-source credential discovery | 7 adapters (env, dotenv, keyfile, K8s, AWS Secrets, KMS, Vault) | Works across all deployment contexts without code changes |
| Short-lived credential brokers | `CredentialBrokerPort`: STS AssumeRole + session policies, OpenAI project keys, Vault dynamic secrets | Least-privilege, no long-lived secrets in agent memory |
| Priority-ordered triage | `AccessScript` — `env_var → dotenv → k8s → aws_secrets → kms → vault` | Same code works locally, on Lambda, and on K8s |
| Forbidden source enforcement | `AccessScript.from_config({"forbidden": ["kms"]})` | Hard policy prevents accidental credential path changes |
| Audit trail | Per-attempt source logging with `issued_to` field on `ProviderCredential` | Every credential issuance is traceable |
| Budget/token enforcement | `RBACPolicyAdapter` — per-role cost and token caps enforced at policy decision time | Prevents runaway agent spend |

### agentic-auth strengths (not in swarm-it-auth)

| Capability | agentic-auth mechanism | Gap in swarm-it-auth |
|------------|----------------------|----------------------|
| Per-agent cryptographic identity | DPoP keypairs (RFC 9449) + SPIFFE JWT-SVIDs per agent | `User` entity has no key material; identity is asserted, not proved |
| Token sender-constraint | `cnf.jkt` claim binds token to DPoP public key thumbprint | Tokens can be replayed from any client |
| Token exchange / delegation chains | RFC 8693 `urn:ietf:params:oauth:grant-type:token-exchange` | No delegation — agents present their own token only |
| OAuth 2.0 client credentials | Standard `client_credentials` grant with `client_id`/`client_secret` | No OAuth2 grant flow; custom JWT auth only |
| OIDC discovery | `.well-known/openid-configuration` endpoint | No OIDC; not discoverable by standard OAuth2 clients |
| Scope-based API authorization | Cedar policy engine — resource-scoped `permit` rules | RBAC is role-based only; no per-resource scoping |
| Agent type taxonomy | `agent_type`: human / assistant / tool / orchestrator / service / bot | `UserRole` has `SERVICE` but no agent-specific roles |
| Static public key registry | `AgentKey` store — Ed25519/RSA/ECDSA, DNS/GitHub verification proofs | No public key registry; service accounts have no key material |
| Sponsor trust anchor | Email-anchored sponsor model for agent registration | No sponsor concept; service accounts are self-registered |
| Replay detection | `jti` blacklist for DPoP proofs (sliding window) | JWT blacklist exists but no DPoP `jti` replay window |
| Real-time revocation | SSF/CAEP framework (partially wired) | Token blacklist + expiry only; no event-driven revocation |
| Machine-readable discovery | `SKILL.md` endpoint per agent | No agent capability discovery endpoint |

---

## Priority Gap Ranking

Ranked by impact on the swarm-it-* ecosystem (not on general-purpose use cases).

### Priority 1 — Agent Type Taxonomy (Low effort, High impact)

**Problem**: `UserRole.SERVICE` is used for all machine-to-machine accounts. An arxiv scraper, an LLM agent, and an orchestrator are all `SERVICE`. Policy decisions can't distinguish.

**agentic-auth pattern**:
```python
class AgentType(Enum):
    HUMAN = "human"
    ASSISTANT = "assistant"    # LLM doing work
    TOOL = "tool"              # Deterministic function caller
    ORCHESTRATOR = "orchestrator"  # Coordinates other agents
    SERVICE = "service"        # Background service
    BOT = "bot"                # Automated pipeline
```

**Improvement**: Add `AgentType` to `User` domain model. Keep `UserRole` for permissions. The two are orthogonal: an `ORCHESTRATOR` can have `DEVELOPER` role, a `TOOL` can have `SERVICE` role.

**Effort**: 1 day — domain model change + RBAC adapter update.

---

### Priority 2 — Scope-Based Policy (Medium effort, High impact)

**Problem**: `RBACPolicyAdapter` grants broad role-based access. A `DEVELOPER` can call `openai.chat.generate` on any project. There is no way to say "this agent may only call `openai.chat.generate` on project `discovery-pipeline`."

**agentic-auth pattern** (Cedar):
```cedar
permit(
    principal == Agent::"analyzer-agent",
    action == Action::"openai:chat.completions.create",
    resource == Resource::"project/discovery-pipeline"
);
```

**Improvement**: Add a `scope` field to `ToolRequest` and `ProviderCredential`. The policy adapter checks scope against an allow-list per principal, not just role. Does not require Cedar — can be implemented as a dict-based `ScopePolicy` on top of the existing `PolicyDecisionPoint` port.

```python
@dataclass
class ScopeConstraint:
    principal_id: str          # agent_id or user_id
    provider: ProviderType
    resource_pattern: str      # "project/discovery-*", "arn:aws:s3:::yrsn-*"
    max_tokens: Optional[int]
    allowed_models: Optional[list[str]]
```

**Effort**: 2-3 days — new port implementation, no changes to existing adapters.

---

### Priority 3 — Per-Agent Key Material (Medium effort, Critical for multi-agent)

**Problem**: Service accounts in `User` have no cryptographic identity. A compromised service token can be replayed indefinitely until it expires. In multi-agent pipelines, there is no way to verify *which* agent sent a request — only which `user_id` is in the JWT payload.

**agentic-auth pattern**:
- Each agent has an Ed25519 keypair at registration
- JWTs include `cnf.jkt` (public key thumbprint)
- Every request includes a DPoP proof header (signed with private key over HTTP method + URL + timestamp)
- Server verifies proof before accepting token

**Improvement for swarm-it-auth**:

1. Add `AgentKeyStore` port:
```python
@dataclass
class AgentKey:
    agent_id: str
    public_key_pem: str           # Ed25519 public key
    algorithm: str = "EdDSA"
    key_id: str = ""              # kid for JWK lookup
    registered_at: datetime = field(...)
    verified_via: Optional[str] = None  # "dns", "github", "manual"
```

2. Add `cnf` claim to JWT on issue:
```python
# In JWTAuthAdapter.create_token()
if user.metadata.get("public_key_thumbprint"):
    payload["cnf"] = {"jkt": user.metadata["public_key_thumbprint"]}
```

3. Add `DPoPProofValidator` — verifies the `DPoP` header on inbound requests using the registered public key.

**Effort**: 3-4 days — new port + adapter + JWT changes + proof validation middleware.

**Note**: Full DPoP (RFC 9449) is the long-term target. As a stepping stone, add `AgentKey` registration and `cnf.jkt` binding without requiring DPoP proofs on every request — just use it for replay risk reduction.

---

### Priority 4 — Token Exchange / Delegation (High effort, High value for orchestrators)

**Problem**: When an orchestrator calls a sub-agent on behalf of a user, the sub-agent has no way to know who the original principal was. Currently the orchestrator just passes its own `user_id`. The sub-agent can't enforce "this action was authorized by a DEVELOPER, not a GUEST."

**agentic-auth pattern** (RFC 8693):
```http
POST /oauth/token
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<orchestrator_token>
actor_token=<sub_agent_token>
scope=openai:chat.completions.create
```

Response includes `act` claim: `{"sub": "sub-agent-id", "act": {"sub": "orchestrator-id", "act": {"sub": "user-id"}}}` — full delegation chain, auditable.

**Improvement for swarm-it-auth**: Add a `TokenExchangePort` that:
1. Validates both `subject_token` and `actor_token`
2. Checks the orchestrator has `delegate` permission for the requested scope
3. Issues a new token with an `act` claim chain
4. Logs the full delegation path for audit

**Effort**: 4-5 days — new grant type, `act` claim support in JWT adapter, orchestrator-level permission in RBAC.

---

### Priority 5 — OAuth 2.0 Client Credentials Grant (High effort, Prerequisite for ecosystem integration)

**Problem**: swarm-it-auth uses a custom JWT auth flow. Any external system (RapidAPI gateway, third-party tool, external orchestration framework) that speaks OAuth2 cannot integrate without a custom adapter.

**agentic-auth pattern**: Standard `client_credentials` grant at `/oauth/token`. Yields a bearer token with `scope` and `expires_in`.

**Improvement**: Add `OAuth2ServerPort` with `client_credentials` grant. The existing `JWTAuthAdapter` becomes the token issuer; the grant handler adds standard OAuth2 request/response shapes. Enables `OIDC discovery` endpoint as a follow-on.

**Effort**: 5-7 days — grant handler, client registry, OIDC discovery endpoint. High effort but unlocks ecosystem compatibility.

---

## What NOT to Adopt

| agentic-auth feature | Reason to skip |
|---------------------|---------------|
| Cedar policy engine | RBAC with scope constraints (Priority 2) covers swarm-it-* needs without a full policy engine dependency |
| Full SPIFFE/SVID infrastructure | Overkill for current deployment model; `AgentKey` + `cnf.jkt` achieves 80% of the value |
| Email-anchored sponsor model | swarm-it-auth manages service accounts internally; external sponsor registration adds surface area without benefit |
| SSF/CAEP real-time revocation | Existing token blacklist + short TTLs cover the threat model; SSF adds infrastructure complexity |
| `SKILL.md` discovery endpoint | Relevant for external agent ecosystems; not needed for internal swarm-it-* pipeline |

---

## Implementation Order

```
Week 1:  Priority 1 — Agent type taxonomy (domain model only)
Week 2:  Priority 2 — Scope-based policy (new ScopeConstraint adapter)
Week 3:  Priority 3 — AgentKey store + cnf.jkt binding (no full DPoP yet)
Week 4+: Priority 4 — Token exchange (schedule when orchestrators go multi-tenant)
         Priority 5 — OAuth2 client credentials (schedule when RapidAPI needs it)
```

---

## Concrete File Changes for Priority 1 + 2

### Priority 1: `swarm_auth/domain/user.py`

Add `AgentType` enum and field to `User`:

```python
class AgentType(Enum):
    HUMAN = "human"
    ASSISTANT = "assistant"
    TOOL = "tool"
    ORCHESTRATOR = "orchestrator"
    SERVICE = "service"
    BOT = "bot"

@dataclass
class User:
    ...
    agent_type: Optional[AgentType] = None  # None = human default
```

### Priority 2: new file `swarm_auth/adapters/scope_policy.py`

New `ScopePolicyAdapter` implementing `PolicyDecisionPoint`:
- Takes a list of `ScopeConstraint` objects at construction
- `evaluate()` checks RBAC role first, then narrows by scope
- Returns `DENY` if action's resource doesn't match any allowed pattern for principal

### Priority 2: `swarm_auth/adapters/rbac_policy.py`

Add `scope_policy: Optional[ScopePolicyAdapter] = None` parameter. If set, chain evaluation: RBAC ALLOW → scope check → final decision.

---

## References

- agentic-auth: https://github.com/strongdm/agentic-auth
- RFC 9449: DPoP — Demonstrating Proof of Possession
- RFC 8693: OAuth 2.0 Token Exchange
- SPIFFE/SVID: https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/
- Cedar policy language: https://www.cedarpolicy.com/
