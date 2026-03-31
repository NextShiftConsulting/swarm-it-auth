# ADR-002: Certificate Authority Architecture

**Status:** Accepted
**Date:** 2026-03-31
**Context:** ADK certificate delegation to yrsn via API

## Decision

**Certificate authority lives in yrsn. ADK delegates all certification to swarm-it-api.**

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   swarm-it-adk  │────▶│  swarm-it-api   │────▶│      yrsn       │
│ (Runtime Client)│     │  (HTTP Gateway) │     │ (RSCT Authority)│
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       │
   ToolInterceptor         REST Routes           HybridSimplexRotor
   CertificateGate         /v1/certify           YRSNCertificate
   SwarmCertifier          /v1/validate          Constraint Graph
        │                       │                       │
        └───────────────────────┴───────────────────────┘
              ADK calls API ─────▶ API calls yrsn
```

## Rationale

1. **Single source of truth**: yrsn owns the RSCT mathematical model
2. **No duplicate logic**: ADK's `_classify_local()` reimplements what yrsn does natively
3. **Consistent gates**: API applies the authoritative constraint graph
4. **Auditability**: All certification flows through API with audit trail
5. **Evolution safety**: Threshold learning happens in one place

## Current State (Problem)

ADK has **three separate certification paths**:

| Path | Location | Problem |
|------|----------|---------|
| Local engine | `adk/swarm_it/local/engine.py` | Hash-based approximation, not production-grade |
| API client | `adk/swarm_it/client.py` | Correct path, but missing swarm support |
| Swarm certifier | `adk/swarm_it/topology/certifier.py` | Local-only, no API counterpart |

The `_classify_local()` method implements 16 RSCT modes that the API doesn't expose, creating drift between local and API behavior.

## Target State

ADK becomes a **thin client** that:
1. Intercepts tool calls (authorization check)
2. Calls API for certification (no local RSCT computation)
3. Enforces API decision (allow/deny/repair)
4. Emits events with API-issued certificates

```python
# Target: ADK CertificateGate delegates to API
class CertificateGate:
    def __init__(self, api_client: SwarmItClient):
        self.api = api_client

    async def check(self, context: str, policy: str) -> GateResult:
        # Delegate entirely to API
        cert = await self.api.certify(context, policy)

        if cert.decision == "REJECT":
            return GateResult.FAIL(cert.reasoning)
        if cert.kappa_gate < self.min_kappa:
            return GateResult.FAIL(f"kappa {cert.kappa_gate} < {self.min_kappa}")

        return GateResult.PASS(certificate=cert)
```

## API Gaps to Close

### Priority 1: Critical for ADK Delegation

| Gap | Endpoint Needed | Why |
|-----|-----------------|-----|
| Swarm certification | `POST /v1/swarms/{id}/certify` | ADK's SwarmCertifier has no API counterpart |
| Batch certification | `POST /v1/certify/batch` | ADK makes N sequential calls |
| 16-mode taxonomy | Response field `rsct_mode` | ADK computes locally, API doesn't return |

### Priority 2: Operational

| Gap | Endpoint Needed | Why |
|-----|-----------------|-----|
| Phasor coherence | `POST /v1/consensus/compute` | API approximates c = R/(R+N+0.1), not true coherence |
| Certificate binding | Signed response or `proof` field | No way to verify certificate authenticity |
| Webhook notifications | `POST /v1/webhooks/register` | Async certificate events |

### Priority 3: Scale

| Gap | Endpoint Needed | Why |
|-----|-----------------|-----|
| Real-time stream | `WS /v1/stream` | Continuous certification for long-running swarms |
| Query certificates | `GET /v1/certificates?filter=...` | Only ID lookup exists |

## Implementation Plan

### Phase 1: Close Critical Gaps (swarm-it-api)

```python
# New endpoint: POST /v1/swarms/{swarm_id}/certify
@router.post("/v1/swarms/{swarm_id}/certify")
async def certify_swarm(
    swarm_id: str,
    request: SwarmCertifyRequest,
) -> SwarmCertificate:
    """
    Request:
        agents: List[AgentOutput]  # Each agent's context/output
        topology: TopologySpec     # DAG, star, mesh, etc.
        task_encoding: str         # Swarm-level task description

    Response:
        swarm_certificate: Certificate with aggregate RSN
        agent_certificates: List[Certificate] per agent
        consensus: float  # True phasor coherence
        weakest_link: AgentId
    """
```

```python
# New endpoint: POST /v1/certify/batch
@router.post("/v1/certify/batch")
async def certify_batch(
    request: BatchCertifyRequest,
) -> BatchCertifyResponse:
    """
    Request:
        items: List[CertifyRequest]  # Up to 100 items

    Response:
        certificates: List[Certificate]
        failed: List[FailedItem]
    """
```

### Phase 2: Deprecate ADK Local Engine

1. Mark `adk/swarm_it/local/engine.py` as deprecated
2. Remove `_classify_local()` - use API's `rsct_mode` instead
3. SwarmCertifier calls `POST /v1/swarms/{id}/certify`

### Phase 3: ADK Thin Client

ADK becomes:
- `ToolInterceptor` - authorization (swarm-it-auth tokens)
- `CertificateGate` - quality (swarm-it-api certification)
- Event emitter - telemetry (shared event schema)

No local RSCT computation.

## Field Mapping

When ADK receives API response, map fields:

| API Field | ADK Field | Notes |
|-----------|-----------|-------|
| `kappa` | `kappa_gate` | External name is `kappa` |
| `S_sup` | `S` | API uses S_sup |
| `decision` | `gate_decision` | EXECUTE/REJECT/BLOCK/RE_ENCODE/REPAIR |
| `rsct_mode` | `collapse_mode` | New field needed in API |

## Consequences

**Positive:**
- Single certification authority (yrsn)
- ADK simplified to thin client
- Consistent behavior across all callers
- Audit trail in one place

**Negative:**
- API dependency for certification (offline mode limited)
- Additional network latency

**Mitigation:**
- Keep minimal offline fallback for development only
- Batch API to reduce round trips

## References

- [INTERFACE-SPEC-auth-adk.md](./INTERFACE-SPEC-auth-adk.md) - Auth ↔ ADK boundary
- [ADR-001-AccessScript-Hexagonal.md](./ADR-001-AccessScript-Hexagonal.md) - Credential triage
- swarm-it-api/docs/API_GAPS.md - Documented gaps
- swarm-it-adk/docs/analysis/swarm-it-gaps.md - Gap analysis
