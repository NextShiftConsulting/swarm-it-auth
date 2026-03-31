# API Gaps for ADK Delegation

**Version:** 1.0.0
**Date:** 2026-03-31
**Status:** Implementation Required

This document specifies the API endpoints swarm-it-api must implement for ADK to fully delegate certificate authority to yrsn.

---

## Field Name Contract (Frozen)

**These field names are locked before implementation. All consumers (API, ADK, telemetry) must use these exact names.**

| External Name | Internal Alias | Notes |
|---------------|----------------|-------|
| `kappa` | `kappa_gate` | Quality gate metric; internal code may use `kappa_gate` but serialize as `kappa` |
| `S` | `S_sup` | Stability; yrsn uses `S_sup` internally, API exposes as `S` |
| `R` | - | Relevance (no alias) |
| `N` | - | Noise (no alias) |
| `rsct_mode` | `collapse_mode` | 16-mode taxonomy; ADK internal may use `collapse_mode` |
| `decision` | `gate_decision` | EXECUTE/REJECT/BLOCK/RE_ENCODE/REPAIR |
| `kappa_H` | - | Hallucination resistance (no alias) |
| `kappa_L` | - | Logical consistency (no alias) |
| `kappa_interface` | - | Agent interface compatibility (no alias) |

**Serialization Rule:** At every API boundary, translate internal aliases to external names. No alias should appear in HTTP responses, events, or stored certificates.

---

## rsct_mode Authority

**`rsct_mode` is computed by yrsn and passed through swarm-it-api unchanged.**

swarm-it-api does NOT:
- Reconstruct `rsct_mode` from RSN values
- Apply its own mode classification logic
- Override yrsn's mode determination

swarm-it-api DOES:
- Pass `rsct_mode` from yrsn's `YRSNCertificate` to API response
- Include it in batch and swarm certification responses
- Log it in audit trail

This prevents drift between yrsn's authoritative mode taxonomy and any downstream reconstruction.

```python
# CORRECT: Pass through from yrsn
response["rsct_mode"] = yrsn_certificate.rsct_mode

# WRONG: Reconstruct in API
response["rsct_mode"] = classify_mode(R, S, N)  # DO NOT DO THIS
```

---

## Priority 1: Critical Gaps

### 1.1 POST /v1/swarms/{swarm_id}/certify

**Purpose:** Certify an entire swarm's output, replacing ADK's local `SwarmCertifier`.

**Request:**
```json
{
  "agents": [
    {
      "agent_id": "agent_abc123",
      "context": "User asked about quarterly revenue...",
      "output": "Q3 revenue was $4.2M...",
      "role": "data_analyst"
    },
    {
      "agent_id": "agent_def456",
      "context": "Synthesize analyst reports...",
      "output": "Based on the data, revenue grew 12%...",
      "role": "summarizer"
    }
  ],
  "topology": {
    "type": "dag",
    "edges": [
      {"from": "agent_abc123", "to": "agent_def456"}
    ]
  },
  "task_encoding": "Generate quarterly financial summary",
  "policy": "strict"
}
```

**Response:**
```json
{
  "swarm_id": "swarm_xyz789",
  "swarm_certificate": {
    "R": 0.72,
    "S": 0.18,
    "N": 0.10,
    "kappa": 0.85,
    "decision": "EXECUTE",
    "rsct_mode": "1.1",
    "consensus": 0.91,
    "weakest_link": "agent_abc123"
  },
  "agent_certificates": [
    {
      "agent_id": "agent_abc123",
      "R": 0.68,
      "S": 0.20,
      "N": 0.12,
      "kappa": 0.78,
      "kappa_interface": 0.82
    },
    {
      "agent_id": "agent_def456",
      "R": 0.76,
      "S": 0.16,
      "N": 0.08,
      "kappa": 0.88,
      "kappa_interface": 0.85
    }
  ],
  "interface_scores": [
    {
      "from": "agent_abc123",
      "to": "agent_def456",
      "compatibility": 0.84,
      "kappa_interface": 0.82
    }
  ],
  "timestamp": "2026-03-31T12:15:00.000Z"
}
```

**ADK Usage:**
```python
# Before: ADK local SwarmCertifier (to be deprecated)
certifier = SwarmCertifier(swarm)
cert = certifier.certify()

# After: ADK delegates to API
cert = await api.certify_swarm(swarm_id, agents, topology, task)
```

---

### 1.2 POST /v1/certify/batch

**Purpose:** Certify multiple items in a single request, reducing N API calls to 1.

**Request:**
```json
{
  "items": [
    {
      "id": "item_001",
      "context": "First context...",
      "policy": "standard"
    },
    {
      "id": "item_002",
      "context": "Second context...",
      "policy": "strict"
    }
  ],
  "options": {
    "continue_on_error": true,
    "max_parallel": 10
  }
}
```

**Response:**
```json
{
  "certificates": [
    {
      "id": "item_001",
      "certificate": {
        "R": 0.72,
        "S": 0.18,
        "N": 0.10,
        "kappa": 0.85,
        "decision": "EXECUTE"
      }
    },
    {
      "id": "item_002",
      "certificate": {
        "R": 0.65,
        "S": 0.22,
        "N": 0.13,
        "kappa": 0.71,
        "decision": "EXECUTE"
      }
    }
  ],
  "failed": [],
  "stats": {
    "total": 2,
    "succeeded": 2,
    "failed": 0,
    "duration_ms": 145
  }
}
```

**Limits:**
- Max 100 items per batch
- Max 10 parallel internal certifications

---

### 1.3 Response Field: rsct_mode

**Purpose:** Expose the 16-mode RSCT taxonomy that ADK currently computes locally.

**Add to existing `/v1/certify` response:**
```json
{
  "R": 0.72,
  "S": 0.18,
  "N": 0.10,
  "kappa": 0.85,
  "decision": "EXECUTE",
  "rsct_mode": "1.1",
  "rsct_mode_detail": {
    "group": 1,
    "type": 1,
    "name": "EXECUTE_CLEAN",
    "description": "High relevance, low noise - proceed"
  }
}
```

**Mode Groups:**
| Group | Range | Description |
|-------|-------|-------------|
| 1 | 1.1-1.4 | Execute modes (proceed with output) |
| 2 | 2.1-2.4 | Reject modes (block output) |
| 3 | 3.1-3.4 | Re-encode modes (transform output) |
| 4 | 4.1-4.4 | Repair modes (fix specific issues) |

---

## Priority 2: Operational Gaps

### 2.1 POST /v1/consensus/compute

**Purpose:** Compute true phasor coherence from multiple agent outputs.

**Current Problem:** API approximates `c = R / (R + N + 0.1)` instead of computing proper multi-agent agreement.

**Request:**
```json
{
  "outputs": [
    {
      "agent_id": "agent_001",
      "output": "Revenue grew 12% in Q3",
      "embedding": [0.12, 0.34, ...]  // Optional pre-computed
    },
    {
      "agent_id": "agent_002",
      "output": "Q3 saw 12% revenue growth",
      "embedding": [0.13, 0.33, ...]
    }
  ],
  "method": "phasor"  // phasor | cosine | voting
}
```

**Response:**
```json
{
  "consensus": 0.94,
  "method": "phasor",
  "agreement_matrix": [
    [1.0, 0.94],
    [0.94, 1.0]
  ],
  "divergence_points": [],
  "confidence": 0.92
}
```

---

### 2.2 Certificate Binding (Signed Response)

**Purpose:** Cryptographic proof that certificate wasn't tampered.

**Option A: Signed JWT response**
```json
{
  "certificate": "eyJ...",  // JWT containing certificate claims
  "signature": "sha256:abc123..."
}
```

**Option B: Proof field in response**
```json
{
  "R": 0.72,
  "S": 0.18,
  "N": 0.10,
  "kappa": 0.85,
  "proof": {
    "type": "hmac",
    "signature": "sha256:abc123...",
    "timestamp": "2026-03-31T12:15:00.000Z",
    "nonce": "xyz789"
  }
}
```

**ADK Verification:**
```python
# ADK verifies certificate authenticity
if not api.verify_certificate_proof(cert, cert.proof):
    raise CertificateTampered("Certificate proof invalid")
```

---

### 2.3 POST /v1/webhooks/register

**Purpose:** Async notifications for certificate events.

**Request:**
```json
{
  "url": "https://my-app.com/webhooks/rsct",
  "events": ["certificate.issued", "gate.failed", "threshold.updated"],
  "secret": "whsec_abc123"
}
```

**Response:**
```json
{
  "webhook_id": "wh_xyz789",
  "status": "active",
  "events": ["certificate.issued", "gate.failed", "threshold.updated"]
}
```

**Webhook Payload:**
```json
{
  "event": "gate.failed",
  "timestamp": "2026-03-31T12:15:00.000Z",
  "data": {
    "certificate_id": "cert_abc123",
    "gate": 4,
    "threshold": 0.7,
    "actual": 0.65,
    "agent_id": "agent_xyz"
  },
  "signature": "sha256:..."
}
```

---

## Priority 3: Scale Gaps

### 3.1 WS /v1/stream

**Purpose:** Real-time certificate stream for long-running swarms.

**Connection:**
```
wss://api.swarmit.dev/v1/stream?swarm_id=xyz&token=...
```

**Messages:**
```json
// Server → Client
{
  "type": "certificate",
  "agent_id": "agent_abc",
  "certificate": { "R": 0.72, "S": 0.18, "N": 0.10, "kappa": 0.85 },
  "timestamp": "2026-03-31T12:15:00.000Z"
}

// Server → Client
{
  "type": "drift_alert",
  "agent_id": "agent_abc",
  "metric": "kappa",
  "direction": "down",
  "from": 0.85,
  "to": 0.71,
  "timestamp": "2026-03-31T12:15:30.000Z"
}
```

---

### 3.2 GET /v1/certificates (Query Filters)

**Purpose:** Query certificates by multiple criteria.

**Current:** Only `GET /v1/certificates/{id}` exists.

**Needed:**
```
GET /v1/certificates?start_time=2026-03-31T00:00:00Z
                    &end_time=2026-03-31T23:59:59Z
                    &decision=REJECT
                    &policy=strict
                    &agent_id=agent_abc
                    &min_kappa=0.7
                    &limit=100
                    &offset=0
```

**Response:**
```json
{
  "certificates": [...],
  "total": 1234,
  "limit": 100,
  "offset": 0,
  "next": "/v1/certificates?...&offset=100"
}
```

---

## Implementation Checklist

### Build Order (Confirmed)

This sequence gives ADK immediate delegation value before the full swarm path is finished.

**Phase 1: swarm-it-api (Priority 1)**

```
Step 1: POST /v1/certify/batch
Step 2: Add rsct_mode to existing /v1/certify response
Step 3: POST /v1/swarms/{swarm_id}/certify
```

- [x] **Step 1:** `POST /v1/certify/batch` - Batch certification (reduces N calls → 1) ✓ 2026-03-31
- [x] **Step 2:** Add `rsct_mode` field to `/v1/certify` response (passthrough from yrsn) ✓ 2026-03-31
- [x] **Step 3:** `POST /v1/swarms/{swarm_id}/certify` - Swarm-level certification ✓ 2026-03-31

**Phase 2: swarm-it-adk (Consume & Deprecate)**

- [x] Update `client.certify_batch()` to call `/v1/certify/batch` ✓ 2026-03-31
- [x] Parse `rsct_mode` from API response (remove local `_classify_local()`) ✓ 2026-03-31
- [x] Deprecate `local/engine.py` `_classify_local()` ✓ 2026-03-31
- [x] Update `client.certify_swarm()` to call `/v1/swarms/{id}/certify` ✓ 2026-03-31
- [x] Mark local certification paths as deprecated ✓ 2026-03-31

**Phase 3: swarm-it-api (Priority 2)**

- [x] `POST /v1/consensus/compute` - True phasor coherence ✓ 2026-03-31
- [x] Certificate binding (HMAC-SHA256 proof field) ✓ 2026-03-31
- [x] `POST /v1/webhooks/register` - Webhook registration ✓ 2026-03-31

**Phase 4: swarm-it-api (Priority 3)**

- [ ] `WS /v1/stream` - Real-time certificate stream
- [ ] `GET /v1/certificates` with query filters

**Phase 5: swarm-it-adk (Full Thin Client)**

- [ ] Verify certificate proof when present
- [ ] Remove all local RSCT computation
- [ ] ADK becomes pure delegation client

---

## References

- [ADR-002-Certificate-Authority-Architecture.md](./ADR-002-Certificate-Authority-Architecture.md)
- [INTERFACE-SPEC-auth-adk.md](./INTERFACE-SPEC-auth-adk.md)
- swarm-it-api/docs/API.md
