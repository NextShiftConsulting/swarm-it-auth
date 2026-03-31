# ADR-001: AccessScript and Hexagonal Architecture

**Status:** Accepted
**Date:** 2026-03-31
**Context:** P18 v4.0 credential triage implementation

## Summary

AccessScript preserves the hexagonal architecture of swarm-it-auth. It is not a replacement for the existing CredentialPort pattern. Instead, it is an **orchestration layer** that composes multiple CredentialPort implementations into a policy-driven credential resolution flow.

## Architectural Position

The architecture remains:

| Layer | Component |
|-------|-----------|
| **Port** | `CredentialPort` |
| **Adapters** | `EnvCredentialAdapter`, `DotEnvAdapter`, `KMSAdapter`, `K8sSecretsAdapter`, `VaultCredentialAdapter`, `AWSSecretsAdapter` |
| **Orchestration** | `AccessScript` |
| **Public API** | `get_credential()`, `has_credential()` via `swarm_auth` exports |

The port-and-adapter boundary remains intact. AccessScript does not bypass the port—it delegates credential access to adapters that implement the port contract.

## Why This Is Still Hexagonal

Hexagonal architecture is preserved because:

### 1. Core behavior depends on interfaces, not storage details

AccessScript works through `CredentialPort` implementations rather than embedding source-specific retrieval logic directly into application code.

### 2. Credential sources remain swappable adapters

The new sources are implemented as independent adapters:
- `DotEnvAdapter`
- `KMSAdapter`
- `K8sSecretsAdapter`

They sit beside the existing credential adapters and are exported through the adapter package.

### 3. Policy is separated from storage

AccessScript adds orchestration policy:
- Priority ordering
- Forbidden sources
- Environment-specific overrides
- Caching
- Audit logging

But actual credential retrieval still belongs to the adapters.

## Conceptual Model

```
                 ┌──────────────────────────────┐
                 │         AccessScript         │
                 │ orchestration / triage layer │
                 │ priority • forbidden • cache │
                 │ env overrides • audit trail  │
                 └──────────────┬───────────────┘
                                │
               ┌────────────────┼────────────────┐
               │                │                │
               ▼                ▼                ▼
        ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
        │CredentialPort│ │CredentialPort│ │CredentialPort│
        └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
               │                │                │
               ▼                ▼                ▼
      ┌────────────────┐ ┌──────────────┐ ┌──────────────────┐
      │ DotEnvAdapter  │ │ KMSAdapter   │ │ K8sSecretsAdapter│
      └────────────────┘ └──────────────┘ └──────────────────┘
```

## What AccessScript Adds

AccessScript is best thought of as a **composite credential resolver**.

It adds a controlled decision layer over multiple credential sources:

1. Try sources in configured order
2. Skip forbidden sources
3. Optionally raise if a forbidden source would be used
4. Initialize adapters just-in-time
5. Apply per-environment overrides
6. Keep an audit log of attempts
7. Cache retrieved values for a TTL window

That is **orchestration behavior**, not an adapter concern.

## Recommended Terminology

For documentation, the cleanest wording is:

> AccessScript is a hexagonal orchestration layer that composes multiple CredentialPort adapters into a policy-driven credential triage flow.

Alternative phrasings:
- A composite over credential adapters
- An application-service credential resolver
- A policy-driven credential orchestration layer

## Important Nuance

There is one architectural nuance worth noting.

Currently, AccessScript lazily creates concrete adapters internally. That is still compatible with hexagonal design, but it makes AccessScript somewhat aware of specific adapter classes.

This is acceptable for now, but the design could be made cleaner later by introducing a small **adapter registry or factory**:

1. AccessScript asks for a source by type
2. The registry/factory returns a `CredentialPort`
3. AccessScript no longer imports concrete adapter classes directly

That would tighten dependency inversion further without changing external behavior.

## Decision

AccessScript does not break hexagonal architecture.

It strengthens the credential layer by adding a reusable orchestration mechanism above the adapter set, while keeping the port contract and adapter separation intact.

The result is a more flexible and policy-aware credential access model without collapsing the existing architecture.

## Consequences

**Positive:**
- Credential triage is now policy-driven and configurable
- Environment-specific behavior without code changes
- Audit trail for compliance
- Forbidden sources prevent security violations

**Neutral:**
- AccessScript knows about concrete adapter classes (acceptable, improvable later)

**Negative:**
- None identified

## References

- [Google ADK Authentication](https://google.github.io/adk-docs/tools-custom/authentication/)
- [Strata: 8 Strategies for AI Agent Security](https://www.strata.io/blog/agentic-identity/8-strategies-for-ai-agent-security/)
- P18 v4.0 implementation commit: `78eabd5`
