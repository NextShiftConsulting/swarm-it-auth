# Patent Reconciliation Audit: swarm-it-auth

**Date:** 2026-04-24 (Re-audit)
**Patent:** US Application 19/575,615 (TUP96543)
**Status:** ADVISORY ONLY -- NO CODE CHANGES

---

## Executive Summary

swarm-it-auth implements P18 credential gateway with a hexagonal architecture. **No changes since initial audit.** Architecture is compliant: 6 ports, 14+ adapters, 7 credential sources, priority-ordered triage, tool-level permissions, principal-based access. Key gap: audit trail is **in-memory only** (no persistent sink).

---

## Findings

| Element | Status | Evidence |
|---------|--------|----------|
| Hexagonal architecture | **COMPLIANT** | 6 ports in `ports/`, 14+ adapters in `adapters/`, ADR-001 |
| CredentialBrokerPort | **COMPLIANT** | `credential_broker_port.py:102` -- 5 abstract methods |
| AccessScript triage | **COMPLIANT** | `access_script.py:263-314` -- 7 sources in priority order |
| ToolRequest + per-tool vending | **COMPLIANT** | `credential_broker_port.py:82-99`. AWS: per-tool IAM session policy |
| Principal-based access | **COMPLIANT** | `User` + `UserRole`, `RBACPolicyAdapter`, STS session tagging |
| Credential masking | **COMPLIANT** | `AccessAttempt` logs key name, never value |
| Forbidden source enforcement | **COMPLIANT** | `access_script.py:280-289` -- SILENT/LOG/ERROR modes |
| Audit trail persistence | **GAP** | In-memory only. Max 1000 entries, trimmed to 500. No AuditSinkPort, FileAuditSink, or CloudWatchAuditSink |
| GCP/Azure/Anthropic/Bedrock brokers | **GAP** | ProviderType declared, no concrete implementations |

### Unprotected Innovations

| Innovation | Location | Description |
|-----------|----------|-------------|
| JIT adapter creation | `access_script.py:89` | On-demand adapter instantiation |
| OnForbidden configurable behavior | `access_script.py:50-53` | SILENT/LOG/ERROR modes |
| Environment-specific overrides | `access_script.py:101,129` | Per-env priority/forbidden/on_forbidden |
| Auto-discover factory | `access_script.py:376-395` | Runtime availability probing |
| Keyfile per-file isolation | `keyfile_credential.py:57` | Per-credential audit/rotation |

**No changes since initial audit.**
