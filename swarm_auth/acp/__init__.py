# ACP (Agentic Credential Protocol) module — Stage 8
# Status: EXPERIMENTAL — no production code depends on this module.
# See swarm_auth/acp/README.md for architecture and invariants.
#
# Stage 1: ActorChain re-exported from domain (domain is authoritative).
# Stage 4: ScopePolicyAdapter + ScopeEnforcingBrokerAdapter added.
# Stage 7: ACPOrchestrator wires all ports into the ACP pipeline.
# Stage 8: CompositePDP + make_acp_pipeline; DPoP enforcement; richer audit types.

from swarm_auth.domain.agent_identity import ActorChain  # noqa: F401

from swarm_auth.acp.adapters.scope_policy_adapter import (  # noqa: F401
    ScopePolicyAdapter,
    ScopeEnforcingBrokerAdapter,
    ScopePolicyDecision,
    ScopeConstraint,
)

from swarm_auth.acp.orchestrator import (  # noqa: F401
    ACPOrchestrator,
    DelegatedCredentialRequest,
    CredentialResponse,
)

from swarm_auth.ports.composite_pdp import CompositePDP, make_acp_pipeline  # noqa: F401

__all__ = [
    # Domain re-exports (domain is authoritative)
    "ActorChain",
    # Stage 4: scope policy
    "ScopePolicyAdapter",
    "ScopeEnforcingBrokerAdapter",
    "ScopePolicyDecision",
    "ScopeConstraint",
    # Stage 7: orchestrator
    "ACPOrchestrator",
    "DelegatedCredentialRequest",
    "CredentialResponse",
    # Stage 8: policy composition
    "CompositePDP",
    "make_acp_pipeline",
]
