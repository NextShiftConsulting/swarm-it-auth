# ACP (Agentic Credential Protocol) module — Stage 1
# Status: EXPERIMENTAL — no production code depends on this module.
# See swarm_auth/acp/README.md for architecture and invariants.
#
# Stage 1: re-export ActorChain from domain (domain is authoritative).
# ADR-028 mentions `from swarm_auth.acp import ActorChain` as a valid
# public path. This satisfies that contract without creating a separate
# acp/actor_chain.py module.

from swarm_auth.domain.agent_identity import ActorChain  # noqa: F401

__all__ = ["ActorChain"]
