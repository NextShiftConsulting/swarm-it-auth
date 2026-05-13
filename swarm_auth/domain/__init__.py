"""
Domain Models - Pure business entities.

No infrastructure dependencies. Domain logic only.

ADR-028 Stage 1: Principal hierarchy added.
  Principal (ABC) -> HumanUser, AgentIdentity
  User = HumanUser (backward compat alias, deprecated)
  UserRole now lives in domain/roles.py; re-exported here for compat.
"""

# New principal hierarchy (ADR-028 SD-1)
from swarm_auth.domain.roles import UserRole
from swarm_auth.domain.principal import Principal
from swarm_auth.domain.human_user import HumanUser
from swarm_auth.domain.agent_identity import (
    AgentType,
    AgentIdentity,
    ActorChain,
    MAX_ACT_CHAIN_DEPTH,
)

# Backward compat: User = HumanUser (deprecated alias)
from swarm_auth.domain.user import User  # noqa: F401

# Other domain entities unchanged
from swarm_auth.domain.session import Session, SessionStatus
from swarm_auth.domain.credential import Credential

__all__ = [
    # Principal hierarchy
    "Principal",
    "HumanUser",
    "AgentIdentity",
    "AgentType",
    "ActorChain",
    "MAX_ACT_CHAIN_DEPTH",
    # Roles
    "UserRole",
    # Legacy alias
    "User",
    # Other entities
    "Session",
    "SessionStatus",
    "Credential",
]
