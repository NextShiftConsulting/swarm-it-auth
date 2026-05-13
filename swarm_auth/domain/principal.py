"""
Principal — abstract base for all authenticated identities.

ADR-028 SD-1: Principal is the domain root. Concrete subclasses (HumanUser,
AgentIdentity) must implement kind(), which becomes the `principal_kind` JWT
discriminator in Stage 3 (jwt_auth.py).

Import chain (no cycles):
    domain/roles.py  <-  domain/principal.py  <-  domain/human_user.py
                                               <-  domain/agent_identity.py
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict

from swarm_auth.domain.roles import UserRole


@dataclass
class Principal(ABC):
    """Abstract base for HumanUser and AgentIdentity.

    Domain rules:
    - user_id is immutable after construction.
    - kind() must return 'human' or 'agent' — never SERVICE or any other
      string. This value becomes the `principal_kind` JWT claim in Stage 3.
    - has_permission() is role-based; same logic as the original User class.
    - Concrete subclasses must not be instantiated without a user_id.
    """

    user_id: str
    username: str
    role: UserRole
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    @abstractmethod
    def kind(self) -> str:
        """Return 'human' (HumanUser) or 'agent' (AgentIdentity).

        This becomes the principal_kind JWT discriminator in Stage 3.
        No other values are valid — enforce this in from_jwt_payload()
        when it is written.
        """
        ...

    def has_permission(self, permission: str) -> bool:
        """Check if this principal has a specific permission.

        Permission hierarchy:
        - admin: all permissions
        - developer: certify, validate, read, audit
        - auditor: read, audit
        - service: certify, validate, read (no audit)
        - guest: read only (limited)
        """
        permissions_by_role = {
            UserRole.ADMIN: {"*"},
            UserRole.DEVELOPER: {"certify", "validate", "read", "audit"},
            UserRole.AUDITOR: {"read", "audit"},
            UserRole.SERVICE: {"certify", "validate", "read"},
            UserRole.GUEST: {"read"},
        }
        allowed = permissions_by_role.get(self.role, set())
        return "*" in allowed or permission in allowed

    def to_dict(self) -> Dict[str, Any]:
        """Serialize shared fields. Subclasses call super().to_dict() and extend."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role.value,
            "is_active": self.is_active,
            "metadata": self.metadata,
            "principal_kind": self.kind(),
        }
