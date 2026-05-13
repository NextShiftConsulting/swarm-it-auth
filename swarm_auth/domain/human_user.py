"""
HumanUser — concrete Principal for human operators and developers.

ADR-028 SD-1: HumanUser.kind() == "human".

Backward compat notes (Stage 3 removes these):
- is_service_account is kept as a deprecated field (always False for HumanUser)
  because jwt_auth.py reads/writes it until Stage 3.
- to_dict() outputs is_service_account: False so existing JWT payloads
  and dict consumers don't break.
- from_dict() accepts and ignores is_service_account in input data.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from swarm_auth.domain.principal import Principal
from swarm_auth.domain.roles import UserRole


@dataclass
class HumanUser(Principal):
    """A human operator, developer, or auditor.

    Does NOT hold agent_type, parent_agent_id, or sponsor_id —
    use AgentIdentity for machine-to-machine accounts.
    """

    email: Optional[str] = None
    org_id: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = None

    # Deprecated: always False for HumanUser. Kept for jwt_auth.py backward
    # compat until Stage 3. Use isinstance(p, AgentIdentity) instead.
    is_service_account: bool = False

    def kind(self) -> str:
        return "human"

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "email": self.email,
            "org_id": self.org_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "is_service_account": self.is_service_account,  # deprecated field, compat
        })
        return base

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HumanUser":
        """Deserialize from dict. Accepts legacy is_service_account key (ignored)."""
        return cls(
            user_id=data["user_id"],
            username=data["username"],
            role=UserRole(data.get("role", "developer")),
            is_active=data.get("is_active", True),
            metadata=data.get("metadata", {}),
            email=data.get("email"),
            org_id=data.get("org_id"),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if data.get("created_at")
                else datetime.now(timezone.utc)
            ),
            last_login=(
                datetime.fromisoformat(data["last_login"])
                if data.get("last_login")
                else None
            ),
            # is_service_account accepted from legacy dicts but ignored in
            # new construction — HumanUser is never a service account.
        )
