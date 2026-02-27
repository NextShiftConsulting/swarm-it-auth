"""
User Domain Model - Pure business entity.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from datetime import datetime
from enum import Enum


class UserRole(Enum):
    """User roles for RBAC."""
    ADMIN = "admin"              # Full system access
    DEVELOPER = "developer"      # API access, can create API keys
    AUDITOR = "auditor"          # Read-only access to certificates
    SERVICE = "service"          # Machine-to-machine (M2M) account
    GUEST = "guest"              # Limited read access


@dataclass
class User:
    """
    User entity - represents an authenticated user or service.

    Domain rules:
    - user_id is immutable
    - email must be unique (enforced by adapter)
    - Service accounts have no email
    """
    user_id: str
    username: str
    role: UserRole = UserRole.DEVELOPER

    # Optional fields
    email: Optional[str] = None
    org_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None

    # Metadata
    is_active: bool = True
    is_service_account: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def has_permission(self, permission: str) -> bool:
        """
        Check if user has a specific permission.

        Permission hierarchy:
        - admin: all permissions
        - developer: certify, validate, read
        - auditor: read only
        - service: certify, validate (no audit)
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
        """Serialize to dict."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "role": self.role.value,
            "email": self.email,
            "org_id": self.org_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "is_active": self.is_active,
            "is_service_account": self.is_service_account,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        """Deserialize from dict."""
        return cls(
            user_id=data["user_id"],
            username=data["username"],
            role=UserRole(data.get("role", "developer")),
            email=data.get("email"),
            org_id=data.get("org_id"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.utcnow(),
            last_login=datetime.fromisoformat(data["last_login"]) if data.get("last_login") else None,
            is_active=data.get("is_active", True),
            is_service_account=data.get("is_service_account", False),
            metadata=data.get("metadata", {}),
        )
