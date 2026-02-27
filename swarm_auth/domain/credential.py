"""
Credential Domain Model - Secure credential entity.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from datetime import datetime


@dataclass
class Credential:
    """
    Credential entity - represents a stored credential.

    Domain rules:
    - key is unique
    - value is never returned in to_dict() (security)
    - Credentials can be rotated (versioned)
    """
    key: str
    created_at: datetime
    updated_at: datetime

    # Metadata (not secret)
    version: int = 1
    description: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    rotation_policy: Optional[str] = None  # e.g., "30d", "90d", "manual"

    # Audit
    created_by: Optional[str] = None
    last_rotated_at: Optional[datetime] = None
    last_accessed_at: Optional[datetime] = None

    @classmethod
    def create(
        cls,
        key: str,
        description: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        created_by: Optional[str] = None,
    ) -> "Credential":
        """
        Create a new credential metadata.

        Args:
            key: Credential identifier
            description: Human-readable description
            tags: Optional tags for organization
            created_by: User who created the credential

        Returns:
            New credential instance
        """
        now = datetime.utcnow()
        return cls(
            key=key,
            created_at=now,
            updated_at=now,
            version=1,
            description=description,
            tags=tags or {},
            created_by=created_by,
        )

    def needs_rotation(self, policy_days: Optional[int] = None) -> bool:
        """
        Check if credential needs rotation based on policy.

        Args:
            policy_days: Days before rotation needed (overrides rotation_policy)

        Returns:
            True if rotation is needed
        """
        if not policy_days and not self.rotation_policy:
            return False

        # Parse policy if not provided
        if not policy_days:
            if self.rotation_policy == "manual":
                return False
            # Parse "30d", "90d" format
            try:
                policy_days = int(self.rotation_policy.rstrip("d"))
            except (ValueError, AttributeError):
                return False

        rotation_date = self.last_rotated_at or self.created_at
        age_days = (datetime.utcnow() - rotation_date).days
        return age_days >= policy_days

    def rotate(self):
        """Mark credential as rotated (increment version)."""
        self.version += 1
        self.updated_at = datetime.utcnow()
        self.last_rotated_at = datetime.utcnow()

    def record_access(self):
        """Record that credential was accessed."""
        self.last_accessed_at = datetime.utcnow()

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        Serialize to dict.

        Args:
            include_sensitive: If True, includes fields for internal use only

        Returns:
            Dict representation (never includes actual value)
        """
        return {
            "key": self.key,
            "version": self.version,
            "description": self.description,
            "tags": self.tags,
            "rotation_policy": self.rotation_policy,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "last_rotated_at": self.last_rotated_at.isoformat() if self.last_rotated_at else None,
            "last_accessed_at": self.last_accessed_at.isoformat() if self.last_accessed_at else None,
            "needs_rotation": self.needs_rotation(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Credential":
        """Deserialize from dict."""
        return cls(
            key=data["key"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            version=data.get("version", 1),
            description=data.get("description"),
            tags=data.get("tags", {}),
            rotation_policy=data.get("rotation_policy"),
            created_by=data.get("created_by"),
            last_rotated_at=datetime.fromisoformat(data["last_rotated_at"]) if data.get("last_rotated_at") else None,
            last_accessed_at=datetime.fromisoformat(data["last_accessed_at"]) if data.get("last_accessed_at") else None,
        )
