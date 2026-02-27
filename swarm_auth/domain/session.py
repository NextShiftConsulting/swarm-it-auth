"""
Session Domain Model - Represents a user session.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from enum import Enum
import secrets


class SessionStatus(Enum):
    """Session lifecycle states."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class Session:
    """
    Session entity - represents an authenticated session.

    Domain rules:
    - session_id is cryptographically random
    - expires_at must be in the future for active sessions
    - Session can be extended but not beyond max_duration
    """
    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    status: SessionStatus = SessionStatus.ACTIVE

    # Optional fields
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    last_activity: Optional[datetime] = None

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        user_id: str,
        ttl: int = 3600,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "Session":
        """
        Create a new session with generated ID.

        Args:
            user_id: User ID
            ttl: Time-to-live in seconds (default 1 hour)
            ip_address: Client IP
            user_agent: Client user agent
            metadata: Optional metadata

        Returns:
            New session instance
        """
        now = datetime.utcnow()
        session_id = secrets.token_urlsafe(32)

        return cls(
            session_id=session_id,
            user_id=user_id,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            status=SessionStatus.ACTIVE,
            ip_address=ip_address,
            user_agent=user_agent,
            last_activity=now,
            metadata=metadata or {},
        )

    def is_valid(self) -> bool:
        """Check if session is valid (active and not expired)."""
        if self.status != SessionStatus.ACTIVE:
            return False
        return datetime.utcnow() < self.expires_at

    def extend(self, seconds: int, max_duration: int = 86400) -> bool:
        """
        Extend session TTL.

        Args:
            seconds: Seconds to extend
            max_duration: Max session duration in seconds (default 24 hours)

        Returns:
            True if extended, False if would exceed max_duration
        """
        if not self.is_valid():
            return False

        new_expires = self.expires_at + timedelta(seconds=seconds)
        max_expires = self.created_at + timedelta(seconds=max_duration)

        if new_expires > max_expires:
            return False

        self.expires_at = new_expires
        return True

    def revoke(self):
        """Revoke the session."""
        self.status = SessionStatus.REVOKED

    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "status": self.status.value,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "metadata": self.metadata,
            "is_valid": self.is_valid(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Session":
        """Deserialize from dict."""
        return cls(
            session_id=data["session_id"],
            user_id=data["user_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            status=SessionStatus(data.get("status", "active")),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            last_activity=datetime.fromisoformat(data["last_activity"]) if data.get("last_activity") else None,
            metadata=data.get("metadata", {}),
        )
