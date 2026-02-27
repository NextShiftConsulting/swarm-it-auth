"""
Session Port - Interface for session management.

Implementations:
- RedisSessionAdapter: Redis-backed sessions
- DynamoDBSessionAdapter: DynamoDB sessions
- MemorySessionAdapter: In-memory sessions (testing only)
"""

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from datetime import datetime
from swarm_auth.domain.session import Session


class SessionPort(ABC):
    """Port: Manage user sessions."""

    @abstractmethod
    def create(
        self,
        user_id: str,
        ttl: int = 3600,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Session:
        """
        Create a new session.

        Args:
            user_id: User ID for the session
            ttl: Time-to-live in seconds (default 1 hour)
            metadata: Optional session metadata

        Returns:
            Created session
        """
        pass

    @abstractmethod
    def get(self, session_id: str) -> Optional[Session]:
        """
        Get a session by ID.

        Args:
            session_id: Session ID

        Returns:
            Session if found and valid, None otherwise
        """
        pass

    @abstractmethod
    def update(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        """
        Update session metadata.

        Args:
            session_id: Session ID
            metadata: Metadata to merge into session

        Returns:
            True if updated, False if not found
        """
        pass

    @abstractmethod
    def delete(self, session_id: str) -> bool:
        """
        Delete a session.

        Args:
            session_id: Session ID

        Returns:
            True if deleted, False if not found
        """
        pass

    @abstractmethod
    def list_by_user(self, user_id: str) -> List[Session]:
        """
        List all active sessions for a user.

        Args:
            user_id: User ID

        Returns:
            List of active sessions
        """
        pass

    @abstractmethod
    def extend(self, session_id: str, ttl: int) -> bool:
        """
        Extend session TTL.

        Args:
            session_id: Session ID
            ttl: Additional seconds to extend

        Returns:
            True if extended, False if not found
        """
        pass

    @abstractmethod
    def cleanup_expired(self) -> int:
        """
        Clean up expired sessions.

        Returns:
            Number of sessions deleted
        """
        pass
