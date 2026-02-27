"""
Memory Session Adapter - In-memory session storage (testing only).
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from swarm_auth.ports.session_port import SessionPort
from swarm_auth.domain.session import Session, SessionStatus


class MemorySessionAdapter(SessionPort):
    """
    In-memory session storage.

    WARNING: Only for testing. Sessions are lost on restart.
    Not suitable for production or distributed deployments.
    """

    def __init__(self):
        """Initialize in-memory storage."""
        self._sessions: Dict[str, Session] = {}
        self._user_sessions: Dict[str, List[str]] = {}

    def create(
        self,
        user_id: str,
        ttl: int = 3600,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Session:
        """Create a new session in memory."""
        session = Session.create(user_id=user_id, ttl=ttl, metadata=metadata)

        self._sessions[session.session_id] = session

        if user_id not in self._user_sessions:
            self._user_sessions[user_id] = []
        self._user_sessions[user_id].append(session.session_id)

        return session

    def get(self, session_id: str) -> Optional[Session]:
        """Get a session from memory."""
        session = self._sessions.get(session_id)

        if not session:
            return None

        if not session.is_valid():
            # Auto-cleanup expired session
            self.delete(session_id)
            return None

        return session

    def update(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        """Update session metadata."""
        session = self.get(session_id)
        if not session:
            return False

        session.metadata.update(metadata)
        session.update_activity()
        return True

    def delete(self, session_id: str) -> bool:
        """Delete a session from memory."""
        session = self._sessions.get(session_id)
        if not session:
            return False

        # Remove from sessions
        del self._sessions[session_id]

        # Remove from user index
        if session.user_id in self._user_sessions:
            self._user_sessions[session.user_id].remove(session_id)
            if not self._user_sessions[session.user_id]:
                del self._user_sessions[session.user_id]

        return True

    def list_by_user(self, user_id: str) -> List[Session]:
        """List all active sessions for a user."""
        session_ids = self._user_sessions.get(user_id, [])
        sessions = []

        for session_id in session_ids:
            session = self.get(session_id)
            if session:
                sessions.append(session)

        return sessions

    def extend(self, session_id: str, ttl: int) -> bool:
        """Extend session TTL."""
        session = self.get(session_id)
        if not session:
            return False

        return session.extend(ttl)

    def cleanup_expired(self) -> int:
        """Clean up expired sessions."""
        expired_ids = [
            sid for sid, sess in self._sessions.items()
            if not sess.is_valid()
        ]

        for session_id in expired_ids:
            self.delete(session_id)

        return len(expired_ids)
