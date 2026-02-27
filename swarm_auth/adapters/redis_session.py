"""
Redis Session Adapter - Redis-backed session storage.
"""

from typing import Optional, List, Dict, Any
import json
from swarm_auth.ports.session_port import SessionPort
from swarm_auth.domain.session import Session, SessionStatus


class RedisSessionAdapter(SessionPort):
    """
    Redis-backed session storage.

    Sessions are stored as JSON with automatic expiration (TTL).
    Supports distributed deployments.
    """

    def __init__(self, redis_client=None, prefix: str = "swarm:session:"):
        """
        Initialize Redis session adapter.

        Args:
            redis_client: Redis client instance (redis.Redis or redis.asyncio.Redis)
            prefix: Key prefix for sessions
        """
        self._redis = redis_client
        self._prefix = prefix

    def _get_redis(self):
        """Lazy load Redis client."""
        if self._redis is None:
            try:
                import redis
                self._redis = redis.Redis(
                    host="localhost",
                    port=6379,
                    db=0,
                    decode_responses=True,
                )
            except ImportError:
                raise ImportError("redis package required: pip install redis")
        return self._redis

    def _key(self, session_id: str) -> str:
        """Generate Redis key for session."""
        return f"{self._prefix}{session_id}"

    def _user_key(self, user_id: str) -> str:
        """Generate Redis set key for user's sessions."""
        return f"{self._prefix}user:{user_id}"

    def create(
        self,
        user_id: str,
        ttl: int = 3600,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Session:
        """
        Create a new session in Redis.

        Args:
            user_id: User ID
            ttl: Time-to-live in seconds
            metadata: Optional metadata

        Returns:
            Created session
        """
        session = Session.create(
            user_id=user_id,
            ttl=ttl,
            metadata=metadata,
        )

        redis = self._get_redis()
        key = self._key(session.session_id)
        user_key = self._user_key(user_id)

        # Store session with TTL
        redis.setex(key, ttl, json.dumps(session.to_dict()))

        # Add to user's session set
        redis.sadd(user_key, session.session_id)
        redis.expire(user_key, ttl)

        return session

    def get(self, session_id: str) -> Optional[Session]:
        """
        Get a session from Redis.

        Args:
            session_id: Session ID

        Returns:
            Session if found and valid, None otherwise
        """
        redis = self._get_redis()
        key = self._key(session_id)

        data = redis.get(key)
        if not data:
            return None

        try:
            session = Session.from_dict(json.loads(data))
            if session.is_valid():
                return session
            return None
        except (json.JSONDecodeError, KeyError, ValueError):
            return None

    def update(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        """
        Update session metadata.

        Args:
            session_id: Session ID
            metadata: Metadata to merge

        Returns:
            True if updated, False if not found
        """
        session = self.get(session_id)
        if not session:
            return False

        session.metadata.update(metadata)
        session.update_activity()

        redis = self._get_redis()
        key = self._key(session_id)

        # Get remaining TTL
        ttl = redis.ttl(key)
        if ttl < 0:
            return False

        redis.setex(key, ttl, json.dumps(session.to_dict()))
        return True

    def delete(self, session_id: str) -> bool:
        """
        Delete a session from Redis.

        Args:
            session_id: Session ID

        Returns:
            True if deleted, False if not found
        """
        session = self.get(session_id)
        if not session:
            return False

        redis = self._get_redis()
        key = self._key(session_id)
        user_key = self._user_key(session.user_id)

        redis.delete(key)
        redis.srem(user_key, session_id)
        return True

    def list_by_user(self, user_id: str) -> List[Session]:
        """
        List all active sessions for a user.

        Args:
            user_id: User ID

        Returns:
            List of active sessions
        """
        redis = self._get_redis()
        user_key = self._user_key(user_id)

        session_ids = redis.smembers(user_key)
        sessions = []

        for session_id in session_ids:
            session = self.get(session_id)
            if session and session.is_valid():
                sessions.append(session)
            else:
                # Clean up expired session from user set
                redis.srem(user_key, session_id)

        return sessions

    def extend(self, session_id: str, ttl: int) -> bool:
        """
        Extend session TTL.

        Args:
            session_id: Session ID
            ttl: Additional seconds to extend

        Returns:
            True if extended, False if not found
        """
        session = self.get(session_id)
        if not session:
            return False

        if not session.extend(ttl):
            return False

        redis = self._get_redis()
        key = self._key(session_id)

        # Update session data and TTL
        new_ttl = int((session.expires_at - session.created_at).total_seconds())
        redis.setex(key, new_ttl, json.dumps(session.to_dict()))
        return True

    def cleanup_expired(self) -> int:
        """
        Clean up expired sessions.

        Redis handles expiration automatically via TTL.
        This method is a no-op but provided for interface compatibility.

        Returns:
            0 (Redis auto-expires)
        """
        return 0
