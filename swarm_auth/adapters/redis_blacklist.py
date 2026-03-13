"""
Redis Blacklist Adapter - Redis-backed token blacklist with TTL.
"""

from typing import Optional
import hashlib
from swarm_auth.ports.blacklist_port import BlacklistPort


class RedisBlacklistAdapter(BlacklistPort):
    """
    Redis-backed token blacklist.

    - Tokens stored with SHA256 hash (privacy)
    - Automatic expiration via TTL
    - Supports distributed deployments
    """

    def __init__(
        self,
        redis_client=None,
        prefix: str = "swarm:jwt:blacklist:",
        default_ttl: int = 86400,  # 24 hours
    ):
        """
        Initialize Redis blacklist adapter.

        Args:
            redis_client: Redis client instance (redis.Redis)
            prefix: Key prefix for blacklisted tokens
            default_ttl: Default TTL for blacklisted tokens (seconds)
        """
        self._redis = redis_client
        self._prefix = prefix
        self._default_ttl = default_ttl

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

    def _key(self, token: str) -> str:
        """
        Generate Redis key for token.

        Uses SHA256 hash to avoid storing full token in key (privacy).
        """
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
        return f"{self._prefix}{token_hash}"

    def is_blacklisted(self, token: str) -> bool:
        """
        Check if token is blacklisted.

        Args:
            token: Token to check

        Returns:
            True if blacklisted, False otherwise
        """
        try:
            redis = self._get_redis()
            key = self._key(token)
            return redis.exists(key) > 0
        except Exception:
            # Redis error - fail safe (assume not blacklisted)
            return False

    def add(self, token: str, ttl: Optional[int] = None) -> bool:
        """
        Add token to blacklist with TTL.

        Args:
            token: Token to blacklist
            ttl: Time-to-live in seconds (None = use default)

        Returns:
            True if added, False if already blacklisted
        """
        try:
            redis = self._get_redis()
            key = self._key(token)

            # Check if already blacklisted
            if redis.exists(key):
                return False

            # Add with TTL (auto-expires)
            ttl = ttl or self._default_ttl
            redis.setex(key, ttl, "1")
            return True

        except Exception:
            # Redis error - fail safe
            return False

    def remove(self, token: str) -> bool:
        """
        Remove token from blacklist.

        Args:
            token: Token to remove

        Returns:
            True if removed, False if not found
        """
        try:
            redis = self._get_redis()
            key = self._key(token)
            deleted = redis.delete(key)
            return deleted > 0
        except Exception:
            return False

    def cleanup_expired(self) -> int:
        """
        Clean up expired blacklist entries.

        Redis handles expiration automatically via TTL.
        This method is a no-op but provided for interface compatibility.

        Returns:
            0 (Redis auto-expires)
        """
        return 0
