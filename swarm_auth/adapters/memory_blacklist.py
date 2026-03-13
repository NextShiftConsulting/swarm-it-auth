"""
Memory Blacklist Adapter - In-memory token blacklist.
"""

from typing import Optional, Set, Dict
from datetime import datetime, timedelta
from swarm_auth.ports.blacklist_port import BlacklistPort


class MemoryBlacklistAdapter(BlacklistPort):
    """
    In-memory token blacklist.

    - Fast lookups (set-based)
    - No external dependencies
    - Not distributed (local process only)
    - Suitable for development and single-instance deployments
    """

    def __init__(self, default_ttl: int = 86400):
        """
        Initialize in-memory blacklist adapter.

        Args:
            default_ttl: Default TTL for blacklisted tokens (seconds)
        """
        self._blacklist: Set[str] = set()
        self._expiration: Dict[str, datetime] = {}
        self._default_ttl = default_ttl

    def is_blacklisted(self, token: str) -> bool:
        """
        Check if token is blacklisted.

        Args:
            token: Token to check

        Returns:
            True if blacklisted and not expired, False otherwise
        """
        if token not in self._blacklist:
            return False

        # Check expiration
        if token in self._expiration:
            if datetime.utcnow() > self._expiration[token]:
                # Expired - remove and return False
                self._blacklist.discard(token)
                del self._expiration[token]
                return False

        return True

    def add(self, token: str, ttl: Optional[int] = None) -> bool:
        """
        Add token to blacklist.

        Args:
            token: Token to blacklist
            ttl: Time-to-live in seconds (None = use default)

        Returns:
            True if added, False if already blacklisted
        """
        if self.is_blacklisted(token):
            return False

        self._blacklist.add(token)

        # Set expiration
        ttl = ttl or self._default_ttl
        self._expiration[token] = datetime.utcnow() + timedelta(seconds=ttl)

        return True

    def remove(self, token: str) -> bool:
        """
        Remove token from blacklist.

        Args:
            token: Token to remove

        Returns:
            True if removed, False if not found
        """
        if token not in self._blacklist:
            return False

        self._blacklist.discard(token)
        self._expiration.pop(token, None)
        return True

    def cleanup_expired(self) -> int:
        """
        Clean up expired blacklist entries.

        Returns:
            Number of entries cleaned up
        """
        now = datetime.utcnow()
        expired = [
            token
            for token, exp_time in self._expiration.items()
            if now > exp_time
        ]

        for token in expired:
            self._blacklist.discard(token)
            del self._expiration[token]

        return len(expired)
