"""
Blacklist Port - Interface for token blacklist management.

Implementations:
- RedisBlacklistAdapter: Redis-backed blacklist with TTL
- MemoryBlacklistAdapter: In-memory blacklist (testing/development)
"""

from abc import ABC, abstractmethod
from typing import Optional


class BlacklistPort(ABC):
    """Port: Manage token blacklist for revocation."""

    @abstractmethod
    def is_blacklisted(self, token: str) -> bool:
        """
        Check if a token is blacklisted.

        Args:
            token: Token to check

        Returns:
            True if blacklisted, False otherwise
        """
        pass

    @abstractmethod
    def add(self, token: str, ttl: Optional[int] = None) -> bool:
        """
        Add a token to the blacklist.

        Args:
            token: Token to blacklist
            ttl: Time-to-live in seconds (None = permanent)

        Returns:
            True if added, False if already blacklisted
        """
        pass

    @abstractmethod
    def remove(self, token: str) -> bool:
        """
        Remove a token from the blacklist.

        Args:
            token: Token to remove

        Returns:
            True if removed, False if not found
        """
        pass

    @abstractmethod
    def cleanup_expired(self) -> int:
        """
        Clean up expired blacklist entries.

        Returns:
            Number of entries cleaned up
        """
        pass
