"""
Authentication Port - Interface for user authentication.

Implementations:
- JWTAuthAdapter: JWT token-based auth
- APIKeyAuthAdapter: API key-based auth
- OAuth2Adapter: OAuth2 flows
"""

from abc import ABC, abstractmethod
from typing import Optional
from swarm_auth.domain.user import User


class AuthenticationPort(ABC):
    """Port: Authenticate users and validate tokens."""

    @abstractmethod
    def authenticate(self, token: str) -> Optional[User]:
        """
        Authenticate a token and return the user.

        Args:
            token: Authentication token (JWT, API key, etc.)

        Returns:
            User if valid, None if invalid

        Raises:
            AuthenticationError: If token is malformed or verification fails
        """
        pass

    @abstractmethod
    def create_token(self, user: User, expires_in: int = 3600) -> str:
        """
        Create an authentication token for a user.

        Args:
            user: User to create token for
            expires_in: Token expiration in seconds (default 1 hour)

        Returns:
            Authentication token string
        """
        pass

    @abstractmethod
    def verify_token(self, token: str) -> bool:
        """
        Verify if a token is valid without extracting user info.

        Args:
            token: Token to verify

        Returns:
            True if valid, False otherwise
        """
        pass

    @abstractmethod
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token (blacklist it).

        Args:
            token: Token to revoke

        Returns:
            True if revoked, False if already revoked or not found
        """
        pass
