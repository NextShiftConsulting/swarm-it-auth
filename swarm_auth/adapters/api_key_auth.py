"""
API Key Authentication Adapter - Simple API key-based auth.

Used by swarm-it-api marketplace for RapidAPI integration.
"""

import secrets
import hashlib
from typing import Optional, Dict
from swarm_auth.ports.auth_port import AuthenticationPort
from swarm_auth.domain.principal import Principal
from swarm_auth.domain.user import User  # noqa: F401 — kept for register_user() compat


class APIKeyAuthAdapter(AuthenticationPort):
    """
    API key-based authentication adapter.

    Suitable for service-to-service authentication.
    Keys are hashed before storage (SHA-256).
    """

    def __init__(self):
        """Initialize API key adapter with in-memory store."""
        # In production: use database or key-value store
        # Format: {hashed_key: user_id}
        self._keys: Dict[str, str] = {}
        # Format: {user_id: Principal}
        self._users: Dict[str, Principal] = {}

    def authenticate(self, token: str) -> Optional[Principal]:
        """
        Authenticate an API key.

        Args:
            token: API key (plain text)

        Returns:
            User if valid, None if invalid
        """
        hashed = self._hash_key(token)
        user_id = self._keys.get(hashed)

        if not user_id:
            return None

        return self._users.get(user_id)

    def create_token(self, principal: Principal, expires_in: int = 3600) -> str:
        """
        Create an API key for a user.

        Args:
            user: User to create key for
            expires_in: Ignored (API keys don't expire by default)

        Returns:
            API key string (store this - it can't be recovered!)
        """
        # Generate random API key
        api_key = f"sk_{secrets.token_urlsafe(32)}"

        # Hash and store
        hashed = self._hash_key(api_key)
        self._keys[hashed] = principal.user_id
        self._users[principal.user_id] = principal

        return api_key

    def verify_token(self, token: str) -> bool:
        """
        Verify if an API key is valid.

        Args:
            token: API key

        Returns:
            True if valid, False otherwise
        """
        hashed = self._hash_key(token)
        return hashed in self._keys

    def revoke_token(self, token: str) -> bool:
        """
        Revoke an API key.

        Args:
            token: API key to revoke

        Returns:
            True if revoked, False if not found
        """
        hashed = self._hash_key(token)

        if hashed not in self._keys:
            return False

        del self._keys[hashed]
        return True

    @staticmethod
    def _hash_key(key: str) -> str:
        """Hash an API key with SHA-256."""
        return hashlib.sha256(key.encode()).hexdigest()

    def register_user(self, user: Principal) -> str:
        """
        Register a principal and generate an API key.

        Args:
            user: Principal (HumanUser or AgentIdentity) to register.
                  Parameter named 'user' for backward compatibility.

        Returns:
            Generated API key
        """
        self._users[user.user_id] = user
        return self.create_token(user)
