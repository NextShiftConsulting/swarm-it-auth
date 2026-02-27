"""
Auth Client - High-level SDK for auth operations.

Simplifies common auth workflows for application developers.
"""

from typing import Optional, Dict, Any
from swarm_auth.ports.auth_port import AuthenticationPort
from swarm_auth.ports.session_port import SessionPort
from swarm_auth.ports.credential_port import CredentialPort
from swarm_auth.domain.user import User
from swarm_auth.domain.session import Session


class AuthClient:
    """
    High-level auth client combining authentication, sessions, and credentials.

    Example:
        from swarm_auth import AuthClient
        from swarm_auth.adapters import JWTAuthAdapter, RedisSessionAdapter

        client = AuthClient(
            auth=JWTAuthAdapter(secret="secret"),
            sessions=RedisSessionAdapter(),
        )

        # Login
        token = client.login(user)
        session = client.get_session(token)

        # Logout
        client.logout(token)
    """

    def __init__(
        self,
        auth: AuthenticationPort,
        sessions: Optional[SessionPort] = None,
        credentials: Optional[CredentialPort] = None,
    ):
        """
        Initialize auth client with adapters.

        Args:
            auth: Authentication adapter (required)
            sessions: Session adapter (optional)
            credentials: Credential adapter (optional)
        """
        self._auth = auth
        self._sessions = sessions
        self._credentials = credentials

    def login(
        self,
        user: User,
        ttl: int = 3600,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log in a user (create token + session).

        Args:
            user: User to log in
            ttl: Token/session TTL in seconds
            metadata: Optional session metadata

        Returns:
            Dict with 'token' and optionally 'session'
        """
        token = self._auth.create_token(user, expires_in=ttl)

        result = {"token": token}

        if self._sessions:
            session = self._sessions.create(
                user_id=user.user_id,
                ttl=ttl,
                metadata=metadata,
            )
            result["session"] = session.to_dict()

        return result

    def logout(self, token: str) -> bool:
        """
        Log out a user (revoke token + delete session).

        Args:
            token: Token to revoke

        Returns:
            True if logged out successfully
        """
        user = self._auth.authenticate(token)
        success = self._auth.revoke_token(token)

        if self._sessions and user:
            # Delete all sessions for this user
            sessions = self._sessions.list_by_user(user.user_id)
            for session in sessions:
                self._sessions.delete(session.session_id)

        return success

    def verify(self, token: str) -> Optional[User]:
        """
        Verify a token and return the user.

        Args:
            token: Token to verify

        Returns:
            User if valid, None otherwise
        """
        return self._auth.authenticate(token)

    def get_session(self, session_id: str) -> Optional[Session]:
        """
        Get a session by ID.

        Args:
            session_id: Session ID

        Returns:
            Session if found and valid, None otherwise
        """
        if not self._sessions:
            return None

        return self._sessions.get(session_id)

    def extend_session(self, session_id: str, ttl: int = 3600) -> bool:
        """
        Extend a session's TTL.

        Args:
            session_id: Session ID
            ttl: Additional seconds to extend

        Returns:
            True if extended, False otherwise
        """
        if not self._sessions:
            return False

        return self._sessions.extend(session_id, ttl)

    def get_credential(self, key: str) -> Optional[str]:
        """
        Get a credential value.

        Args:
            key: Credential key

        Returns:
            Credential value or None
        """
        if not self._credentials:
            return None

        return self._credentials.retrieve(key)

    def store_credential(
        self,
        key: str,
        value: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Store a credential.

        Args:
            key: Credential key
            value: Credential value
            metadata: Optional metadata

        Returns:
            True if stored successfully
        """
        if not self._credentials:
            return False

        self._credentials.store(key, value, metadata)
        return True
