"""
JWT Authentication Adapter - Implements AuthenticationPort with JWT tokens.
"""

import jwt
from datetime import datetime, timedelta
from typing import Optional
from swarm_auth.ports.auth_port import AuthenticationPort
from swarm_auth.ports.blacklist_port import BlacklistPort
from swarm_auth.domain.user import User, UserRole


class JWTAuthAdapter(AuthenticationPort):
    """
    JWT-based authentication adapter.

    Uses PyJWT for token creation and verification.
    Supports token blacklisting via pluggable BlacklistPort adapter.
    """

    def __init__(
        self,
        secret: str,
        algorithm: str = "HS256",
        issuer: str = "swarm-it",
        blacklist_adapter: Optional[BlacklistPort] = None,
    ):
        """
        Initialize JWT adapter.

        Args:
            secret: JWT signing secret
            algorithm: JWT algorithm (default HS256)
            issuer: Token issuer claim
            blacklist_adapter: Optional blacklist adapter (defaults to MemoryBlacklistAdapter)
        """
        self._secret = secret
        self._algorithm = algorithm
        self._issuer = issuer

        # Use provided blacklist adapter or default to in-memory
        if blacklist_adapter is None:
            from swarm_auth.adapters.memory_blacklist import MemoryBlacklistAdapter
            self._blacklist = MemoryBlacklistAdapter()
        else:
            self._blacklist = blacklist_adapter

    def authenticate(self, token: str) -> Optional[User]:
        """
        Authenticate a JWT token.

        Args:
            token: JWT token string

        Returns:
            User if valid, None if invalid
        """
        if not token or self._blacklist.is_blacklisted(token):
            return None

        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                issuer=self._issuer,
            )

            # Extract user from payload
            user = User(
                user_id=payload["sub"],
                username=payload.get("username", payload["sub"]),
                role=UserRole(payload.get("role", "developer")),
                email=payload.get("email"),
                org_id=payload.get("org_id"),
                is_service_account=payload.get("is_service_account", False),
            )

            return user

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except (KeyError, ValueError):
            return None

    def create_token(self, user: User, expires_in: int = 3600) -> str:
        """
        Create a JWT token for a user.

        Args:
            user: User to create token for
            expires_in: Token expiration in seconds

        Returns:
            JWT token string
        """
        now = datetime.utcnow()
        payload = {
            "sub": user.user_id,
            "username": user.username,
            "role": user.role.value,
            "email": user.email,
            "org_id": user.org_id,
            "is_service_account": user.is_service_account,
            "iat": now,
            "exp": now + timedelta(seconds=expires_in),
            "iss": self._issuer,
        }

        token = jwt.encode(payload, self._secret, algorithm=self._algorithm)
        return token

    def verify_token(self, token: str) -> bool:
        """
        Verify if a token is valid.

        Args:
            token: JWT token

        Returns:
            True if valid, False otherwise
        """
        if self._blacklist.is_blacklisted(token):
            return False

        try:
            jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                issuer=self._issuer,
            )
            return True
        except jwt.InvalidTokenError:
            return False

    def revoke_token(self, token: str) -> bool:
        """
        Revoke a token by adding to blacklist.

        Args:
            token: Token to revoke

        Returns:
            True if revoked, False if already revoked
        """
        # Extract expiration from token for TTL
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                issuer=self._issuer,
            )
            exp = payload.get("exp")
            if exp:
                # Calculate remaining TTL
                exp_time = datetime.fromtimestamp(exp)
                ttl = int((exp_time - datetime.utcnow()).total_seconds())
                if ttl > 0:
                    return self._blacklist.add(token, ttl)
        except jwt.InvalidTokenError:
            pass

        # Fallback: use default TTL
        return self._blacklist.add(token)
