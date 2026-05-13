"""
JWT Authentication Adapter - Implements AuthenticationPort with JWT tokens.

ADR-028 Stage 3: principal_kind discriminator added.
- create_token() adds principal_kind="human"|"agent" to every new token.
- authenticate() reads principal_kind first, then constructs HumanUser or AgentIdentity.
- Legacy tokens without principal_kind decode safely as HumanUser (backward compat).
- is_service_account remains in payloads until Stage 4 removes it from jwt_auth.

Stage 4 TODOs:
- TODO(Stage 4): remove is_service_account from JWT payload (use principal_kind instead)
- TODO(Stage 4): add ActorChain propagation (ADR-026 Rule 6)
"""

import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional

from swarm_auth.ports.auth_port import AuthenticationPort
from swarm_auth.ports.blacklist_port import BlacklistPort
from swarm_auth.domain.principal import Principal
from swarm_auth.domain.human_user import HumanUser
from swarm_auth.domain.agent_identity import AgentIdentity, AgentType
from swarm_auth.domain.roles import UserRole


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
        blacklist_adapter: BlacklistPort = None,
    ):
        """
        Initialize JWT adapter.

        Args:
            secret: JWT signing secret
            algorithm: JWT algorithm (default HS256)
            issuer: Token issuer claim
            blacklist_adapter: Blacklist adapter (required). Use factory.create_jwt_auth()
                              for convenient defaults.

        Raises:
            ValueError: If blacklist_adapter is not provided
        """
        if blacklist_adapter is None:
            raise ValueError(
                "blacklist_adapter is required. Use swarm_auth.factory.create_jwt_auth() "
                "for convenient defaults, or inject a BlacklistPort implementation."
            )

        self._secret = secret
        self._algorithm = algorithm
        self._issuer = issuer
        self._blacklist = blacklist_adapter

    def authenticate(self, token: str) -> Optional[Principal]:
        """
        Authenticate a JWT token and return the correct Principal subtype.

        Reads principal_kind first to select the constructor:
        - "agent"  → AgentIdentity
        - "human"  → HumanUser
        - absent   → HumanUser (legacy tokens, backward compat, logs deprecation warning)

        Args:
            token: JWT token string

        Returns:
            Principal (HumanUser or AgentIdentity) if valid, None if invalid
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

            principal_kind = payload.get("principal_kind")

            if principal_kind == "agent":
                return AgentIdentity(
                    user_id=payload["sub"],
                    username=payload.get("username", payload["sub"]),
                    role=UserRole(payload.get("role", "service")),
                    agent_type=AgentType(payload.get("agent_type", "service")),
                    is_active=True,
                )

            # "human" or absent (legacy token) → HumanUser
            if principal_kind is None:
                # Legacy token predating Stage 3 — safe fallback
                import warnings
                warnings.warn(
                    "JWT token missing principal_kind claim — assuming HumanUser. "
                    "Re-issue the token to suppress this warning.",
                    DeprecationWarning,
                    stacklevel=2,
                )

            return HumanUser(
                user_id=payload["sub"],
                username=payload.get("username", payload["sub"]),
                role=UserRole(payload.get("role", "developer")),
                email=payload.get("email"),
                org_id=payload.get("org_id"),
                is_service_account=payload.get("is_service_account", False),
            )

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except (KeyError, ValueError):
            return None

    def create_token(self, principal: Principal, expires_in: int = 3600) -> str:
        """
        Create a JWT token for a principal.

        Always includes principal_kind ("human" or "agent").
        For AgentIdentity, also includes agent_type.
        Retains is_service_account for backward compat until Stage 4.

        Args:
            principal: Principal (HumanUser or AgentIdentity) to create token for
            expires_in: Token expiration in seconds

        Returns:
            JWT token string
        """
        now = datetime.now(timezone.utc)
        payload = {
            "sub": principal.user_id,
            "username": principal.username,
            "role": principal.role.value,
            "principal_kind": principal.kind(),  # "human" or "agent" (ADR-028 SD-1)
            "iat": now,
            "exp": now + timedelta(seconds=expires_in),
            "iss": self._issuer,
        }

        if isinstance(principal, AgentIdentity):
            payload["agent_type"] = principal.agent_type.value
            payload["is_service_account"] = True  # deprecated — Stage 4 removes this
        elif isinstance(principal, HumanUser):
            payload["email"] = principal.email
            payload["org_id"] = principal.org_id
            payload["is_service_account"] = False  # deprecated — Stage 4 removes this

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
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                issuer=self._issuer,
            )
            exp = payload.get("exp")
            if exp:
                exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
                ttl = int((exp_time - datetime.now(timezone.utc)).total_seconds())
                if ttl > 0:
                    return self._blacklist.add(token, ttl)
        except jwt.InvalidTokenError:
            pass

        return self._blacklist.add(token)
