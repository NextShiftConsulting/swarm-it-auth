"""
JWT Authentication Adapter - Implements AuthenticationPort with JWT tokens.
"""

import jwt
from datetime import datetime, timedelta
from typing import Optional, Set
from swarm_auth.ports.auth_port import AuthenticationPort
from swarm_auth.domain.user import User, UserRole


class JWTAuthAdapter(AuthenticationPort):
    """
    JWT-based authentication adapter.

    Uses PyJWT for token creation and verification.
    Supports token blacklisting via Redis (falls back to in-memory if unavailable).
    """

    def __init__(
        self,
        secret: str,
        algorithm: str = "HS256",
        issuer: str = "swarm-it",
        redis_client=None,
        blacklist_prefix: str = "swarm:jwt:blacklist:",
        blacklist_ttl: int = 86400,  # 24 hours default
    ):
        """
        Initialize JWT adapter.

        Args:
            secret: JWT signing secret
            algorithm: JWT algorithm (default HS256)
            issuer: Token issuer claim
            redis_client: Optional Redis client for distributed blacklist
            blacklist_prefix: Redis key prefix for blacklisted tokens
            blacklist_ttl: TTL for blacklisted tokens in seconds (default 24h)
        """
        self._secret = secret
        self._algorithm = algorithm
        self._issuer = issuer
        self._redis = redis_client
        self._blacklist_prefix = blacklist_prefix
        self._blacklist_ttl = blacklist_ttl
        self._memory_blacklist: Set[str] = set()  # Fallback for when Redis unavailable
        self._use_redis = False  # Track if Redis is available

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
                self._use_redis = True
            except ImportError:
                # Redis not installed, use in-memory fallback
                self._use_redis = False
                return None
            except Exception:
                # Redis connection failed, use in-memory fallback
                self._use_redis = False
                return None
        else:
            self._use_redis = True
        return self._redis

    def _blacklist_key(self, token: str) -> str:
        """Generate Redis key for blacklisted token."""
        # Use hash of token to avoid storing full token in key
        import hashlib
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
        return f"{self._blacklist_prefix}{token_hash}"

    def _is_blacklisted(self, token: str) -> bool:
        """Check if token is blacklisted (Redis or in-memory)."""
        redis = self._get_redis()
        if redis and self._use_redis:
            try:
                key = self._blacklist_key(token)
                return redis.exists(key) > 0
            except Exception:
                # Redis error, fallback to memory
                return token in self._memory_blacklist
        else:
            return token in self._memory_blacklist

    def _add_to_blacklist(self, token: str) -> bool:
        """Add token to blacklist (Redis or in-memory)."""
        redis = self._get_redis()
        if redis and self._use_redis:
            try:
                key = self._blacklist_key(token)
                # Set with TTL (tokens auto-expire after blacklist_ttl)
                redis.setex(key, self._blacklist_ttl, "1")
                return True
            except Exception:
                # Redis error, fallback to memory
                self._memory_blacklist.add(token)
                return True
        else:
            self._memory_blacklist.add(token)
            return True

    def authenticate(self, token: str) -> Optional[User]:
        """
        Authenticate a JWT token.

        Args:
            token: JWT token string

        Returns:
            User if valid, None if invalid
        """
        if not token or self._is_blacklisted(token):
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
        if self._is_blacklisted(token):
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
        if self._is_blacklisted(token):
            return False

        self._add_to_blacklist(token)
        return True
