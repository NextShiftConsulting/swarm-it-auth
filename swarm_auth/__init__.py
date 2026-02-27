"""
Swarm-It Auth - Session & Credential Management

Hexagonal architecture for authentication and session management
across the Swarm-It platform.

Usage:
    from swarm_auth import AuthClient
    from swarm_auth.adapters import JWTAuthAdapter, RedisSessionAdapter

    auth = JWTAuthAdapter(secret="your-secret")
    sessions = RedisSessionAdapter(redis_url="redis://localhost")

    # Authenticate
    user = auth.authenticate(token)

    # Create session
    session = sessions.create(user.id)
"""

__version__ = "0.1.0"

from swarm_auth.sdk.client import AuthClient
from swarm_auth.domain.user import User
from swarm_auth.domain.session import Session
from swarm_auth.domain.credential import Credential

__all__ = [
    "AuthClient",
    "User",
    "Session",
    "Credential",
]
