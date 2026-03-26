"""
Swarm-It Auth - Session & Credential Management

Hexagonal architecture for authentication and session management
across the Swarm-It platform.

Usage:
    # P18 v3.0 - Unified Credential Access (preferred)
    from swarm_auth import get_credential, get_aws_credentials, has_credential

    api_key = get_credential('OPENAI_API_KEY')
    aws = get_aws_credentials()

    # Full auth client
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

# P18 v3.0 - Unified credential access
from swarm_auth.credentials import get_credential, get_aws_credentials, has_credential

# Auth client and domain objects
from swarm_auth.sdk.client import AuthClient
from swarm_auth.domain.user import User
from swarm_auth.domain.session import Session
from swarm_auth.domain.credential import Credential

__all__ = [
    # P18 v3.0 Credential Gateway
    "get_credential",
    "get_aws_credentials",
    "has_credential",
    # Auth client
    "AuthClient",
    # Domain objects
    "User",
    "Session",
    "Credential",
]
