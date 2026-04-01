"""
Swarm-It Auth - Session & Credential Management

Hexagonal architecture for authentication and session management
across the Swarm-It platform.

Usage:
    # P18 v4.0 - AccessScript Credential Triage (SOTA)
    from swarm_auth import get_credential, has_credential, AccessScript

    # Simple usage - auto-discovers available sources
    api_key = get_credential('OPENAI_API_KEY')

    # Configured usage - explicit priority and forbidden sources
    access = AccessScript.from_config({
        "priority": ["env_var", "dotenv", "aws_secrets"],
        "forbidden": ["kms"],  # Don't attempt in this env
    })
    api_key = access.get('OPENAI_API_KEY')

    # AWS credentials helper
    aws = get_aws_credentials()

    # Auth client via factory (recommended)
    from swarm_auth import create_jwt_auth, create_auth_client

    auth = create_jwt_auth(secret="my-secret")  # memory blacklist
    auth = create_jwt_auth(secret="my-secret", blacklist="redis", redis_url="redis://localhost")

    client = create_auth_client(
        secret="my-secret",
        session_backend="redis",
        redis_url="redis://localhost",
    )

    # Or manual assembly with explicit adapters
    from swarm_auth.adapters import JWTAuthAdapter, MemoryBlacklistAdapter
    auth = JWTAuthAdapter(secret="my-secret", blacklist_adapter=MemoryBlacklistAdapter())
"""

__version__ = "0.2.0"

# P18 v4.0 - AccessScript credential triage
from swarm_auth.access_script import (
    AccessScript,
    AccessScriptConfig,
    SourceType,
    OnForbidden,
    get_credential,
    has_credential,
)

# Legacy credential helpers (still useful)
from swarm_auth.credentials import get_aws_credentials

# Auth client and domain objects
from swarm_auth.sdk.client import AuthClient
from swarm_auth.domain.user import User, UserRole
from swarm_auth.domain.session import Session
from swarm_auth.domain.credential import Credential

# Factory functions (composition root)
from swarm_auth.factory import (
    create_blacklist,
    create_session_store,
    create_jwt_auth,
    create_auth_client,
)

__all__ = [
    # P18 v4.0 AccessScript Credential Triage
    "AccessScript",
    "AccessScriptConfig",
    "SourceType",
    "OnForbidden",
    "get_credential",
    "has_credential",
    "get_aws_credentials",
    # Factory functions (recommended)
    "create_blacklist",
    "create_session_store",
    "create_jwt_auth",
    "create_auth_client",
    # Auth client
    "AuthClient",
    # Domain objects
    "User",
    "UserRole",
    "Session",
    "Credential",
]
