"""
Factory - Composition root for adapter assembly.

Hexagonal architecture: Adapters should not depend on other adapters.
This factory assembles adapters with sensible defaults.

Usage:
    from swarm_auth.factory import create_jwt_auth, create_auth_client

    # Simple JWT auth with in-memory blacklist
    auth = create_jwt_auth(secret="my-secret")

    # JWT auth with Redis blacklist
    auth = create_jwt_auth(secret="my-secret", blacklist="redis", redis_url="redis://localhost")

    # Full auth client
    client = create_auth_client(
        secret="my-secret",
        session_backend="redis",
        redis_url="redis://localhost",
    )
"""

from typing import Optional, Literal
from swarm_auth.ports.auth_port import AuthenticationPort
from swarm_auth.ports.session_port import SessionPort
from swarm_auth.ports.blacklist_port import BlacklistPort


def create_blacklist(
    backend: Literal["memory", "redis"] = "memory",
    redis_url: Optional[str] = None,
    redis_prefix: str = "blacklist:",
) -> BlacklistPort:
    """
    Create a blacklist adapter.

    Args:
        backend: "memory" or "redis"
        redis_url: Redis URL (required if backend="redis")
        redis_prefix: Key prefix for Redis

    Returns:
        BlacklistPort implementation
    """
    if backend == "memory":
        from swarm_auth.adapters.memory_blacklist import MemoryBlacklistAdapter
        return MemoryBlacklistAdapter()

    elif backend == "redis":
        if not redis_url:
            raise ValueError("redis_url required for redis backend")
        from swarm_auth.adapters.redis_blacklist import RedisBlacklistAdapter
        return RedisBlacklistAdapter(redis_url=redis_url, prefix=redis_prefix)

    else:
        raise ValueError(f"Unknown blacklist backend: {backend}")


def create_session_store(
    backend: Literal["memory", "redis", "dynamodb"] = "memory",
    redis_url: Optional[str] = None,
    dynamodb_table: Optional[str] = None,
    region_name: str = "us-east-1",
) -> SessionPort:
    """
    Create a session store adapter.

    Args:
        backend: "memory", "redis", or "dynamodb"
        redis_url: Redis URL (required if backend="redis")
        dynamodb_table: DynamoDB table name (required if backend="dynamodb")
        region_name: AWS region for DynamoDB

    Returns:
        SessionPort implementation
    """
    if backend == "memory":
        from swarm_auth.adapters.memory_session import MemorySessionAdapter
        return MemorySessionAdapter()

    elif backend == "redis":
        if not redis_url:
            raise ValueError("redis_url required for redis backend")
        from swarm_auth.adapters.redis_session import RedisSessionAdapter
        return RedisSessionAdapter(redis_url=redis_url)

    elif backend == "dynamodb":
        if not dynamodb_table:
            raise ValueError("dynamodb_table required for dynamodb backend")
        from swarm_auth.adapters.dynamodb_session import DynamoDBSessionAdapter
        return DynamoDBSessionAdapter(table_name=dynamodb_table, region_name=region_name)

    else:
        raise ValueError(f"Unknown session backend: {backend}")


def create_jwt_auth(
    secret: str,
    algorithm: str = "HS256",
    issuer: str = "swarm-it",
    blacklist: Literal["memory", "redis"] = "memory",
    redis_url: Optional[str] = None,
) -> AuthenticationPort:
    """
    Create a JWT authentication adapter with blacklist.

    Args:
        secret: JWT signing secret
        algorithm: JWT algorithm (default HS256)
        issuer: Token issuer claim
        blacklist: Blacklist backend ("memory" or "redis")
        redis_url: Redis URL (required if blacklist="redis")

    Returns:
        AuthenticationPort implementation (JWTAuthAdapter)
    """
    blacklist_adapter = create_blacklist(backend=blacklist, redis_url=redis_url)

    from swarm_auth.adapters.jwt_auth import JWTAuthAdapter
    return JWTAuthAdapter(
        secret=secret,
        algorithm=algorithm,
        issuer=issuer,
        blacklist_adapter=blacklist_adapter,
    )


def create_auth_client(
    secret: str,
    algorithm: str = "HS256",
    issuer: str = "swarm-it",
    blacklist: Literal["memory", "redis"] = "memory",
    session_backend: Literal["memory", "redis", "dynamodb"] = "memory",
    redis_url: Optional[str] = None,
    dynamodb_table: Optional[str] = None,
    region_name: str = "us-east-1",
):
    """
    Create a fully configured AuthClient.

    Args:
        secret: JWT signing secret
        algorithm: JWT algorithm
        issuer: Token issuer
        blacklist: Blacklist backend
        session_backend: Session store backend
        redis_url: Redis URL (for redis backends)
        dynamodb_table: DynamoDB table (for dynamodb session backend)
        region_name: AWS region for DynamoDB

    Returns:
        Configured AuthClient
    """
    from swarm_auth.sdk.client import AuthClient

    auth = create_jwt_auth(
        secret=secret,
        algorithm=algorithm,
        issuer=issuer,
        blacklist=blacklist,
        redis_url=redis_url,
    )

    sessions = create_session_store(
        backend=session_backend,
        redis_url=redis_url,
        dynamodb_table=dynamodb_table,
        region_name=region_name,
    )

    return AuthClient(auth=auth, sessions=sessions)
