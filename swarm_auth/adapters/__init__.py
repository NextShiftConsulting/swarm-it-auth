"""
Adapters - Implementations of ports.

Each adapter implements a port interface using specific technology:
- JWTAuthAdapter: JWT token authentication
- RedisSessionAdapter: Redis-backed sessions
- VaultCredentialAdapter: HashiCorp Vault for secrets
"""

from swarm_auth.adapters.jwt_auth import JWTAuthAdapter
from swarm_auth.adapters.api_key_auth import APIKeyAuthAdapter
from swarm_auth.adapters.redis_session import RedisSessionAdapter
from swarm_auth.adapters.memory_session import MemorySessionAdapter
from swarm_auth.adapters.env_credential import EnvCredentialAdapter

__all__ = [
    "JWTAuthAdapter",
    "APIKeyAuthAdapter",
    "RedisSessionAdapter",
    "MemorySessionAdapter",
    "EnvCredentialAdapter",
]
