"""
Adapters - Implementations of ports.

Each adapter implements a port interface using specific technology:
- JWTAuthAdapter: JWT token authentication
- APIKeyAuthAdapter: API key authentication
- RedisSessionAdapter: Redis-backed sessions
- MemorySessionAdapter: In-memory sessions (testing)
- DynamoDBSessionAdapter: AWS DynamoDB sessions
- EnvCredentialAdapter: Environment variable credentials
- VaultCredentialAdapter: HashiCorp Vault for secrets
- AWSSecretsAdapter: AWS Secrets Manager
"""

from swarm_auth.adapters.jwt_auth import JWTAuthAdapter
from swarm_auth.adapters.api_key_auth import APIKeyAuthAdapter
from swarm_auth.adapters.redis_session import RedisSessionAdapter
from swarm_auth.adapters.memory_session import MemorySessionAdapter
from swarm_auth.adapters.dynamodb_session import DynamoDBSessionAdapter
from swarm_auth.adapters.env_credential import EnvCredentialAdapter
from swarm_auth.adapters.vault_credential import VaultCredentialAdapter
from swarm_auth.adapters.aws_credential import AWSSecretsAdapter

__all__ = [
    "JWTAuthAdapter",
    "APIKeyAuthAdapter",
    "RedisSessionAdapter",
    "MemorySessionAdapter",
    "DynamoDBSessionAdapter",
    "EnvCredentialAdapter",
    "VaultCredentialAdapter",
    "AWSSecretsAdapter",
]
