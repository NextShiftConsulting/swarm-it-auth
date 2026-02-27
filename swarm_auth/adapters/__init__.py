"""
Adapters - Implementations of ports.

Authentication & Sessions:
- JWTAuthAdapter: JWT token authentication
- APIKeyAuthAdapter: API key authentication
- RedisSessionAdapter: Redis-backed sessions
- MemorySessionAdapter: In-memory sessions (testing)
- DynamoDBSessionAdapter: AWS DynamoDB sessions

Credential Storage:
- EnvCredentialAdapter: Environment variable credentials
- VaultCredentialAdapter: HashiCorp Vault for secrets
- AWSSecretsAdapter: AWS Secrets Manager

Authorization (PDP):
- RBACPolicyAdapter: Role-based access control

Credential Brokers (outbound provider access):
- AWSCredentialBroker: AWS STS temporary credentials
- GCPCredentialBroker: GCP Workload Identity Federation
- OpenAICredentialBroker: OpenAI project-scoped keys
"""

# Authentication & Sessions
from swarm_auth.adapters.jwt_auth import JWTAuthAdapter
from swarm_auth.adapters.api_key_auth import APIKeyAuthAdapter
from swarm_auth.adapters.redis_session import RedisSessionAdapter
from swarm_auth.adapters.memory_session import MemorySessionAdapter
from swarm_auth.adapters.dynamodb_session import DynamoDBSessionAdapter

# Credential Storage
from swarm_auth.adapters.env_credential import EnvCredentialAdapter
from swarm_auth.adapters.vault_credential import VaultCredentialAdapter
from swarm_auth.adapters.aws_credential import AWSSecretsAdapter

# Authorization
from swarm_auth.adapters.rbac_policy import RBACPolicyAdapter

# Credential Brokers
from swarm_auth.adapters.aws_credential_broker import AWSCredentialBroker
from swarm_auth.adapters.gcp_credential_broker import GCPCredentialBroker
from swarm_auth.adapters.openai_credential_broker import OpenAICredentialBroker

__all__ = [
    # Authentication & Sessions
    "JWTAuthAdapter",
    "APIKeyAuthAdapter",
    "RedisSessionAdapter",
    "MemorySessionAdapter",
    "DynamoDBSessionAdapter",
    # Credential Storage
    "EnvCredentialAdapter",
    "VaultCredentialAdapter",
    "AWSSecretsAdapter",
    # Authorization
    "RBACPolicyAdapter",
    # Credential Brokers
    "AWSCredentialBroker",
    "GCPCredentialBroker",
    "OpenAICredentialBroker",
]
