"""
Adapters - Implementations of ports.

Authentication & Sessions:
- JWTAuthAdapter: JWT token authentication
- APIKeyAuthAdapter: API key authentication (used by marketplace)
- HeaderIdentityAdapter: Trust identity headers from gateway (OAuth2-Proxy, Envoy)
- RedisSessionAdapter: Redis-backed sessions
- MemorySessionAdapter: In-memory sessions (testing)
- DynamoDBSessionAdapter: AWS DynamoDB sessions

Token Blacklist:
- RedisBlacklistAdapter: Redis-backed token blacklist
- MemoryBlacklistAdapter: In-memory token blacklist

Credential Storage:
- EnvCredentialAdapter: Environment variable credentials
- DotEnvAdapter: .env file credentials (auto-discovery)
- KeyfileAdapter: per-file text credentials under a keys/ directory
- KMSAdapter: AWS KMS encrypted credentials
- K8sSecretsAdapter: Kubernetes mounted secrets
- VaultCredentialAdapter: HashiCorp Vault for secrets
- AWSSecretsAdapter: AWS Secrets Manager

Authorization (PDP):
- RBACPolicyAdapter: Role-based access control

Credential Brokers (outbound provider access):
- AWSCredentialBroker: AWS STS temporary credentials
- OpenAICredentialBroker: OpenAI project-scoped keys
- VaultCredentialBroker: HashiCorp Vault broker for all providers
"""

# Authentication & Sessions
from swarm_auth.adapters.jwt_auth import JWTAuthAdapter
from swarm_auth.adapters.api_key_auth import APIKeyAuthAdapter
from swarm_auth.adapters.header_identity import HeaderIdentityAdapter
from swarm_auth.adapters.redis_session import RedisSessionAdapter
from swarm_auth.adapters.memory_session import MemorySessionAdapter
from swarm_auth.adapters.dynamodb_session import DynamoDBSessionAdapter

# Token Blacklist
from swarm_auth.adapters.redis_blacklist import RedisBlacklistAdapter
from swarm_auth.adapters.memory_blacklist import MemoryBlacklistAdapter

# Credential Storage
from swarm_auth.adapters.env_credential import EnvCredentialAdapter
from swarm_auth.adapters.dotenv_credential import DotEnvAdapter
from swarm_auth.adapters.keyfile_credential import KeyfileAdapter
from swarm_auth.adapters.kms_credential import KMSAdapter
from swarm_auth.adapters.k8s_credential import K8sSecretsAdapter
from swarm_auth.adapters.vault_credential import VaultCredentialAdapter
from swarm_auth.adapters.aws_credential import AWSSecretsAdapter

# Authorization
from swarm_auth.adapters.rbac_policy import RBACPolicyAdapter

# Credential Brokers
from swarm_auth.adapters.aws_credential_broker import AWSCredentialBroker
from swarm_auth.adapters.openai_credential_broker import OpenAICredentialBroker
from swarm_auth.adapters.vault_broker import VaultCredentialBroker

__all__ = [
    # Authentication & Sessions
    "JWTAuthAdapter",
    "APIKeyAuthAdapter",
    "HeaderIdentityAdapter",
    "RedisSessionAdapter",
    "MemorySessionAdapter",
    "DynamoDBSessionAdapter",
    # Token Blacklist
    "RedisBlacklistAdapter",
    "MemoryBlacklistAdapter",
    # Credential Storage
    "EnvCredentialAdapter",
    "DotEnvAdapter",
    "KeyfileAdapter",
    "KMSAdapter",
    "K8sSecretsAdapter",
    "VaultCredentialAdapter",
    "AWSSecretsAdapter",
    # Authorization
    "RBACPolicyAdapter",
    # Credential Brokers
    "AWSCredentialBroker",
    "OpenAICredentialBroker",
    "VaultCredentialBroker",
]
