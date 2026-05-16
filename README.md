# Swarm-Auth

**Agent identity, credential triage, and session management for the Swarm-It platform.**

Built with hexagonal (ports & adapters) architecture. Implements SOTA agent authentication patterns from Google ADK and Strata 8-strategies.

## P18 v4.0 - AccessScript Credential Triage

```python
from swarm_auth import get_credential, AccessScript

# Simple - auto-discovers available sources
api_key = get_credential('OPENAI_API_KEY')

# Configured - explicit priority and forbidden sources
access = AccessScript.from_config({
    "priority": ["dotenv", "aws_secrets"],
    "forbidden": ["kms"],  # Don't attempt in this env
    "env_overrides": {
        "prod": {
            "priority": ["aws_secrets"],
            "forbidden": ["env_var", "dotenv"],
        }
    }
})
```

### Credential Sources (Priority Order)

| Source | Adapter | Use Case |
|--------|---------|----------|
| `env_var` | `EnvCredentialAdapter` | Environment variables |
| `dotenv` | `DotEnvAdapter` | Auto-load `.env` files |
| `k8s_secrets` | `K8sSecretsAdapter` | Kubernetes mounted secrets |
| `aws_secrets` | `AWSSecretsAdapter` | AWS Secrets Manager |
| `kms` | `KMSAdapter` | AWS KMS encrypted blobs |
| `vault` | `VaultCredentialAdapter` | HashiCorp Vault |

### Forbidden Sources

In locked-down environments, attempting certain sources triggers security violations:

```python
access = AccessScript.from_config({
    "priority": ["vault"],
    "forbidden": ["env_var", "dotenv", "kms"],  # Would trigger alerts
    "on_forbidden": "log",  # silent | log | error
})
```

## Features

- **AccessScript Triage**: Priority-ordered credential discovery with forbidden source enforcement
- **Agent-Ready**: JIT provisioning, short-lived tokens, audit trails
- **Credential Brokering**: Tool-level credential vending via CredentialBrokerPort
- **AWS Integration**: STS AssumeRole, Secrets Manager, KMS
- **Authentication**: JWT tokens, API keys
- **Session Management**: Redis, DynamoDB, in-memory
- **Hexagonal Architecture**: Ports & adapters for testability

## Installation

```bash
# Basic installation
pip install swarm-auth

# With Redis support
pip install swarm-auth[redis]

# With AWS support (Secrets Manager, KMS, STS)
pip install swarm-auth[aws]

# With all adapters
pip install swarm-auth[all]
```

## Quick Start

### Credential Access (P18 v4.0)

```python
from swarm_auth import get_credential, has_credential, AccessScript

# Auto-discovers: env_var → dotenv → k8s → aws_secrets → kms → vault
api_key = get_credential('OPENAI_API_KEY')

# Check existence
if has_credential('ANTHROPIC_API_KEY'):
    claude_key = get_credential('ANTHROPIC_API_KEY')

# AWS credentials helper
from swarm_auth import get_aws_credentials
aws = get_aws_credentials()  # Returns boto3-compatible dict
```

### Configured Triage

```python
from swarm_auth import AccessScript, SourceType

# Production config - only AWS Secrets Manager
access = AccessScript.from_config({
    "priority": ["aws_secrets"],
    "forbidden": ["env_var", "dotenv"],
    "cache_ttl": 300,
    "audit_enabled": True,
})

key = access.get('DATABASE_PASSWORD')

# Check available sources
sources = access.list_available_sources()
print(f"Available: {[s.value for s in sources]}")

# Audit log
for entry in access.get_audit_log():
    print(f"{entry.timestamp}: {entry.source.value} -> {entry.success}")
```

### JWT Authentication

```python
from swarm_auth import AuthClient, User, UserRole
from swarm_auth.adapters import JWTAuthAdapter, MemorySessionAdapter
import os

# Initialize
auth = JWTAuthAdapter(secret=os.environ["JWT_SECRET"])
sessions = MemorySessionAdapter()
client = AuthClient(auth=auth, sessions=sessions)

# Create user
user = User(
    user_id="user123",
    username="alice",
    role=UserRole.DEVELOPER,
)

# Login
result = client.login(user, ttl=3600)
token = result["token"]

# Verify
verified = client.verify(token)
print(f"User: {verified.username}, Role: {verified.role}")
```

### Credential Brokering (Tool-Level)

```python
from swarm_auth.adapters import AWSCredentialBroker
from swarm_auth.ports.credential_broker_port import ToolRequest, ProviderType

broker = AWSCredentialBroker(region="us-east-1")

# Request scoped credentials for specific tool
cred = broker.vend_credential(
    principal=agent,
    tool_request=ToolRequest(
        tool_name="s3_upload",
        provider=ProviderType.AWS,
        action="s3:PutObject",
        resource="arn:aws:s3:::my-bucket/*",
        max_duration=900,  # 15 minutes
    )
)

# Use temporary credentials
import boto3
s3 = boto3.client(
    's3',
    aws_access_key_id=cred.credentials['access_key_id'],
    aws_secret_access_key=cred.credentials['secret_access_key'],
    aws_session_token=cred.credentials['session_token'],
)
```

## Architecture

```
swarm-auth/
├── access_script.py    # P18 v4.0 credential triage orchestration
├── ports/              # Interfaces (what we need)
│   ├── auth_port.py
│   ├── session_port.py
│   ├── credential_port.py
│   └── credential_broker_port.py
├── domain/             # Business entities
│   ├── user.py
│   ├── session.py
│   └── credential.py
├── adapters/           # Implementations (how we do it)
│   ├── dotenv_credential.py    # NEW: .env auto-load
│   ├── kms_credential.py       # NEW: AWS KMS
│   ├── k8s_credential.py       # NEW: Kubernetes secrets
│   ├── env_credential.py
│   ├── aws_credential.py
│   ├── vault_credential.py
│   ├── jwt_auth.py
│   ├── api_key_auth.py
│   └── aws_credential_broker.py
└── sdk/
    └── client.py
```

### Hexagonal Pattern

```
                    ┌─────────────────────┐
                    │    AccessScript     │  Orchestration
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
         CredentialPort   CredentialPort   CredentialPort   ← Port
              │                │                │
              ▼                ▼                ▼
         DotEnvAdapter    KMSAdapter    K8sSecretsAdapter   ← Adapters
```

## Adapters

### Credential Storage (CredentialPort)

| Adapter | Source | Status |
|---------|--------|--------|
| `EnvCredentialAdapter` | Environment variables | ✅ |
| `DotEnvAdapter` | `.env` files (auto-discovery) | ✅ |
| `KMSAdapter` | AWS KMS encrypted blobs | ✅ |
| `K8sSecretsAdapter` | Kubernetes mounted secrets | ✅ |
| `AWSSecretsAdapter` | AWS Secrets Manager | ✅ |
| `VaultCredentialAdapter` | HashiCorp Vault | ✅ |

### Credential Brokers (CredentialBrokerPort)

| Broker | Provider | Description |
|--------|----------|-------------|
| `AWSCredentialBroker` | AWS | STS AssumeRole, session policies |
| `GCPCredentialBroker` | GCP | Workload Identity Federation |
| `OpenAICredentialBroker` | OpenAI | Project-scoped API keys |

### Authentication (AuthenticationPort)

| Adapter | Method |
|---------|--------|
| `JWTAuthAdapter` | JWT tokens (HS256, RS256) |
| `APIKeyAuthAdapter` | API keys (SHA-256 hashed) |

### Sessions (SessionPort)

| Adapter | Backend |
|---------|---------|
| `RedisSessionAdapter` | Redis |
| `DynamoDBSessionAdapter` | AWS DynamoDB |
| `MemorySessionAdapter` | In-memory (testing) |

## User Roles & Permissions

| Role | Permissions |
|------|-------------|
| `ADMIN` | All permissions |
| `DEVELOPER` | certify, validate, read, audit |
| `AUDITOR` | read, audit |
| `SERVICE` | certify, validate, read |
| `GUEST` | read |

## Environment Configuration

```bash
# Local development
export ENVIRONMENT=dev

# Production - force AWS Secrets Manager only
export ENVIRONMENT=prod
```

```python
access = AccessScript.from_config({
    "env_overrides": {
        "dev": {
            "priority": ["env_var", "dotenv"],
        },
        "prod": {
            "priority": ["aws_secrets"],
            "forbidden": ["env_var", "dotenv"],
        }
    }
})
```

## Development Setup

After cloning, run once to install git hooks:

```bash
./install-hooks.sh
```

This sets `core.hooksPath=hooks` so the pre-push hook runs unit tests before every push.

## Testing

```bash
# Run tests
pytest

# With coverage
pytest --cov=swarm_auth --cov-report=html

# Type checking
mypy swarm_auth
```

## Related Projects

- [swarm-it-adk](https://github.com/NextShiftConsulting/swarm-it-adk) - Agent Development Kit (runtime enforcement)
- [swarm-it-api](https://github.com/NextShiftConsulting/swarm-it-api) - RSCT certification API
- [swarm-it-discovery](https://github.com/NextShiftConsulting/swarm-it-discovery) - Research discovery platform

## License

MIT License. See [LICENSE](LICENSE) for details.
