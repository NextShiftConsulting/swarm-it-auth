# Swarm-Auth Integration Guide

This guide shows how to integrate swarm-auth with your Swarm-It services.

## Table of Contents

1. [Quick Start](#quick-start)
2. [swarm-it-api Integration](#swarm-it-api-integration)
3. [Adapter Selection](#adapter-selection)
4. [Production Deployment](#production-deployment)
5. [Testing](#testing)

## Quick Start

### Install swarm-auth

```bash
# Basic installation
pip install swarm-auth

# With Redis support
pip install swarm-auth[redis]

# With all adapters (Redis, Vault, AWS)
pip install swarm-auth[all]
```

### Basic Usage

```python
from swarm_auth import AuthClient, User, UserRole
from swarm_auth.adapters import JWTAuthAdapter, MemorySessionAdapter

# Initialize
auth = JWTAuthAdapter(secret="your-secret-key")
sessions = MemorySessionAdapter()
client = AuthClient(auth=auth, sessions=sessions)

# Create user
user = User(user_id="usr_1", username="alice", role=UserRole.DEVELOPER)

# Login
result = client.login(user, ttl=3600)
token = result["token"]

# Verify
verified_user = client.verify(token)
if verified_user.has_permission("certify"):
    # Proceed...
    pass
```

## swarm-it-api Integration

### Step 1: Install swarm-auth

Add to `requirements.txt`:
```
swarm-auth[redis]
```

### Step 2: Enable Authentication

Set environment variables:
```bash
export ENABLE_AUTH=1
export JWT_SECRET=your-secret-key-here
```

### Step 3: Protected Endpoints

The middleware automatically protects:
- `/api/v1/certify` - Requires authentication
- `/api/v1/validate` - Requires authentication

Unprotected endpoints:
- `/health` - Health check
- `/ready` - Readiness check
- `/metrics` - Prometheus metrics

### Step 4: Test Authentication

```python
import httpx
from swarm_auth import User, UserRole
from swarm_auth.adapters import JWTAuthAdapter

# Create token
auth = JWTAuthAdapter(secret="your-secret-key-here")
user = User(user_id="usr_1", username="alice", role=UserRole.DEVELOPER)
token = auth.create_token(user)

# Call API
response = httpx.post(
    "http://localhost:8080/api/v1/certify",
    json={"prompt": "What is 2+2?"},
    headers={"Authorization": f"Bearer {token}"}
)

print(response.json())
```

## Adapter Selection

### Development

**Auth**: `JWTAuthAdapter` or `APIKeyAuthAdapter`
**Sessions**: `MemorySessionAdapter`
**Credentials**: `EnvCredentialAdapter`

```python
from swarm_auth.adapters import (
    JWTAuthAdapter,
    MemorySessionAdapter,
    EnvCredentialAdapter,
)

auth = JWTAuthAdapter(secret=os.environ["JWT_SECRET"])
sessions = MemorySessionAdapter()
credentials = EnvCredentialAdapter()
```

### Production (AWS)

**Auth**: `JWTAuthAdapter` or `APIKeyAuthAdapter`
**Sessions**: `DynamoDBSessionAdapter`
**Credentials**: `AWSSecretsAdapter`

```python
from swarm_auth.adapters import (
    JWTAuthAdapter,
    DynamoDBSessionAdapter,
    AWSSecretsAdapter,
)

auth = JWTAuthAdapter(secret=os.environ["JWT_SECRET"])
sessions = DynamoDBSessionAdapter(
    table_name="swarm-it-sessions",
    region_name="us-east-1",
)
credentials = AWSSecretsAdapter(region_name="us-east-1")
```

### Production (Self-Hosted)

**Auth**: `JWTAuthAdapter`
**Sessions**: `RedisSessionAdapter`
**Credentials**: `VaultCredentialAdapter`

```python
from swarm_auth.adapters import (
    JWTAuthAdapter,
    RedisSessionAdapter,
    VaultCredentialAdapter,
)

auth = JWTAuthAdapter(secret=os.environ["JWT_SECRET"])
sessions = RedisSessionAdapter(redis_client=redis.Redis(host="redis"))
credentials = VaultCredentialAdapter(
    url="https://vault.example.com",
    token=os.environ["VAULT_TOKEN"],
)
```

## Production Deployment

### AWS Lambda + DynamoDB

```python
# handler.py
import os
from swarm_auth import AuthClient
from swarm_auth.adapters import JWTAuthAdapter, DynamoDBSessionAdapter

# Initialize once (outside handler)
auth_client = AuthClient(
    auth=JWTAuthAdapter(secret=os.environ["JWT_SECRET"]),
    sessions=DynamoDBSessionAdapter(
        table_name=os.environ["SESSION_TABLE"],
        region_name=os.environ["AWS_REGION"],
    ),
)

def lambda_handler(event, context):
    # Extract token
    token = event["headers"].get("Authorization", "").replace("Bearer ", "")

    # Verify
    user = auth_client.verify(token)
    if not user:
        return {"statusCode": 401, "body": "Unauthorized"}

    # Process request...
    return {"statusCode": 200, "body": "Success"}
```

### Docker + Redis

```dockerfile
# Dockerfile
FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python", "main.py"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8080:8080"
    environment:
      - ENABLE_AUTH=1
      - JWT_SECRET=${JWT_SECRET}
      - REDIS_URL=redis://redis:6379
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

### Kubernetes

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: swarm-it-api
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: api
        image: swarmit/api:latest
        env:
        - name: ENABLE_AUTH
          value: "1"
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: swarm-secrets
              key: jwt-secret
        - name: REDIS_URL
          value: redis://redis-service:6379
---
apiVersion: v1
kind: Service
metadata:
  name: redis-service
spec:
  selector:
    app: redis
  ports:
  - port: 6379
```

## Testing

### Unit Tests

```bash
# Run unit tests
cd swarm-it-auth
pytest tests/unit/

# With coverage
pytest tests/unit/ --cov=swarm_auth --cov-report=html
```

### Integration Tests

```bash
# Requires Redis running
docker run -d -p 6379:6379 redis:7-alpine

# Run integration tests
pytest tests/integration/

# Skip tests requiring external services
pytest tests/integration/ -m "not vault and not aws"
```

### API Integration Test

```bash
# Terminal 1: Start API with auth
export ENABLE_AUTH=1
export JWT_SECRET=test-secret-key
python main.py

# Terminal 2: Run tests
pytest tests/integration/test_api_integration.py
```

## User Roles & Permissions

| Role | certify | validate | read | audit |
|------|---------|----------|------|-------|
| ADMIN | ✓ | ✓ | ✓ | ✓ |
| DEVELOPER | ✓ | ✓ | ✓ | ✓ |
| AUDITOR | ✗ | ✗ | ✓ | ✓ |
| SERVICE | ✓ | ✓ | ✓ | ✗ |
| GUEST | ✗ | ✗ | ✓ | ✗ |

## Troubleshooting

### Token Authentication Fails

**Check JWT secret matches:**
```python
# API
auth = JWTAuthAdapter(secret="my-secret")

# Client
auth = JWTAuthAdapter(secret="my-secret")  # Must match!
```

### Redis Connection Error

**Verify Redis is running:**
```bash
redis-cli ping
# Should return: PONG
```

### Permission Denied (403)

**Check user role:**
```python
user = auth.authenticate(token)
print(f"Role: {user.role}")
print(f"Can certify: {user.has_permission('certify')}")
```

## Next Steps

- [API Reference](./API_REFERENCE.md)
- [Security Best Practices](./SECURITY.md)
- [Examples](../examples/)
