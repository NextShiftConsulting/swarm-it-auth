# Swarm-Auth

**Session and credential management for the Swarm-It platform.**

Built with hexagonal (ports & adapters) architecture for maximum flexibility and testability.

## Features

- **Authentication**: JWT tokens, API keys
- **Session Management**: Redis, in-memory
- **Credential Storage**: Environment variables, Vault (coming soon), AWS Secrets Manager (coming soon)
- **Clean Architecture**: Ports & adapters pattern
- **Cross-Platform**: Used by swarm-it-api, swarm-it-adk, swarm-it-discovery

## Installation

```bash
# Basic installation
pip install swarm-auth

# With Redis support
pip install swarm-auth[redis]

# With all adapters
pip install swarm-auth[all]

# Development
pip install swarm-auth[dev]
```

## Quick Start

### JWT Authentication

```python
from swarm_auth import AuthClient, User, UserRole
from swarm_auth.adapters import JWTAuthAdapter, MemorySessionAdapter

# Initialize
auth = JWTAuthAdapter(secret="your-secret-key")
sessions = MemorySessionAdapter()
client = AuthClient(auth=auth, sessions=sessions)

# Create user
user = User(
    user_id="user123",
    username="alice",
    role=UserRole.DEVELOPER,
    email="alice@example.com"
)

# Login (creates token + session)
result = client.login(user, ttl=3600)
token = result["token"]
print(f"Token: {token}")

# Verify token
verified_user = client.verify(token)
print(f"User: {verified_user.username}, Role: {verified_user.role}")

# Logout
client.logout(token)
```

### API Key Authentication

```python
from swarm_auth.adapters import APIKeyAuthAdapter

auth = APIKeyAuthAdapter()

# Register user and get API key
user = User(user_id="svc1", username="service-bot", role=UserRole.SERVICE)
api_key = auth.register_user(user)
print(f"API Key: {api_key}")  # Save this!

# Later: authenticate with API key
authenticated_user = auth.authenticate(api_key)
print(f"Authenticated: {authenticated_user.username}")
```

### Session Management (Redis)

```python
from swarm_auth.adapters import RedisSessionAdapter

# Connect to Redis
sessions = RedisSessionAdapter(prefix="myapp:session:")

# Create session
session = sessions.create(user_id="user123", ttl=3600)
print(f"Session ID: {session.session_id}")

# Get session
retrieved = sessions.get(session.session_id)
print(f"Valid: {retrieved.is_valid()}")

# Extend session
sessions.extend(session.session_id, ttl=1800)

# List user's sessions
user_sessions = sessions.list_by_user("user123")
print(f"Active sessions: {len(user_sessions)}")
```

### Credential Storage

```python
from swarm_auth.adapters import EnvCredentialAdapter

creds = EnvCredentialAdapter()

# Store credential
creds.store("openai_api_key", "sk-...", metadata={
    "description": "OpenAI API key for embeddings",
    "rotation_policy": "90d"
})

# Retrieve credential
api_key = creds.retrieve("openai_api_key")

# List credentials
keys = creds.list_keys(prefix="openai")
print(f"Keys: {keys}")
```

## Architecture

```
swarm-auth/
├── ports/              # Interfaces (what we need)
│   ├── auth_port.py
│   ├── session_port.py
│   └── credential_port.py
├── domain/             # Business entities (pure logic)
│   ├── user.py
│   ├── session.py
│   └── credential.py
├── adapters/           # Implementations (how we do it)
│   ├── jwt_auth.py
│   ├── api_key_auth.py
│   ├── redis_session.py
│   └── env_credential.py
└── sdk/                # High-level client
    └── client.py
```

### Hexagonal Architecture Benefits

1. **Testable**: Mock any port with a test adapter
2. **Swappable**: Switch from JWT to OAuth without changing domain
3. **Technology-agnostic**: Domain knows nothing about Redis, JWT, etc.
4. **Clear boundaries**: Infrastructure vs. domain logic

## Integration with swarm-it-api

```python
# swarm-it-api/main.py
from fastapi import FastAPI, Depends, HTTPException
from swarm_auth import AuthClient
from swarm_auth.adapters import JWTAuthAdapter, RedisSessionAdapter

app = FastAPI()

# Initialize auth
auth_client = AuthClient(
    auth=JWTAuthAdapter(secret=os.environ["JWT_SECRET"]),
    sessions=RedisSessionAdapter(),
)

# Dependency injection
async def get_current_user(token: str = Depends(oauth2_scheme)):
    user = auth_client.verify(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

# Protected endpoint
@app.post("/api/v1/certify")
async def certify(
    request: CertifyRequest,
    user: User = Depends(get_current_user)
):
    # User is authenticated
    if not user.has_permission("certify"):
        raise HTTPException(status_code=403, detail="Permission denied")

    # Process certification...
```

## User Roles & Permissions

| Role | Permissions |
|------|-------------|
| `ADMIN` | All permissions |
| `DEVELOPER` | certify, validate, read, audit |
| `AUDITOR` | read, audit (compliance only) |
| `SERVICE` | certify, validate, read (M2M) |
| `GUEST` | read (limited) |

## Adapters

### Authentication

- **JWTAuthAdapter**: JWT token-based auth (HS256, RS256)
- **APIKeyAuthAdapter**: API key-based auth (SHA-256 hashed)
- **OAuth2Adapter**: OAuth2 flows (coming soon)

### Sessions

- **RedisSessionAdapter**: Redis-backed sessions (distributed)
- **MemorySessionAdapter**: In-memory sessions (testing only)
- **DynamoDBSessionAdapter**: DynamoDB sessions (coming soon)

### Credentials

- **EnvCredentialAdapter**: Environment variables (dev only)
- **VaultCredentialAdapter**: HashiCorp Vault (coming soon)
- **AWSSecretsAdapter**: AWS Secrets Manager (coming soon)

## Testing

```bash
# Run tests
pytest

# With coverage
pytest --cov=swarm_auth --cov-report=html

# Type checking
mypy swarm_auth
```

## Examples

See `examples/` for complete integration examples:

- `basic_auth.py` - JWT authentication
- `api_key_service.py` - Service account with API keys
- `session_management.py` - Redis session handling
- `fastapi_integration.py` - FastAPI middleware

## License

MIT License. See [LICENSE](LICENSE) for details.

## Related Projects

- [swarm-it-api](https://github.com/NextShiftConsulting/swarm-it-api) - RSCT certification API
- [swarm-it-adk](https://github.com/NextShiftConsulting/swarm-it-adk) - Agent Development Kit
- [swarm-it-discovery](https://github.com/NextShiftConsulting/swarm-it-discovery) - Research discovery platform
