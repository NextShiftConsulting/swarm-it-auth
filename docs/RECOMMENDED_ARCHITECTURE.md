# Recommended Architecture: Multi-Cloud Agent Auth

**Stop reading 8 adapters. Use this.**

---

## The Stack (What You Actually Need)

### 1. Edge: OAuth2-Proxy (Inbound Auth)

**Purpose**: Validate user identity at the boundary.

**What it does**:
- OIDC/JWT validation
- Injects `X-Auth-Request-User`, `X-Auth-Request-Email` headers
- Protects web UI + API

**Deploy once, forget about it**:
```yaml
# docker-compose.yml
oauth2-proxy:
  image: quay.io/oauth2-proxy/oauth2-proxy:latest
  command:
    - --provider=oidc
    - --oidc-issuer-url=https://your-idp.com
    - --upstream=http://api:8080
    - --email-domain=*
```

---

### 2. Service: 3 Ports (Your Auth Kernel)

**Keep exactly these**:

```python
# ports/
├── identity_verifier.py    # request → Principal
├── policy_port.py           # (Principal, Action, Resource) → allow/deny
└── credential_broker_port.py # (Principal, ToolRequest) → short-lived cred
```

**That's it. No more.**

---

### 3. Adapters: Start Simple, Graduate Later

#### Inbound Auth
- **Start**: `HeaderIdentityAdapter` (trust gateway headers)
- **Graduate to**: `JWTAuthAdapter` (verify JWT if no gateway)

```python
# adapters/header_identity.py
class HeaderIdentityAdapter(IdentityVerifier):
    """Trust headers from oauth2-proxy."""
    def verify(self, request):
        user_id = request.headers.get("X-Auth-Request-User")
        email = request.headers.get("X-Auth-Request-Email")
        return Principal(user_id=user_id, email=email)
```

#### Policy (PDP)
- **Start**: `RBACPolicyAdapter` (in-process, file-based)
- **Graduate to**: Envoy ext_authz → OPA (when you have multiple services)

```python
# Start simple
pdp = RBACPolicyAdapter(policy_file="policies.yaml")

# Graduate to OPA later (same interface!)
# pdp = OPAPolicyAdapter(opa_url="http://opa:8181")
```

#### Credential Broker
- **AWS**: Vault AWS Secrets Engine (not boto3 STS directly)
- **GCP**: Workload Identity Federation
- **OpenAI/HF**: Pre-created project keys from secrets manager

```python
# The ONE broker you need
class VaultCredentialBroker(CredentialBrokerPort):
    """
    Vault handles ALL providers:
    - AWS: dynamic STS credentials
    - GCP: service account tokens
    - OpenAI/HF: stored project keys with rotation
    """
    pass
```

**Why Vault**:
- One system for all providers
- Dynamic credentials for AWS/GCP
- Key rotation for OpenAI/HF
- Audit built-in
- Production-grade

---

## The Flow (What Actually Happens)

```
┌────────────────────────────────────────────────────┐
│  1. USER → OAuth2-Proxy → JWT validation          │
│     Headers: X-Auth-Request-User, X-Auth-Request-Email │
└────────────────────────────────────────────────────┘
                    ↓
┌────────────────────────────────────────────────────┐
│  2. API → HeaderIdentityAdapter → Principal        │
│     Convert headers → internal Principal type       │
└────────────────────────────────────────────────────┘
                    ↓
┌────────────────────────────────────────────────────┐
│  3. PDP → RBACPolicyAdapter → allow/deny           │
│     Check: can Principal perform Action on Resource │
│     Returns: obligations (max_cost, max_tokens)    │
└────────────────────────────────────────────────────┘
                    ↓
┌────────────────────────────────────────────────────┐
│  4. CredentialBroker → Vault → temp cred           │
│     Request: "agent_123 wants aws.s3.put"          │
│     Returns: 15min STS credential                  │
└────────────────────────────────────────────────────┘
                    ↓
┌────────────────────────────────────────────────────┐
│  5. Tool executes with temp credential             │
│     s3.put_object(... credentials from Vault ...)  │
└────────────────────────────────────────────────────┘
                    ↓
┌────────────────────────────────────────────────────┐
│  6. Audit log                                      │
│     {principal, action, resource, decision, cost}  │
└────────────────────────────────────────────────────┘
```

---

## Repository Layout (The Right Structure)

```
swarm-it-auth/
├── ports/                    # 3 files only
│   ├── identity_verifier.py
│   ├── policy_port.py
│   └── credential_broker_port.py
│
├── domain/                   # Pure business logic
│   ├── principal.py
│   └── permissions.py
│
├── adapters/
│   ├── header_identity.py    # START HERE (trust gateway)
│   ├── jwt_auth.py           # For direct API access (no gateway)
│   ├── rbac_policy.py        # START HERE (file-based RBAC)
│   ├── opa_policy.py         # Graduate to this (multi-service)
│   └── vault_broker.py       # THE broker (all providers)
│
└── sdk/
    └── client.py             # High-level API
```

**Delete everything else.**

---

## Deployment Patterns

### Pattern A: Single Service (Start Here)

```yaml
# docker-compose.yml
version: '3.8'
services:
  oauth2-proxy:
    image: quay.io/oauth2-proxy/oauth2-proxy
    ports:
      - "4180:4180"
    environment:
      - OAUTH2_PROXY_UPSTREAMS=http://api:8080
      - OAUTH2_PROXY_PROVIDER=oidc
      - OAUTH2_PROXY_OIDC_ISSUER_URL=${OIDC_ISSUER}

  api:
    build: .
    environment:
      - VAULT_ADDR=http://vault:8200
      - VAULT_TOKEN=${VAULT_TOKEN}

  vault:
    image: hashicorp/vault:latest
    cap_add:
      - IPC_LOCK
    environment:
      - VAULT_DEV_ROOT_TOKEN_ID=root
```

**Auth flow**:
1. User → OAuth2-Proxy (validates OIDC)
2. OAuth2-Proxy → API (with headers)
3. API uses `HeaderIdentityAdapter` (trust headers)
4. API uses `RBACPolicyAdapter` (in-process)
5. API uses `VaultCredentialBroker` (dynamic creds)

---

### Pattern B: Multi-Service / Service Mesh (Graduate To)

```yaml
# When you have multiple services
services:
  envoy:
    image: envoyproxy/envoy:latest
    volumes:
      - ./envoy.yaml:/etc/envoy/envoy.yaml
    # ext_authz → OPA

  opa:
    image: openpolicyagent/opa:latest
    command: ["run", "--server", "/policies"]
    volumes:
      - ./policies:/policies

  api-1:
    build: ./service-1
  api-2:
    build: ./service-2
  api-3:
    build: ./service-3

  vault:
    image: hashicorp/vault:latest
```

**Auth flow**:
1. User → Envoy (validates JWT/mTLS)
2. Envoy → ext_authz → OPA (policy check)
3. Envoy → API (with Principal headers)
4. API uses `HeaderIdentityAdapter` (trust Envoy)
5. API uses `VaultCredentialBroker` (shared across services)

---

## Vault Configuration (The Core)

### AWS Dynamic Credentials
```hcl
# vault policy
path "aws/creds/s3-upload-role" {
  capabilities = ["read"]
}
```

```bash
# Enable AWS secrets engine
vault secrets enable aws
vault write aws/config/root \
    access_key=$AWS_ACCESS_KEY \
    secret_key=$AWS_SECRET_KEY

# Create role that mints STS credentials
vault write aws/roles/s3-upload-role \
    credential_type=assumed_role \
    role_arns=arn:aws:iam::123456789012:role/S3UploadRole \
    default_sts_ttl=900s \
    max_sts_ttl=3600s
```

### GCP Service Account Tokens
```bash
vault secrets enable gcp
vault write gcp/config \
    credentials=@gcp-credentials.json

vault write gcp/roleset/storage-reader \
    project="my-project" \
    secret_type="access_token" \
    token_scopes="https://www.googleapis.com/auth/devstorage.read_only" \
    bindings=-<<EOF
        resource "//cloudresourcemanager.googleapis.com/projects/my-project" {
          roles = ["roles/storage.objectViewer"]
        }
EOF
```

### OpenAI/HF Keys (Static with Rotation)
```bash
vault kv put secret/openai/project-123 \
    api_key="sk-..." \
    project_id="proj-123"

vault kv put secret/huggingface/prod \
    token="hf_..."
```

---

## Code Example (The Right Way)

```python
# main.py
from fastapi import FastAPI, Request
from swarm_auth.adapters.header_identity import HeaderIdentityAdapter
from swarm_auth.adapters.rbac_policy import RBACPolicyAdapter
from swarm_auth.adapters.vault_broker import VaultCredentialBroker

app = FastAPI()

# Initialize auth kernel
identity = HeaderIdentityAdapter()
pdp = RBACPolicyAdapter(policy_file="policies.yaml")
broker = VaultCredentialBroker(vault_url="http://vault:8200")

@app.post("/api/v1/upload-to-s3")
async def upload_to_s3(request: Request, file: bytes):
    # 1. Get Principal from headers (oauth2-proxy injected)
    principal = identity.verify(request)

    # 2. Check policy
    action = Action(verb="put", provider="aws", resource_type="s3")
    resource = Resource(provider="aws", type="bucket", id="my-bucket/uploads/*")

    decision = pdp.evaluate(principal, action, resource)
    if decision.decision == Decision.DENY:
        raise HTTPException(403, decision.reason)

    # 3. Get temp AWS credentials from Vault
    tool_request = ToolRequest(
        tool_name="s3_upload",
        provider="aws",
        action="s3:PutObject",
        resource="my-bucket/uploads/*",
        max_duration=900,
    )

    credential = broker.vend_credential(principal, tool_request)

    # 4. Use credential (expires in 15min)
    import boto3
    s3 = boto3.client(
        "s3",
        aws_access_key_id=credential.credentials["access_key_id"],
        aws_secret_access_key=credential.credentials["secret_access_key"],
        aws_session_token=credential.credentials["session_token"],
    )

    s3.put_object(Bucket="my-bucket", Key=f"uploads/{principal.user_id}/file", Body=file)

    return {"status": "uploaded"}
```

---

## Migration Path (Start → Mature)

### Phase 1: Single Service (Week 1)
- ✅ OAuth2-Proxy at edge
- ✅ HeaderIdentityAdapter
- ✅ RBACPolicyAdapter (file-based)
- ✅ VaultCredentialBroker
- ✅ Vault dev mode

### Phase 2: Production (Week 2-4)
- ✅ Vault production setup
- ✅ AWS dynamic credentials via Vault
- ✅ GCP WIF via Vault
- ✅ Audit logging

### Phase 3: Multi-Service (Month 2-3)
- ✅ Envoy + ext_authz
- ✅ OPA for centralized policy
- ✅ mTLS (SPIRE)
- ✅ Service mesh

---

## What NOT to Build

❌ **Don't**: Build 8 different credential brokers (AWS, GCP, OpenAI, HF)
✅ **Do**: Use Vault for all of them

❌ **Don't**: Build custom JWT validation
✅ **Do**: Use OAuth2-Proxy or Envoy

❌ **Don't**: Build ABAC policy engine from scratch
✅ **Do**: Use OPA (graduate to OpenFGA only if you need Zanzibar-style)

❌ **Don't**: Store long-lived keys in your service
✅ **Do**: Vault dynamic credentials (15min-1hr)

❌ **Don't**: Build your own session management
✅ **Do**: Let OAuth2-Proxy handle it

---

## The Focused File Structure

```
swarm-it-auth/
├── ports/
│   ├── identity_verifier.py       # 1 interface
│   ├── policy_port.py              # 1 interface
│   └── credential_broker_port.py   # 1 interface
│
├── domain/
│   ├── principal.py                # Your identity type
│   └── permissions.py              # Action, Resource types
│
├── adapters/
│   ├── header_identity.py          # THE inbound adapter
│   ├── rbac_policy.py              # THE policy adapter (start)
│   ├── opa_policy.py               # THE policy adapter (graduate)
│   └── vault_broker.py             # THE credential broker
│
└── examples/
    ├── single_service.py           # Start here
    └── service_mesh.py             # Graduate to this
```

**Total: 10 files. Not 50.**

---

## Summary: The Chef's Menu

| Concern | Start With | Graduate To | Never Use |
|---------|-----------|-------------|-----------|
| **Edge auth** | OAuth2-Proxy | Envoy + mTLS (SPIRE) | Custom JWT validation |
| **Identity** | HeaderIdentityAdapter | Same (headers from Envoy) | Parsing JWTs in app code |
| **Policy (PDP)** | RBACPolicyAdapter (file) | OPAPolicyAdapter | Custom policy engine |
| **Credentials** | VaultCredentialBroker | Same (Vault for all) | Boto3 STS directly |
| **Sessions** | OAuth2-Proxy | Same | Redis/DynamoDB sessions |

**One sentence**: OAuth2-Proxy handles login, your service trusts headers, checks policy via RBAC/OPA, and mints temp credentials via Vault.

---

## Questions This Answers

**Q**: "Do I need JWT validation in my service?"
**A**: No. OAuth2-Proxy or Envoy does it. You trust headers.

**Q**: "Should I use boto3 to call STS AssumeRole?"
**A**: No. Vault's AWS secrets engine does it better (rotation, audit, revocation).

**Q**: "Do I need 8 credential brokers?"
**A**: No. Vault handles AWS/GCP/OpenAI/HF. One broker.

**Q**: "When do I need Envoy + OPA?"
**A**: When you have multiple services. Start simple first.

**Q**: "What about OpenFGA?"
**A**: Only if you need fine-grained, multi-tenant, relationship-based authz (Zanzibar). 95% of systems don't need this.

---

**This is the menu. Build this.**
