# Swarm-It-Auth on AWS

**Package**: `swarm-auth[aws]` (v0.2.0)
**Repo**: `NextShiftConsulting/swarm-it-auth`
**Status**: Production
**Last Updated**: 2026-05-29

---

## Executive Summary

`swarm-auth` provides three AWS integration points through its hexagonal adapter layer:

| Adapter | AWS Service | Purpose |
|---------|------------|---------|
| **AWSSecretsAdapter** | Secrets Manager | Store/retrieve/rotate credentials |
| **KMSAdapter** | KMS | Envelope encryption for credential blobs |
| **AWSCredentialBroker** | STS | Vend short-lived scoped credentials via AssumeRole |

All three are wired through **AccessScript** (P18 v4.0), the priority-ordered credential triage system. No adapter touches `boto3` directly -- all AWS calls route through `swarm_auth` internals (per P18 normative rule).

---

## Install

```bash
pip install swarm-auth[aws]    # pulls boto3>=1.34.0
```

---

## 1. AccessScript -- Credential Triage

AccessScript tries sources in priority order until it finds the requested key.

```python
from swarm_auth import get_credential, get_aws_credentials, AccessScript

# Simple (auto-discovers available sources)
api_key = get_credential("OPENAI_API_KEY")

# Explicit priority for AWS-only environments
access = AccessScript.from_config({
    "priority": ["aws_secrets"],
    "forbidden": ["env_var", "dotenv"],   # lock out local-dev sources in prod
    "cache_ttl": 300,
    "audit_enabled": True,
})
db_pass = access.get("DATABASE_PASSWORD")
```

### Default Priority Order

```
ENV_VAR -> DOTENV -> KEYFILE -> K8S_SECRETS -> AWS_SECRETS -> KMS -> VAULT
```

### Environment Overrides

```python
access = AccessScript.from_config({
    "priority": ["dotenv", "aws_secrets"],
    "env_overrides": {
        "prod": {
            "priority": ["aws_secrets"],
            "forbidden": ["env_var", "dotenv"],
        },
    },
})
```

---

## 2. AWS Secrets Manager (AWSSecretsAdapter)

### Store and Retrieve

```python
from swarm_auth.adapters import AWSSecretsAdapter

adapter = AWSSecretsAdapter(
    region_name="us-east-1",
    prefix="swarm-it/",          # keys stored as swarm-it/KEY
)

# Store
adapter.store("OPENAI_API_KEY", "<YOUR_API_KEY>", metadata={
    "description": "OpenAI production key",
    "tags": {"env": "prod"},
})

# Retrieve
value = adapter.retrieve("OPENAI_API_KEY")

# Rotate
adapter.rotate("OPENAI_API_KEY", "<NEW_API_KEY>")

# List
keys = adapter.list_keys(prefix="OPENAI")

# Check availability (class method)
AWSSecretsAdapter.is_available()   # True if boto3 + creds present
```

### IAM Policy (Least Privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "secretsmanager:UpdateSecret",
        "secretsmanager:ListSecrets",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:swarm-it/*"
    }
  ]
}
```

---

## 3. AWS KMS (KMSAdapter)

For envelope encryption -- credential blobs encrypted at rest with a KMS key.

```python
from swarm_auth.adapters import KMSAdapter

adapter = KMSAdapter(
    key_id="arn:aws:kms:us-east-1:123456789012:key/abc-123",
    region_name="us-east-1",
    encrypted_credentials_env="KMS_ENCRYPTED_CREDENTIALS",
)

value = adapter.retrieve("API_KEY")
adapter.store("API_KEY", "<YOUR_API_KEY>", metadata={...})
```

### IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/abc-123"
    }
  ]
}
```

---

## 4. AWS STS (AWSCredentialBroker)

Token vending machine -- mints short-lived, scoped credentials for agents making outbound AWS calls.

```python
from swarm_auth.adapters import AWSCredentialBroker
from swarm_auth.ports.credential_broker_port import ToolRequest, ProviderType

broker = AWSCredentialBroker(
    region="us-east-1",
    role_arn_template="arn:aws:iam::123456789012:role/{tool_name}",
)

cred = broker.vend_credential(
    principal=agent,
    tool_request=ToolRequest(
        tool_name="s3_upload",
        provider=ProviderType.AWS,
        action="s3:PutObject",
        resource="arn:aws:s3:::my-bucket/prefix/*",
        max_duration=900,     # 15 minutes
        scope_restrictions={"region": "us-east-1"},
    ),
)

# Returns ProviderCredential with:
#   access_key_id, secret_access_key, session_token, expires_at
```

### Use the Vended Credentials

```python
import boto3

s3 = boto3.client("s3", **{
    "aws_access_key_id": cred.credentials["access_key_id"],
    "aws_secret_access_key": cred.credentials["secret_access_key"],
    "aws_session_token": cred.credentials["session_token"],
    "region_name": "us-east-1",
})
```

---

## 5. `get_aws_credentials()` -- The Simple Path

For scripts and launchers that just need a boto3-compatible dict:

```python
from swarm_auth import get_aws_credentials
import boto3

aws = get_aws_credentials()
# {'aws_access_key_id': '...', 'aws_secret_access_key': '...', 'region_name': 'us-east-1'}

s3 = boto3.client("s3", **aws)
sagemaker = boto3.client("sagemaker", **aws)
```

This is the **mandatory** way to get AWS credentials in all swarm-it code. Never use bare `boto3.client()`.

---

## 6. Environment Patterns

### Local Development

```bash
# User sources credentials in their shell (see your team's onboarding docs)
# Code uses AccessScript (env_var source wins first)
python my_script.py
```

```python
# In code -- no difference from prod
from swarm_auth import get_credential
key = get_credential("OPENAI_API_KEY")
```

### ECS / Lambda (IAM Role)

No credential files. IAM role provides AWS access automatically. Application secrets come from Secrets Manager:

```python
access = AccessScript.from_config({
    "priority": ["aws_secrets"],
    "forbidden": ["env_var", "dotenv"],
})
api_key = access.get("OPENAI_API_KEY")

# AWS API calls use IAM role (boto3 default chain)
s3 = boto3.client("s3")   # IAM role -- no explicit creds needed
```

### SageMaker Jobs

```python
from swarm_auth import get_aws_credentials

aws = get_aws_credentials()
s3 = boto3.client("s3", **aws)
```

SageMaker execution role provides AWS access. Application secrets stored in Secrets Manager or passed via environment variables in the job definition.

---

## 7. CLI: Migrate Env Vars to Secrets Manager

```bash
python -m swarm_auth.cli.env_to_secrets \
    --prefix SWARM_ \
    --region us-east-1 \
    --secrets-prefix swarm-it/
```

Reads local env vars matching the prefix and stores them in Secrets Manager.

---

## 8. DynamoDB Sessions (Optional)

For services that need server-side session state on AWS:

```python
from swarm_auth import create_session_store

sessions = create_session_store(
    backend="dynamodb",
    table_name="swarm-sessions",
    region_name="us-east-1",
)

session = sessions.create(user_id="u123", ttl=3600, metadata={"ip": "10.0.0.1"})
retrieved = sessions.get(session.session_id)
```

### DynamoDB Table Schema

```
Table: swarm-sessions
  PK: session_id (S)
  TTL: expires_at (N)
```

---

## Quick Reference

| Task | Code |
|------|------|
| Get any secret | `get_credential("KEY")` |
| Get AWS creds for boto3 | `get_aws_credentials()` |
| Prod-only Secrets Manager | `AccessScript.from_config({"priority": ["aws_secrets"]})` |
| Vend scoped STS token | `AWSCredentialBroker.vend_credential(...)` |
| Migrate env to Secrets Manager | `python -m swarm_auth.cli.env_to_secrets` |
| Check adapter availability | `AWSSecretsAdapter.is_available()` |

---

## Rules (P18 Normative)

1. **No bare `boto3.client()`** -- always use `get_aws_credentials()` or IAM role
2. **Never read `.env` files in code** -- user sources them in their shell
3. **Never log or print credential values** -- metadata only
4. **Rotate secrets >= every 90 days** -- `adapter.rotate()` supports this
5. **Lock down prod sources** -- use `forbidden: ["env_var", "dotenv"]` in production configs

---

**Author**: Next Shift Consulting
**Related Docs**: `docs/INTEGRATION_GUIDE.md`, `docs/AGENT_PATTERNS.md`, `docs/architecture/ADR-001-AccessScript-Hexagonal.md`
