## Agent Authentication Patterns for Multi-Cloud AI Systems

**Problem**: Agents span AWS, GCP, OpenAI, Hugging Face, etc. How do you manage credentials securely?

**Solution**: Two-plane architecture + credential vending machine pattern.

---

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    INBOUND AUTH PLANE                        │
│  (Users/Services → Your API)                                 │
│                                                              │
│  User/Agent → JWT/API Key → Principal                       │
│  • IdentityVerifier (port)                                  │
│  • SessionPort                                              │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                   AUTHORIZATION (PDP)                        │
│  Can Principal perform Action on Resource?                  │
│                                                              │
│  • PolicyDecisionPoint (port)                               │
│  • Tool-centric: llm.generate, aws.s3.put, gcp.storage.read │
│  • Returns: allow/deny + obligations (budget, rate limits)  │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                   OUTBOUND AUTH PLANE                        │
│  (Your System/Agents → External Providers)                  │
│                                                              │
│  CredentialBroker → Short-lived provider credentials        │
│  • AWS: STS AssumeRole (15min-1hr)                          │
│  • GCP: Workload Identity Federation                        │
│  • OpenAI: Project-scoped keys                              │
│  • HF: Fine-grained tokens                                  │
└─────────────────────────────────────────────────────────────┘
```

---

### Pattern 1: Never Hold Long-Lived Secrets

**❌ Bad: Store AWS access keys in agent config**
```python
agent_config = {
    "aws_access_key": "AKIA...",  # Long-lived!
    "aws_secret_key": "...",      # Never expires!
}
```

**✅ Good: Vend temporary credentials on-demand**
```python
# Agent requests capability
tool_request = ToolRequest(
    tool_name="s3_upload",
    provider=ProviderType.AWS,
    action="s3:PutObject",
    resource="arn:aws:s3:::bucket/prefix/*",
    max_duration=900,  # 15 minutes
)

# Broker mints STS credentials with session policy
credential = broker.vend_credential(principal=agent, tool_request=tool_request)

# Credential expires in 15 minutes
# Contains: access_key, secret_key, session_token
```

---

### Pattern 2: Tool-Centric Authorization (Not Endpoint-Centric)

**❌ Bad: Endpoint-level checks**
```python
@app.post("/api/generate")
def generate(user: User):
    if user.role != "admin":
        raise Forbidden
    # What if user is developer? Service account?
```

**✅ Good: Capability-based checks**
```python
action = Action(verb="generate", provider="openai", resource_type="chat")
resource = Resource(provider="openai", resource_type="project", identifier="proj-123")

decision = pdp.evaluate(principal=agent, action=action, resource=resource)

if decision.decision == Decision.ALLOW:
    # Check obligations
    if tokens > decision.max_tokens:
        raise TooManyTokensError()
    # Proceed with call
```

---

### Pattern 3: Scoped Credentials Per Request

**AWS Example: Session Policies**
```python
# Agent wants to upload to S3
# Broker assumes role AND applies session policy

session_policy = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:PutObject",
        "Resource": "arn:aws:s3:::my-bucket/agent-123/*"  # Scoped to prefix!
    }]
}

# STS credentials are valid for 15min and ONLY for this prefix
credentials = sts.assume_role(
    RoleArn="arn:aws:iam::123456789012:role/AgentS3Role",
    RoleSessionName=f"agent-{agent.user_id}",
    Policy=json.dumps(session_policy),
    DurationSeconds=900
)
```

**GCP Example: Service Account Impersonation**
```python
# Agent wants to read from GCS
# Broker impersonates service account with narrow scope

target_credentials = impersonated_credentials.Credentials(
    source_credentials=workload_identity_token,
    target_principal="storage-reader@project.iam.gserviceaccount.com",
    target_scopes=["https://www.googleapis.com/auth/devstorage.read_only"],
    lifetime=900,
)
```

---

### Pattern 4: Obligations from Policy

Policy doesn't just return allow/deny. It returns **obligations**:

```python
decision = pdp.evaluate(agent, action, resource, context)

if decision.decision == Decision.ALLOW:
    # Enforce obligations
    if decision.must_log:
        audit_log.record(agent, action, resource)

    if decision.max_tokens and tokens > decision.max_tokens:
        raise QuotaExceededError(f"Max {decision.max_tokens} tokens")

    if decision.max_cost and cost > decision.max_cost:
        raise BudgetExceededError(f"Max ${decision.max_cost}")

    # Rate limits
    if decision.rate_limit:
        rate_limiter.check(agent.user_id, decision.rate_limit)
```

---

### Pattern 5: Separate Environments by Boundary

**OpenAI**: Separate Projects per environment
```python
# Dev environment
openai_broker_dev = OpenAICredentialBroker(project_id="proj-dev-123")

# Prod environment
openai_broker_prod = OpenAICredentialBroker(project_id="proj-prod-456")
```

**AWS**: Separate accounts or roles per environment
```python
# Dev account
aws_broker_dev = AWSCredentialBroker(
    role_arn_template="arn:aws:iam::111111111111:role/{tool_name}",
    account_id="111111111111"
)

# Prod account
aws_broker_prod = AWSCredentialBroker(
    role_arn_template="arn:aws:iam::999999999999:role/{tool_name}",
    account_id="999999999999"
)
```

---

### Pattern 6: Kill Switches

**Per-tool disable**
```python
disabled_tools = {"s3_upload", "openai_chat"}

if tool_request.tool_name in disabled_tools:
    raise ToolDisabledError(f"{tool_request.tool_name} is disabled")
```

**Per-provider disable**
```python
disabled_providers = {ProviderType.OPENAI}

if tool_request.provider in disabled_providers:
    raise ProviderDisabledError(f"{tool_request.provider} is disabled")
```

**Per-principal disable**
```python
blocked_principals = {"agent_123", "user_456"}

if principal.user_id in blocked_principals:
    raise PrincipalBlockedError(f"{principal.user_id} is blocked")
```

---

### Pattern 7: Budget Limits

**Track costs per principal + per provider**
```python
budget_tracker = BudgetTracker()

# Before vending credential
current_spend = budget_tracker.get_spend(
    principal_id=agent.user_id,
    provider=ProviderType.OPENAI,
    period="hourly"
)

if current_spend + estimated_cost > budget_limit:
    raise BudgetExceededError(
        f"Hourly budget ${budget_limit} exceeded (current: ${current_spend})"
    )

# After tool execution
budget_tracker.record(
    principal_id=agent.user_id,
    provider=ProviderType.OPENAI,
    cost=actual_cost,
)
```

---

### Complete Flow Example

```python
# 1. INBOUND: Agent authenticates
token = request.headers["Authorization"]
agent = auth.authenticate(token)  # → Principal

# 2. POLICY: Check if allowed
action = Action(verb="generate", provider="openai", resource_type="chat")
resource = Resource(provider="openai", resource_type="project", identifier="proj-123")
context = PolicyContext(token_estimate=1000, cost_estimate=0.02)

decision = pdp.evaluate(agent, action, resource, context)

if decision.decision == Decision.DENY:
    raise PermissionDeniedError(decision.reason)

# 3. VEND: Get short-lived OpenAI key
tool_request = ToolRequest(
    tool_name="openai_chat",
    provider=ProviderType.OPENAI,
    action="chat.completions.create",
    resource="proj-123",
    max_duration=3600,
)

credential = broker.vend_credential(agent, tool_request)

# 4. EXECUTE: Call OpenAI with temp credential
import openai
client = openai.OpenAI(api_key=credential.credentials["api_key"])
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": prompt}],
)

# 5. AUDIT: Log everything
audit_log.record({
    "principal_id": agent.user_id,
    "action": f"{action.provider}.{action.resource_type}.{action.verb}",
    "resource": resource.identifier,
    "decision": decision.decision.value,
    "credential_type": credential.credential_type,
    "tokens_used": response.usage.total_tokens,
    "cost": calculate_cost(response.usage),
})
```

---

### Operational Best Practices

1. **No long-lived keys in containers**
   - AWS: Use STS AssumeRole
   - GCP: Use Workload Identity Federation
   - Never bake keys into Docker images

2. **Separate environments by boundary**
   - OpenAI: Projects
   - AWS: Accounts or roles
   - GCP: Projects + service accounts

3. **Prompt safety**
   - Never let secrets enter prompts
   - Redact logs (never log API keys)
   - Treat model outputs as untrusted input

4. **Kill switches**
   - Per-tool disable
   - Per-provider disable
   - Per-principal disable

5. **Budget limits**
   - Per principal + per provider + per tool
   - Tokens/$ per minute/hour/day

---

### Testing Strategy

```python
# Unit tests: Mock the broker
def test_agent_auth():
    fake_broker = FakeBroker()
    fake_broker.set_credential(ProviderCredential(...))

    agent = authenticate_agent(token)
    cred = fake_broker.vend_credential(agent, tool_request)

    assert cred.provider == ProviderType.AWS
    assert cred.expires_at > datetime.utcnow()

# Integration tests: Real providers (in test account)
def test_aws_broker_integration():
    broker = AWSCredentialBroker(account_id="test-account")
    cred = broker.vend_credential(test_agent, s3_upload_request)

    # Verify credential works
    s3 = boto3.client("s3", **cred.credentials)
    s3.put_object(Bucket="test-bucket", Key="test.txt", Body=b"test")
```

---

### Summary

**Two planes**:
1. Inbound auth (users → API): JWT/API keys → Principal
2. Outbound auth (agents → providers): Credential broker → temp creds

**Key ports**:
- `IdentityVerifier`: Authenticate inbound requests
- `PolicyDecisionPoint`: Authorize capabilities
- `CredentialBroker`: Vend short-lived provider credentials

**Best practices**:
- Never store long-lived secrets
- Vend credentials per request (15min-1hr)
- Enforce obligations (budget, rate limits, logging)
- Kill switches at multiple levels
- Separate environments by boundary
