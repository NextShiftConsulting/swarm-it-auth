"""
Example: Complete agent credential flow with PDP + Credential Broker.

Shows the recommended pattern:
1. Authenticate agent (inbound auth)
2. Check policy (can agent use this tool?)
3. Vend credential (mint short-lived provider credential)
4. Execute tool call
5. Audit
"""

import os
from datetime import datetime
from swarm_auth import User, UserRole
from swarm_auth.adapters import JWTAuthAdapter
from swarm_auth.adapters.rbac_policy import RBACPolicyAdapter
from swarm_auth.adapters.aws_credential_broker import AWSCredentialBroker
from swarm_auth.adapters.openai_credential_broker import OpenAICredentialBroker
from swarm_auth.ports.policy_port import Action, Resource, PolicyContext, Decision
from swarm_auth.ports.credential_broker_port import ToolRequest, ProviderType


def main():
    print("=" * 60)
    print("Agent Credential Flow Example")
    print("=" * 60)

    # 1. INBOUND AUTH: Authenticate the agent
    print("\n1. Authenticating agent...")
    auth = JWTAuthAdapter(secret="agent-secret")

    agent = User(
        user_id="agent_123",
        username="data-processor-agent",
        role=UserRole.SERVICE,  # Service account
        is_service_account=True,
    )

    token = auth.create_token(agent, expires_in=3600)
    print(f"   ✓ Agent authenticated: {agent.username}")
    print(f"   ✓ Token: {token[:50]}...")

    # Verify token (simulates inbound request)
    verified_agent = auth.authenticate(token)
    print(f"   ✓ Token verified: {verified_agent.username}")

    # 2. POLICY CHECK: Can agent use this tool?
    print("\n2. Checking policy...")
    pdp = RBACPolicyAdapter()

    # Agent wants to upload to S3
    action = Action(
        verb="put",
        provider="aws",
        resource_type="s3",
    )

    resource = Resource(
        provider="aws",
        resource_type="s3",
        identifier="my-bucket/data/*",
        attributes={"region": "us-east-1"},
    )

    context = PolicyContext(
        timestamp=datetime.utcnow().isoformat(),
        cost_estimate=0.01,  # $0.01
        request_id="req_abc123",
    )

    decision = pdp.evaluate(verified_agent, action, resource, context)

    print(f"   Decision: {decision.decision.value}")
    print(f"   Reason: {decision.reason}")

    if decision.decision == Decision.DENY:
        print("   ✗ Access denied. Stopping.")
        return

    print(f"   ✓ Access allowed")
    print(f"   Obligations:")
    print(f"     - Must log: {decision.must_log}")
    print(f"     - Max cost: ${decision.max_cost}")
    print(f"     - Rate limit: {decision.rate_limit}")

    # 3. VEND CREDENTIAL: Get short-lived AWS credentials
    print("\n3. Vending AWS credentials...")

    broker = AWSCredentialBroker(
        region="us-east-1",
        account_id="123456789012",  # Your AWS account ID
    )

    tool_request = ToolRequest(
        tool_name="s3_upload",
        provider=ProviderType.AWS,
        action="s3:PutObject",
        resource="arn:aws:s3:::my-bucket/data/*",
        max_duration=900,  # 15 minutes
        scope_restrictions={"region": "us-east-1"},
        principal_id=verified_agent.user_id,
        request_id="req_abc123",
    )

    try:
        credential = broker.vend_credential(verified_agent, tool_request)

        print(f"   ✓ Credential vended")
        print(f"   Provider: {credential.provider.value}")
        print(f"   Type: {credential.credential_type}")
        print(f"   Expires: {credential.expires_at}")
        print(f"   Scope: {credential.scope}")
        print(f"   Session: {credential.session_name}")

        # 4. EXECUTE TOOL: Use credential to call AWS
        print("\n4. Executing tool call...")
        print("   [Would call S3 PutObject with temporary credentials]")
        print("   [Credentials contain: access_key, secret_key, session_token]")

        # Example (pseudo-code):
        # import boto3
        # s3 = boto3.client(
        #     "s3",
        #     aws_access_key_id=credential.credentials["access_key_id"],
        #     aws_secret_access_key=credential.credentials["secret_access_key"],
        #     aws_session_token=credential.credentials["session_token"],
        # )
        # s3.put_object(Bucket="my-bucket", Key="data/file.json", Body=data)

        # 5. AUDIT
        print("\n5. Audit log:")
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "principal_id": verified_agent.user_id,
            "principal_role": verified_agent.role.value,
            "action": f"{action.provider}.{action.resource_type}.{action.verb}",
            "resource": resource.identifier,
            "decision": decision.decision.value,
            "credential_type": credential.credential_type,
            "provider": credential.provider.value,
            "request_id": "req_abc123",
        }
        print(f"   {audit_entry}")

    except Exception as e:
        print(f"   ✗ Failed to vend credential: {e}")
        print("   (Note: Requires AWS credentials configured)")

    # Example with OpenAI
    print("\n" + "=" * 60)
    print("OpenAI Credential Flow")
    print("=" * 60)

    # Agent wants to call OpenAI
    action_openai = Action(
        verb="create",
        provider="openai",
        resource_type="chat",
    )

    resource_openai = Resource(
        provider="openai",
        resource_type="project",
        identifier="proj-abc123",
        attributes={},
    )

    context_openai = PolicyContext(
        timestamp=datetime.utcnow().isoformat(),
        token_estimate=1000,
        cost_estimate=0.02,
    )

    decision_openai = pdp.evaluate(verified_agent, action_openai, resource_openai, context_openai)
    print(f"\n1. Policy decision: {decision_openai.decision.value}")
    print(f"   Max tokens: {decision_openai.max_tokens}")

    if decision_openai.decision == Decision.ALLOW:
        print("\n2. Vending OpenAI credentials...")
        openai_broker = OpenAICredentialBroker(
            project_id="proj-abc123",
            master_api_key=os.environ.get("OPENAI_API_KEY", "sk-placeholder"),
        )

        openai_request = ToolRequest(
            tool_name="openai_chat",
            provider=ProviderType.OPENAI,
            action="chat.completions.create",
            resource="proj-abc123",
            max_duration=3600,
            principal_id=verified_agent.user_id,
        )

        openai_cred = openai_broker.vend_credential(verified_agent, openai_request)
        print(f"   ✓ OpenAI credential vended")
        print(f"   Project: {openai_cred.credentials['project_id']}")
        print(f"   Scope: {openai_cred.scope}")


if __name__ == "__main__":
    print("\nAgent Credential Flow Demo")
    print("=" * 60)
    print("\nThis example shows:")
    print("1. Agent authentication (inbound)")
    print("2. Policy evaluation (PDP)")
    print("3. Credential vending (broker)")
    print("4. Tool execution (with temp creds)")
    print("5. Audit logging")
    print("\n" + "=" * 60 + "\n")

    main()
