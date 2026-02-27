"""
Integration test for complete authentication and authorization flow.

Tests the recommended architecture:
1. HeaderIdentityAdapter - extract user from gateway headers
2. RBACPolicyAdapter - check authorization
3. (VaultCredentialBroker would vend credentials - skipped without Vault)
"""

import pytest
from swarm_auth.adapters.header_identity import HeaderIdentityAdapter
from swarm_auth.adapters.rbac_policy import RBACPolicyAdapter
from swarm_auth.ports.policy_port import Action, Resource, Decision


def test_complete_auth_flow():
    """Test complete flow from headers to authorization."""

    # Step 1: Extract identity from headers (from OAuth2-Proxy)
    identity_adapter = HeaderIdentityAdapter()

    headers = {
        "X-Auth-Request-User": "alice",
        "X-Auth-Request-Email": "alice@example.com",
        "X-Auth-Request-Groups": "developers",
    }

    user = identity_adapter.verify_request(headers)

    assert user is not None
    assert user.user_id == "alice"
    assert user.username == "alice"
    assert user.email == "alice@example.com"
    from swarm_auth.domain.user import UserRole
    assert user.role == UserRole.DEVELOPER

    # Step 2: Check if user can access OpenAI chat
    policy_adapter = RBACPolicyAdapter()

    action = Action(
        verb="generate",
        provider="openai",
        resource_type="chat"
    )

    resource = Resource(
        provider="openai",
        resource_type="project",
        identifier="proj-123",
        attributes={}
    )

    decision = policy_adapter.evaluate(user, action, resource)

    assert decision.decision == Decision.ALLOW
    assert decision.max_tokens is not None
    assert decision.max_cost is not None
    assert "developer authorized" in decision.reason.lower()

    # Step 3: Try unauthorized action (audit)
    audit_action = Action(
        verb="read",
        provider="aws",
        resource_type="audit"
    )

    audit_resource = Resource(
        provider="aws",
        resource_type="logs",
        identifier="audit-logs",
        attributes={}
    )

    audit_decision = policy_adapter.evaluate(user, audit_action, audit_resource)

    assert audit_decision.decision == Decision.DENY
    assert "not authorized" in audit_decision.reason.lower()


def test_admin_flow():
    """Test admin has unrestricted access."""

    identity_adapter = HeaderIdentityAdapter()

    headers = {
        "X-Auth-Request-User": "admin",
        "X-Auth-Request-Email": "admin@example.com",
        "X-Auth-Request-Groups": "admin",
    }

    user = identity_adapter.verify_request(headers)

    from swarm_auth.domain.user import UserRole
    assert user.role == UserRole.ADMIN

    # Admin should access anything
    policy_adapter = RBACPolicyAdapter()

    # Try audit action (denied to developers)
    action = Action(verb="read", provider="aws", resource_type="audit")
    resource = Resource(provider="aws", resource_type="logs", identifier="audit-logs", attributes={})

    decision = policy_adapter.evaluate(user, action, resource)

    assert decision.decision == Decision.ALLOW


def test_guest_limited_access():
    """Test guest has very limited access."""

    identity_adapter = HeaderIdentityAdapter()

    headers = {
        "X-Auth-Request-User": "guest",
        "X-Auth-Request-Email": "guest@example.com",
        "X-Auth-Request-Groups": "guest",
    }

    user = identity_adapter.verify_request(headers)

    from swarm_auth.domain.user import UserRole
    assert user.role == UserRole.GUEST

    policy_adapter = RBACPolicyAdapter()

    # Can access LLM
    llm_action = Action(verb="generate", provider="openai", resource_type="chat")
    llm_resource = Resource(provider="openai", resource_type="project", identifier="proj-123", attributes={})

    decision = policy_adapter.evaluate(user, llm_action, llm_resource)
    assert decision.decision == Decision.ALLOW

    # Cannot write to S3
    s3_action = Action(verb="put", provider="aws", resource_type="s3")
    s3_resource = Resource(provider="aws", resource_type="bucket", identifier="my-bucket", attributes={})

    decision = policy_adapter.evaluate(user, s3_action, s3_resource)
    assert decision.decision == Decision.DENY


def test_service_account_flow():
    """Test service account has programmatic access."""

    identity_adapter = HeaderIdentityAdapter()

    headers = {
        "X-Auth-Request-User": "service-bot",
        "X-Auth-Request-Email": "",  # Service accounts may not have email
        "X-Auth-Request-Groups": "service",
    }

    user = identity_adapter.verify_request(headers)

    from swarm_auth.domain.user import UserRole
    assert user.role == UserRole.SERVICE

    policy_adapter = RBACPolicyAdapter()

    # Can access LLM
    llm_action = Action(verb="generate", provider="openai", resource_type="chat")
    llm_resource = Resource(provider="openai", resource_type="project", identifier="proj-123", attributes={})

    decision = policy_adapter.evaluate(user, llm_action, llm_resource)
    assert decision.decision == Decision.ALLOW

    # Can read from S3
    s3_action = Action(verb="get", provider="aws", resource_type="s3")
    s3_resource = Resource(provider="aws", resource_type="bucket", identifier="my-bucket", attributes={})

    decision = policy_adapter.evaluate(user, s3_action, s3_resource)
    assert decision.decision == Decision.ALLOW

    # Cannot write to S3 (read-only for non-LLM)
    s3_write_action = Action(verb="put", provider="aws", resource_type="s3")

    decision = policy_adapter.evaluate(user, s3_write_action, s3_resource)
    assert decision.decision == Decision.DENY
