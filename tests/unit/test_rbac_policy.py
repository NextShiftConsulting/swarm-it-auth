"""
Unit tests for RBAC Policy Adapter.
"""

import pytest
from datetime import datetime
from swarm_auth.domain.user import User, UserRole
from swarm_auth.adapters.rbac_policy import RBACPolicyAdapter
from swarm_auth.ports.policy_port import Action, Resource, PolicyContext, Decision


def test_rbac_admin_has_all_permissions():
    """Admin should have all permissions."""
    pdp = RBACPolicyAdapter()
    admin = User(user_id="admin1", username="admin", role=UserRole.ADMIN)

    action = Action(verb="generate", provider="openai", resource_type="chat")
    resource = Resource(provider="openai", resource_type="project", identifier="proj-123", attributes={})

    decision = pdp.evaluate(admin, action, resource)

    assert decision.decision == Decision.ALLOW
    assert "admin" in decision.reason.lower()


def test_rbac_developer_can_generate():
    """Developer should be able to generate LLM content."""
    pdp = RBACPolicyAdapter()
    dev = User(user_id="dev1", username="dev", role=UserRole.DEVELOPER)

    action = Action(verb="generate", provider="openai", resource_type="chat")
    resource = Resource(provider="openai", resource_type="project", identifier="proj-123", attributes={})

    decision = pdp.evaluate(dev, action, resource)

    assert decision.decision == Decision.ALLOW


def test_rbac_service_cannot_audit():
    """Service accounts should not be able to audit."""
    pdp = RBACPolicyAdapter()
    service = User(user_id="svc1", username="service", role=UserRole.SERVICE)

    action = Action(verb="read", provider="aws", resource_type="audit")
    resource = Resource(provider="aws", resource_type="logs", identifier="audit-logs", attributes={})

    decision = pdp.evaluate(service, action, resource)

    # Service role doesn't have "audit" capability
    assert decision.decision == Decision.DENY


def test_rbac_guest_limited_access():
    """Guest should only have LLM generate access."""
    pdp = RBACPolicyAdapter()
    guest = User(user_id="guest1", username="guest", role=UserRole.GUEST)

    # Can generate
    action_generate = Action(verb="generate", provider="openai", resource_type="chat")
    resource = Resource(provider="openai", resource_type="project", identifier="proj-123", attributes={})

    decision = pdp.evaluate(guest, action_generate, resource)
    assert decision.decision == Decision.ALLOW

    # Cannot write to S3
    action_write = Action(verb="put", provider="aws", resource_type="s3")
    resource_s3 = Resource(provider="aws", resource_type="bucket", identifier="my-bucket", attributes={})

    decision = pdp.evaluate(guest, action_write, resource_s3)
    assert decision.decision == Decision.DENY


def test_rbac_budget_limits():
    """Budget limits should be enforced."""
    pdp = RBACPolicyAdapter()
    dev = User(user_id="dev1", username="dev", role=UserRole.DEVELOPER)

    action = Action(verb="generate", provider="openai", resource_type="chat")
    resource = Resource(provider="openai", resource_type="project", identifier="proj-123", attributes={})

    # Within budget
    context = PolicyContext(timestamp=datetime.utcnow().isoformat(), cost_estimate=50.0)
    decision = pdp.evaluate(dev, action, resource, context)
    assert decision.decision == Decision.ALLOW

    # Over budget (dev limit is $100/hour)
    context_over = PolicyContext(timestamp=datetime.utcnow().isoformat(), cost_estimate=150.0)
    decision = pdp.evaluate(dev, action, resource, context_over)
    assert decision.decision == Decision.DENY
    assert "budget" in decision.reason.lower()


def test_rbac_token_limits():
    """Token limits should be enforced."""
    pdp = RBACPolicyAdapter()
    guest = User(user_id="guest1", username="guest", role=UserRole.GUEST)

    action = Action(verb="generate", provider="openai", resource_type="chat")
    resource = Resource(provider="openai", resource_type="project", identifier="proj-123", attributes={})

    # Within limit
    context = PolicyContext(timestamp=datetime.utcnow().isoformat(), token_estimate=400)
    decision = pdp.evaluate(guest, action, resource, context)
    assert decision.decision == Decision.ALLOW

    # Over limit (guest limit is 500 tokens)
    context_over = PolicyContext(timestamp=datetime.utcnow().isoformat(), token_estimate=600)
    decision = pdp.evaluate(guest, action, resource, context_over)
    assert decision.decision == Decision.DENY
    assert "token" in decision.reason.lower()


def test_rbac_batch_evaluate():
    """Batch evaluation should work."""
    pdp = RBACPolicyAdapter()
    dev = User(user_id="dev1", username="dev", role=UserRole.DEVELOPER)

    requests = [
        (
            Action(verb="generate", provider="openai", resource_type="chat"),
            Resource(provider="openai", resource_type="project", identifier="proj-123", attributes={})
        ),
        (
            Action(verb="put", provider="aws", resource_type="s3"),
            Resource(provider="aws", resource_type="bucket", identifier="my-bucket", attributes={})
        ),
    ]

    decisions = pdp.batch_evaluate(dev, requests)

    assert len(decisions) == 2
    assert decisions[0].decision == Decision.ALLOW  # Can generate
    assert decisions[1].decision == Decision.ALLOW  # Can put to S3
