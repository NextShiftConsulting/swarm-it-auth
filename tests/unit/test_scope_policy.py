"""
Unit tests for ScopePolicyAdapter and ScopeEnforcingBrokerAdapter (ADR-028 Stage 4).

Tests cover:
- Allowed resource (exact match)
- Allowed resource (wildcard match)
- Denied resource (no matching pattern)
- Expired constraint (treated as DENY)
- Agent type restriction (allowed / denied)
- Read-only constraint blocks write actions
- Unknown provider+action (default DENY, fail-closed)
- ScopeEnforcingBrokerAdapter calls inner broker on ALLOW
- ScopeEnforcingBrokerAdapter raises PermissionError on DENY (before provider call)
- validate_resource_indicator (RFC 8707)
- RBAC intersection: scope DENY prevents reaching provider even when RBAC ALLOWs
"""

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from typing import Optional

from swarm_auth.acp.adapters.scope_policy_adapter import (
    ScopePolicyAdapter,
    ScopeEnforcingBrokerAdapter,
    ScopeConstraint,
    ScopePolicyDecision,
)
from swarm_auth.domain.human_user import HumanUser
from swarm_auth.domain.agent_identity import AgentIdentity, AgentType
from swarm_auth.domain.roles import UserRole
from swarm_auth.ports.credential_broker_port import ToolRequest, ProviderType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def human_principal():
    return HumanUser(user_id="u1", username="rudy", role=UserRole.DEVELOPER)


@pytest.fixture
def orchestrator_agent():
    return AgentIdentity(
        user_id="a1", username="orch-001", role=UserRole.SERVICE,
        agent_type=AgentType.ORCHESTRATOR,
    )


@pytest.fixture
def tool_agent():
    return AgentIdentity(
        user_id="a2", username="tool-007", role=UserRole.SERVICE,
        agent_type=AgentType.TOOL,
    )


def _make_policy(*constraints: ScopeConstraint) -> ScopePolicyAdapter:
    """Build a ScopePolicyAdapter with explicit constraints (no YAML needed)."""
    adapter = ScopePolicyAdapter.__new__(ScopePolicyAdapter)
    adapter._constraints = list(constraints)
    return adapter


def _s3_request(action: str = "s3:PutObject", resource: str = "arn:aws:s3:::swarm-data/file.csv"):
    return ToolRequest(
        tool_name="s3_upload",
        provider=ProviderType.AWS,
        action=action,
        resource=resource,
    )


def _openai_request(action: str = "chat.completions.create", resource: str = "project-abc123"):
    return ToolRequest(
        tool_name="openai_chat",
        provider=ProviderType.OPENAI,
        action=action,
        resource=resource,
    )


# ---------------------------------------------------------------------------
# Basic allow / deny
# ---------------------------------------------------------------------------

def test_exact_resource_match_allowed(human_principal):
    constraint = ScopeConstraint(
        id="test-exact",
        provider="aws",
        action_pattern="s3:PutObject",
        allowed_resources=["arn:aws:s3:::swarm-data/file.csv"],
    )
    policy = _make_policy(constraint)
    decision = policy.validate(human_principal, _s3_request())
    assert decision.allowed is True
    assert decision.matched_constraint_id == "test-exact"


def test_wildcard_resource_match_allowed(human_principal):
    constraint = ScopeConstraint(
        id="test-wildcard",
        provider="aws",
        action_pattern="s3:*",
        allowed_resources=["arn:aws:s3:::swarm-*/*"],
    )
    policy = _make_policy(constraint)
    decision = policy.validate(human_principal, _s3_request("s3:PutObject", "arn:aws:s3:::swarm-data/uploads/file.csv"))
    assert decision.allowed is True
    assert decision.matched_resource_pattern == "arn:aws:s3:::swarm-*/*"


def test_resource_not_in_allow_list_denied(human_principal):
    constraint = ScopeConstraint(
        id="test-deny",
        provider="aws",
        action_pattern="s3:*",
        allowed_resources=["arn:aws:s3:::swarm-*/*"],
    )
    policy = _make_policy(constraint)
    decision = policy.validate(human_principal, _s3_request("s3:PutObject", "arn:aws:s3:::prod-secrets/key.pem"))
    assert decision.allowed is False
    assert "prod-secrets" in decision.reason


def test_no_constraint_for_provider_action_denied(human_principal):
    """Unknown provider+action is fail-closed (DENY)."""
    constraint = ScopeConstraint(
        id="aws-only",
        provider="aws",
        action_pattern="s3:*",
        allowed_resources=["arn:aws:s3:::swarm-*"],
    )
    policy = _make_policy(constraint)
    # openai request — no constraint defined
    decision = policy.validate(human_principal, _openai_request())
    assert decision.allowed is False
    assert "No scope constraint defined" in decision.reason


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------

def test_expired_constraint_is_skipped(human_principal):
    """An expired constraint is skipped. If no other constraint matches: DENY."""
    past = datetime.now(timezone.utc) - timedelta(days=1)
    constraint = ScopeConstraint(
        id="expired",
        provider="aws",
        action_pattern="s3:*",
        allowed_resources=["arn:aws:s3:::swarm-*/*"],
        expires_at=past,
    )
    policy = _make_policy(constraint)
    decision = policy.validate(human_principal, _s3_request())
    assert decision.allowed is False


def test_future_expiry_constraint_allows(human_principal):
    """A constraint expiring in the future is valid."""
    future = datetime.now(timezone.utc) + timedelta(days=365)
    constraint = ScopeConstraint(
        id="future",
        provider="aws",
        action_pattern="s3:*",
        allowed_resources=["arn:aws:s3:::swarm-*/*"],
        expires_at=future,
    )
    policy = _make_policy(constraint)
    decision = policy.validate(human_principal, _s3_request("s3:PutObject", "arn:aws:s3:::swarm-data/file.csv"))
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# Agent type restriction
# ---------------------------------------------------------------------------

def test_agent_type_restriction_allows_matching_type(orchestrator_agent):
    constraint = ScopeConstraint(
        id="orch-only",
        provider="aws",
        action_pattern="s3:*",
        allowed_resources=["arn:aws:s3:::swarm-*/*"],
        agent_types=["orchestrator"],
    )
    policy = _make_policy(constraint)
    decision = policy.validate(orchestrator_agent, _s3_request("s3:PutObject", "arn:aws:s3:::swarm-data/file.csv"))
    assert decision.allowed is True


def test_agent_type_restriction_denies_wrong_type(tool_agent):
    constraint = ScopeConstraint(
        id="orch-only",
        provider="aws",
        action_pattern="s3:*",
        allowed_resources=["arn:aws:s3:::swarm-*/*"],
        agent_types=["orchestrator"],
    )
    policy = _make_policy(constraint)
    decision = policy.validate(tool_agent, _s3_request("s3:PutObject", "arn:aws:s3:::swarm-data/file.csv"))
    assert decision.allowed is False


def test_agent_type_restriction_denies_human(human_principal):
    """HumanUser is not an AgentIdentity — denied when agent_types is set."""
    constraint = ScopeConstraint(
        id="agent-only",
        provider="aws",
        action_pattern="s3:*",
        allowed_resources=["arn:aws:s3:::swarm-*/*"],
        agent_types=["orchestrator", "tool"],
    )
    policy = _make_policy(constraint)
    decision = policy.validate(human_principal, _s3_request("s3:PutObject", "arn:aws:s3:::swarm-data/file.csv"))
    assert decision.allowed is False


def test_null_agent_types_allows_human(human_principal):
    """agent_types=None means any principal type is allowed."""
    constraint = ScopeConstraint(
        id="any-principal",
        provider="aws",
        action_pattern="s3:*",
        allowed_resources=["arn:aws:s3:::swarm-*/*"],
        agent_types=None,
    )
    policy = _make_policy(constraint)
    decision = policy.validate(human_principal, _s3_request("s3:PutObject", "arn:aws:s3:::swarm-data/file.csv"))
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# Read-only constraint
# ---------------------------------------------------------------------------

def test_read_only_constraint_blocks_put(human_principal):
    constraint = ScopeConstraint(
        id="readonly",
        provider="aws",
        action_pattern="s3:*",
        allowed_resources=["arn:aws:s3:::swarm-*/*"],
        read_only=True,
    )
    policy = _make_policy(constraint)
    decision = policy.validate(human_principal, _s3_request("s3:PutObject", "arn:aws:s3:::swarm-data/file.csv"))
    assert decision.allowed is False


def test_read_only_constraint_allows_get(human_principal):
    constraint = ScopeConstraint(
        id="readonly",
        provider="aws",
        action_pattern="s3:*",
        allowed_resources=["arn:aws:s3:::swarm-*/*"],
        read_only=True,
    )
    policy = _make_policy(constraint)
    decision = policy.validate(human_principal, _s3_request("s3:GetObject", "arn:aws:s3:::swarm-data/file.csv"))
    assert decision.allowed is True


# ---------------------------------------------------------------------------
# Multiple constraints — first match wins
# ---------------------------------------------------------------------------

def test_first_matching_non_expired_constraint_wins(human_principal):
    """First valid (non-expired, not agent-restricted) constraint that matches wins."""
    past = datetime.now(timezone.utc) - timedelta(days=1)
    future = datetime.now(timezone.utc) + timedelta(days=1)
    constraints = [
        ScopeConstraint(
            id="expired-block",
            provider="aws",
            action_pattern="s3:*",
            allowed_resources=["arn:aws:s3:::swarm-*/*"],
            expires_at=past,
        ),
        ScopeConstraint(
            id="valid-allow",
            provider="aws",
            action_pattern="s3:*",
            allowed_resources=["arn:aws:s3:::swarm-*/*"],
            expires_at=future,
        ),
    ]
    policy = _make_policy(*constraints)
    decision = policy.validate(human_principal, _s3_request("s3:GetObject", "arn:aws:s3:::swarm-data/file.csv"))
    assert decision.allowed is True
    assert decision.matched_constraint_id == "valid-allow"


# ---------------------------------------------------------------------------
# RFC 8707 resource indicator
# ---------------------------------------------------------------------------

def test_validate_resource_indicator_known_resource():
    constraint = ScopeConstraint(
        id="openai-chat",
        provider="openai",
        action_pattern="chat.*",
        allowed_resources=["project-*"],
    )
    policy = _make_policy(constraint)
    assert policy.validate_resource_indicator("project-abc123", "openai") is True


def test_validate_resource_indicator_unknown_resource():
    constraint = ScopeConstraint(
        id="openai-chat",
        provider="openai",
        action_pattern="chat.*",
        allowed_resources=["project-*"],
    )
    policy = _make_policy(constraint)
    assert policy.validate_resource_indicator("evil-project", "openai") is False


def test_validate_resource_indicator_expired_constraint():
    past = datetime.now(timezone.utc) - timedelta(days=1)
    constraint = ScopeConstraint(
        id="expired",
        provider="openai",
        action_pattern="chat.*",
        allowed_resources=["project-*"],
        expires_at=past,
    )
    policy = _make_policy(constraint)
    # Expired constraint not valid for resource indicator check
    assert policy.validate_resource_indicator("project-abc123", "openai") is False


# ---------------------------------------------------------------------------
# ScopeEnforcingBrokerAdapter — deny before provider call
# ---------------------------------------------------------------------------

def test_scope_enforcing_broker_allows_and_delegates(human_principal):
    """On ALLOW, inner broker's vend_credential() is called exactly once."""
    constraint = ScopeConstraint(
        id="allow",
        provider="openai",
        action_pattern="chat.*",
        allowed_resources=["project-*"],
    )
    policy = _make_policy(constraint)

    inner = MagicMock()
    inner.vend_credential.return_value = MagicMock()

    broker = ScopeEnforcingBrokerAdapter(inner=inner, scope_policy=policy)
    broker.vend_credential(human_principal, _openai_request())

    inner.vend_credential.assert_called_once()


def test_scope_enforcing_broker_denies_before_provider_call(human_principal):
    """On DENY, inner broker is never called — PermissionError raised first."""
    constraint = ScopeConstraint(
        id="restricted",
        provider="openai",
        action_pattern="chat.*",
        allowed_resources=["project-abc123"],  # only this one project
    )
    policy = _make_policy(constraint)

    inner = MagicMock()
    broker = ScopeEnforcingBrokerAdapter(inner=inner, scope_policy=policy)

    with pytest.raises(PermissionError, match="Scope policy denied"):
        broker.vend_credential(human_principal, _openai_request(resource="project-evil"))

    inner.vend_credential.assert_not_called()


# ---------------------------------------------------------------------------
# RBAC intersection (scope DENY prevents reaching provider)
# ---------------------------------------------------------------------------

def test_scope_deny_prevents_provider_call_even_when_rbac_allows(human_principal):
    """
    RBAC ∩ ScopePolicy: scope denial blocks the request before RBAC runs.
    Even if RBAC would have allowed the action, the scope policy gate stops it.
    This test verifies the ordering: scope check → provider call (RBAC is upstream).
    """
    # Constraint allows only swarm-* buckets
    constraint = ScopeConstraint(
        id="swarm-only",
        provider="aws",
        action_pattern="s3:*",
        allowed_resources=["arn:aws:s3:::swarm-*/*"],
    )
    policy = _make_policy(constraint)
    inner = MagicMock()
    broker = ScopeEnforcingBrokerAdapter(inner=inner, scope_policy=policy)

    # Resource is NOT in the allow-list
    forbidden_request = ToolRequest(
        tool_name="s3_upload",
        provider=ProviderType.AWS,
        action="s3:PutObject",
        resource="arn:aws:s3:::prod-customer-data/secret.csv",  # not in swarm-*
    )

    with pytest.raises(PermissionError):
        broker.vend_credential(human_principal, forbidden_request)

    inner.vend_credential.assert_not_called()


# ---------------------------------------------------------------------------
# Default config loads without error (smoke test)
# ---------------------------------------------------------------------------

def test_default_scope_constraints_loads():
    """Bundled scope_constraints.yaml loads without error."""
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("PyYAML not installed")

    policy = ScopePolicyAdapter()  # loads bundled defaults
    assert policy.loaded_constraint_count() > 0
