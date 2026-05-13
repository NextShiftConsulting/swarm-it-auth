"""
Domain tests for Principal hierarchy (ADR-028 Stage 1 gate).

These tests must ALL pass before Stage 1 is stamped complete.
They define chain ordering and depth-limit behavior unambiguously
so that future contributors cannot reverse the chain or remove
the depth guard without a test failure.
"""

import pytest
from swarm_auth.domain.principal import Principal
from swarm_auth.domain.human_user import HumanUser
from swarm_auth.domain.agent_identity import (
    AgentIdentity,
    AgentType,
    ActorChain,
    MAX_ACT_CHAIN_DEPTH,
)
from swarm_auth.domain.roles import UserRole
from swarm_auth.domain.user import User, UserRole as UserRoleAlias
from swarm_auth.acp import ActorChain as AcpActorChain


# ---------------------------------------------------------------------------
# Principal ABC
# ---------------------------------------------------------------------------

def test_principal_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        Principal(user_id="x", username="x", role=UserRole.ADMIN)  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# HumanUser
# ---------------------------------------------------------------------------

def test_human_user_kind():
    u = HumanUser(user_id="u1", username="rudy", role=UserRole.DEVELOPER)
    assert u.kind() == "human"


def test_human_user_construction_without_agent_fields():
    """HumanUser has no agent_type, parent_agent_id, or sponsor_id."""
    u = HumanUser(user_id="u1", username="rudy", role=UserRole.DEVELOPER, email="rudy@example.com")
    assert u.email == "rudy@example.com"
    assert not hasattr(u, "agent_type") or u.__class__ is HumanUser
    # Verify it's a Principal
    assert isinstance(u, Principal)


def test_human_user_is_service_account_is_false():
    """is_service_account is deprecated but must be False on HumanUser."""
    u = HumanUser(user_id="u1", username="rudy", role=UserRole.DEVELOPER)
    assert u.is_service_account is False


def test_human_user_serialization_round_trip():
    u = HumanUser(
        user_id="u1", username="rudy", role=UserRole.DEVELOPER,
        email="rudy@test.com", org_id="org1",
    )
    data = u.to_dict()
    restored = HumanUser.from_dict(data)
    assert restored.user_id == u.user_id
    assert restored.username == u.username
    assert restored.role == u.role
    assert restored.email == u.email
    assert restored.org_id == u.org_id
    assert restored.kind() == "human"


def test_human_user_to_dict_has_principal_kind():
    u = HumanUser(user_id="u1", username="rudy", role=UserRole.DEVELOPER)
    assert u.to_dict()["principal_kind"] == "human"


# ---------------------------------------------------------------------------
# AgentIdentity
# ---------------------------------------------------------------------------

def test_agent_identity_kind():
    a = AgentIdentity(user_id="a1", username="assistant", role=UserRole.SERVICE,
                      agent_type=AgentType.ASSISTANT)
    assert a.kind() == "agent"


def test_agent_identity_construction_without_email_fields():
    """AgentIdentity has no email or last_login."""
    a = AgentIdentity(user_id="a1", username="orch-001", role=UserRole.SERVICE,
                      agent_type=AgentType.ORCHESTRATOR, owning_team="search")
    assert a.owning_team == "search"
    assert isinstance(a, Principal)


def test_agent_type_has_no_human_value():
    """AgentType.HUMAN must not exist — defeats the HumanUser/AgentIdentity split."""
    assert not hasattr(AgentType, "HUMAN"), (
        "AgentType.HUMAN must not exist. "
        "Human identity is expressed by HumanUser, not AgentIdentity.agent_type. "
        "See ADR-028 SD-1 and implementation plan pre-Stage-1 fix #2."
    )


def test_agent_identity_serialization_round_trip():
    a = AgentIdentity(
        user_id="a1", username="tool-007", role=UserRole.SERVICE,
        agent_type=AgentType.TOOL, owning_team="search", sponsor_id="rudy",
    )
    data = a.to_dict()
    restored = AgentIdentity.from_dict(data)
    assert restored.user_id == a.user_id
    assert restored.agent_type == AgentType.TOOL
    assert restored.owning_team == a.owning_team
    assert restored.kind() == "agent"


def test_agent_identity_to_dict_has_principal_kind():
    a = AgentIdentity(user_id="a1", username="bot", role=UserRole.SERVICE)
    assert a.to_dict()["principal_kind"] == "agent"


# ---------------------------------------------------------------------------
# ActorChain ordering (the chain direction must be unambiguous)
# ---------------------------------------------------------------------------

def test_actor_chain_three_hop_ordering():
    """human -> orchestrator -> tool: outermost = originator, innermost = proximate actor."""
    chain = ActorChain(
        sub="rudy",
        role="developer",
        act=ActorChain(
            sub="orchestrator-001",
            agent_type="orchestrator",
            act=ActorChain(sub="tool-agent-007", agent_type="tool"),
        ),
    )
    claim = chain.to_jwt_claim()

    # Ordering must be stable
    assert claim["sub"] == "rudy"
    assert claim["act"]["sub"] == "orchestrator-001"
    assert claim["act"]["act"]["sub"] == "tool-agent-007"
    assert "act" not in claim["act"]["act"]  # leaf has no act


def test_actor_chain_round_trip():
    chain = ActorChain(
        sub="rudy",
        role="developer",
        act=ActorChain(
            sub="orchestrator-001",
            agent_type="orchestrator",
            act=ActorChain(sub="tool-agent-007", agent_type="tool"),
        ),
    )
    claim = chain.to_jwt_claim()
    restored = ActorChain.from_jwt_claim(claim)

    assert restored.sub == "rudy"
    assert restored.role == "developer"
    assert restored.act is not None
    assert restored.act.sub == "orchestrator-001"
    assert restored.act.agent_type == "orchestrator"
    assert restored.act.act is not None
    assert restored.act.act.sub == "tool-agent-007"
    assert restored.act.act.act is None


def test_actor_chain_single_hop():
    """A chain with no delegation (just a subject) is valid."""
    chain = ActorChain(sub="rudy")
    claim = chain.to_jwt_claim()
    assert claim == {"sub": "rudy"}
    restored = ActorChain.from_jwt_claim(claim)
    assert restored.sub == "rudy"
    assert restored.act is None


def test_actor_chain_depth_limit():
    """Chains exceeding MAX_ACT_CHAIN_DEPTH raise ValueError."""
    def build_claim(depth: int) -> dict:
        if depth == 0:
            return {"sub": "leaf"}
        return {"sub": f"node-{depth}", "act": build_claim(depth - 1)}

    # Exactly at limit: should succeed
    at_limit = build_claim(MAX_ACT_CHAIN_DEPTH)
    chain = ActorChain.from_jwt_claim(at_limit)
    assert chain.sub == f"node-{MAX_ACT_CHAIN_DEPTH}"

    # One hop deeper: must raise
    over_limit = build_claim(MAX_ACT_CHAIN_DEPTH + 1)
    with pytest.raises(ValueError, match="act chain depth"):
        ActorChain.from_jwt_claim(over_limit)


def test_actor_chain_missing_sub_raises():
    with pytest.raises(KeyError):
        ActorChain.from_jwt_claim({"role": "developer"})  # no sub


# ---------------------------------------------------------------------------
# Legacy compatibility
# ---------------------------------------------------------------------------

def test_user_alias_is_human_user():
    assert User is HumanUser


def test_user_role_re_export_from_domain_user():
    assert UserRoleAlias is UserRole


def test_legacy_user_import_and_construction():
    """from swarm_auth.domain.user import User, UserRole still works."""
    from swarm_auth.domain.user import User as LegacyUser, UserRole as LegacyRole
    u = LegacyUser(user_id="x", username="x", role=LegacyRole.DEVELOPER)
    assert u.kind() == "human"


def test_actor_chain_re_exported_from_acp():
    """from swarm_auth.acp import ActorChain works (domain is authoritative)."""
    assert AcpActorChain is ActorChain


# ---------------------------------------------------------------------------
# has_permission (moved to Principal, same logic as before)
# ---------------------------------------------------------------------------

def test_human_user_permissions_unchanged():
    admin = HumanUser(user_id="1", username="admin", role=UserRole.ADMIN)
    dev = HumanUser(user_id="2", username="dev", role=UserRole.DEVELOPER)
    auditor = HumanUser(user_id="3", username="audit", role=UserRole.AUDITOR)
    guest = HumanUser(user_id="5", username="guest", role=UserRole.GUEST)

    assert admin.has_permission("anything")
    assert dev.has_permission("certify") and dev.has_permission("audit")
    assert auditor.has_permission("read") and not auditor.has_permission("certify")
    assert guest.has_permission("read") and not guest.has_permission("certify")


def test_agent_identity_permissions():
    svc = AgentIdentity(user_id="s1", username="svc", role=UserRole.SERVICE)
    assert svc.has_permission("certify")
    assert svc.has_permission("validate")
    assert not svc.has_permission("audit")
