"""
Unit tests for RFC8693TokenExchangeAdapter (ADR-027 Stage 6).

Tests cover:
  - Delegation exchange (human subject + orchestrator actor → act claim)
  - Missing/invalid subject_token → error response
  - actor_token not AgentIdentity → error response
  - actor_token not ORCHESTRATOR → error response
  - Chain depth limit enforcement
  - No actor_token (subject-only exchange)
  - Introspect: valid, expired, wrong issuer
  - Issued token has correct RFC 8693 act claim structure
  - ADR-026: no ProviderCredential produced directly by the exchange adapter
"""

import time
from typing import Any, Dict, Optional

import pytest
import jwt as pyjwt

from swarm_auth.adapters.rfc8693_token_exchange import RFC8693TokenExchangeAdapter
from swarm_auth.ports.token_exchange_port import (
    DelegationType,
    TokenExchangeRequest,
    TokenType,
)
# DelegationType imported above — used in blocker-fix tests

_SIGNING_KEY = "test-exchange-signing-key-32-bytes!!"
_ALGORITHM = "HS256"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _human_token(sub="u1", signing_key=_SIGNING_KEY, exp_offset=3600) -> str:
    payload = {
        "sub": sub,
        "principal_kind": "human",
        "iat": int(time.time()),
        "exp": int(time.time()) + exp_offset,
    }
    return pyjwt.encode(payload, signing_key, algorithm=_ALGORITHM)


def _agent_token(
    sub="orch-001",
    agent_type="orchestrator",
    signing_key=_SIGNING_KEY,
    exp_offset=3600,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    payload = {
        "sub": sub,
        "principal_kind": "agent",
        "agent_type": agent_type,
        "iat": int(time.time()),
        "exp": int(time.time()) + exp_offset,
    }
    if extra:
        payload.update(extra)
    return pyjwt.encode(payload, signing_key, algorithm=_ALGORITHM)


def _basic_request(
    subject_token=None,
    actor_token=None,
    scope=None,
) -> TokenExchangeRequest:
    return TokenExchangeRequest(
        subject_token=subject_token or _human_token(),
        subject_token_type=TokenType.ACCESS_TOKEN,
        requested_token_type=TokenType.ACCESS_TOKEN,
        actor_token=actor_token or _agent_token(),
        actor_token_type=TokenType.ACCESS_TOKEN,
        scope=scope or ["aws.s3.get"],
    )


@pytest.fixture
def exchanger():
    return RFC8693TokenExchangeAdapter(signing_key=_SIGNING_KEY)


# ---------------------------------------------------------------------------
# Happy path: delegation exchange
# ---------------------------------------------------------------------------

def test_exchange_returns_access_token(exchanger):
    response = exchanger.exchange(_basic_request())
    assert response.access_token is not None
    assert response.error is None


def test_exchange_issued_token_has_act_claim(exchanger):
    response = exchanger.exchange(_basic_request())
    claims = pyjwt.decode(
        response.access_token, _SIGNING_KEY,
        algorithms=[_ALGORITHM], options={"verify_aud": False}
    )
    assert "act" in claims
    assert claims["act"]["sub"] == "orch-001"


def test_exchange_issued_token_sub_is_subject(exchanger):
    response = exchanger.exchange(_basic_request(subject_token=_human_token(sub="alice")))
    claims = pyjwt.decode(
        response.access_token, _SIGNING_KEY,
        algorithms=[_ALGORITHM], options={"verify_aud": False}
    )
    assert claims["sub"] == "alice"


def test_exchange_response_has_correct_issued_token_type(exchanger):
    response = exchanger.exchange(_basic_request())
    assert response.issued_token_type == TokenType.ACCESS_TOKEN


def test_exchange_response_has_scope(exchanger):
    response = exchanger.exchange(_basic_request(scope=["aws.s3.get", "aws.s3.put"]))
    assert response.scope == "aws.s3.get aws.s3.put"


def test_exchange_act_claim_in_response_metadata(exchanger):
    response = exchanger.exchange(_basic_request())
    assert response.act_claim is not None
    assert response.act_claim["sub"] == "orch-001"


# ---------------------------------------------------------------------------
# Blocker 2 fix: DELEGATION requires actor_token
# ---------------------------------------------------------------------------

def test_delegation_exchange_requires_actor_token(exchanger):
    """
    Blocker 2 fix: DELEGATION without actor_token is rejected.
    RFC 8693 §4.1: act claim requires an actor; omitting actor_token
    for DELEGATION is a contract violation.
    """
    request = TokenExchangeRequest(
        subject_token=_human_token(),
        subject_token_type=TokenType.ACCESS_TOKEN,
        requested_token_type=TokenType.ACCESS_TOKEN,
        delegation_type=DelegationType.DELEGATION,
        # actor_token intentionally omitted
    )
    response = exchanger.exchange(request)
    assert response.access_token is None
    assert response.error == "invalid_request"
    assert "actor_token" in response.error_description.lower()


def test_delegation_exchange_requires_actor_token_type(exchanger):
    """actor_token_type must be provided when actor_token is present."""
    request = TokenExchangeRequest(
        subject_token=_human_token(),
        subject_token_type=TokenType.ACCESS_TOKEN,
        requested_token_type=TokenType.ACCESS_TOKEN,
        actor_token=_agent_token(),
        # actor_token_type intentionally omitted
    )
    response = exchanger.exchange(request)
    assert response.access_token is None
    assert response.error == "invalid_request"
    assert "actor_token_type" in response.error_description.lower()


# ---------------------------------------------------------------------------
# Blocker 3 fix: fail closed on dpop_jkt and resource until Stage 7
# ---------------------------------------------------------------------------

def test_exchange_rejects_dpop_jkt_until_bound(exchanger):
    """dpop_jkt is rejected until Stage 7 wires DPoPValidatorPort."""
    request = TokenExchangeRequest(
        subject_token=_human_token(),
        subject_token_type=TokenType.ACCESS_TOKEN,
        requested_token_type=TokenType.ACCESS_TOKEN,
        actor_token=_agent_token(),
        actor_token_type=TokenType.ACCESS_TOKEN,
        dpop_jkt="some-jwk-thumbprint",
    )
    response = exchanger.exchange(request)
    assert response.access_token is None
    assert response.error == "invalid_request"
    assert "dpop_jkt" in response.error_description.lower()


def test_exchange_rejects_resource_until_scope_validation_wired(exchanger):
    """resource indicator is rejected until Stage 7 wires ScopePolicyAdapter."""
    request = TokenExchangeRequest(
        subject_token=_human_token(),
        subject_token_type=TokenType.ACCESS_TOKEN,
        requested_token_type=TokenType.ACCESS_TOKEN,
        actor_token=_agent_token(),
        actor_token_type=TokenType.ACCESS_TOKEN,
        resource="arn:aws:s3:::swarm-data/",
    )
    response = exchanger.exchange(request)
    assert response.access_token is None
    assert response.error == "invalid_request"
    assert "resource" in response.error_description.lower()


# ---------------------------------------------------------------------------
# Impersonation exchange (actor_token optional)
# ---------------------------------------------------------------------------

def test_exchange_impersonation_no_actor_token_allowed(exchanger):
    """Impersonation exchange does not require actor_token (RFC 8693 §1.1)."""
    request = TokenExchangeRequest(
        subject_token=_human_token(),
        subject_token_type=TokenType.ACCESS_TOKEN,
        requested_token_type=TokenType.ACCESS_TOKEN,
        delegation_type=DelegationType.IMPERSONATION,
    )
    response = exchanger.exchange(request)
    assert response.access_token is not None
    claims = pyjwt.decode(
        response.access_token, _SIGNING_KEY,
        algorithms=[_ALGORITHM], options={"verify_aud": False}
    )
    assert "act" not in claims


# ---------------------------------------------------------------------------
# Denied: invalid subject token
# ---------------------------------------------------------------------------

def test_exchange_invalid_subject_token_returns_error(exchanger):
    request = _basic_request(subject_token="not.a.valid.jwt")
    response = exchanger.exchange(request)
    assert response.access_token is None
    assert response.error == "invalid_request"
    assert "subject_token" in response.error_description.lower()


def test_exchange_expired_subject_token_returns_error(exchanger):
    expired = _human_token(exp_offset=-10)
    response = exchanger.exchange(_basic_request(subject_token=expired))
    assert response.error == "invalid_request"


# ---------------------------------------------------------------------------
# Denied: actor is not AgentIdentity
# ---------------------------------------------------------------------------

def test_exchange_actor_not_agent_returns_error(exchanger):
    # principal_kind = "human" — not an agent
    human_actor = _human_token(sub="rudy")
    response = exchanger.exchange(_basic_request(actor_token=human_actor))
    assert response.error == "invalid_request"
    assert "principal_kind" in response.error_description.lower()


# ---------------------------------------------------------------------------
# Denied: actor is not ORCHESTRATOR
# ---------------------------------------------------------------------------

def test_exchange_actor_not_orchestrator_returns_error(exchanger):
    tool_actor = _agent_token(agent_type="tool")
    response = exchanger.exchange(_basic_request(actor_token=tool_actor))
    assert response.error == "invalid_request"
    assert "ORCHESTRATOR" in response.error_description


# ---------------------------------------------------------------------------
# Chain depth limit (RFC 8693 §8)
# ---------------------------------------------------------------------------

def test_exchange_chain_depth_at_limit_denied(exchanger):
    """An actor token that already has max_chain_depth act hops is rejected."""
    # Build deeply nested act claim
    deep_act: Dict[str, Any] = {"sub": "orch-0"}
    for i in range(1, 10):
        deep_act = {"sub": f"orch-{i}", "act": deep_act}

    actor_with_deep_chain = _agent_token(extra={"act": deep_act})
    request = TokenExchangeRequest(
        subject_token=_human_token(),
        subject_token_type=TokenType.ACCESS_TOKEN,
        requested_token_type=TokenType.ACCESS_TOKEN,
        actor_token=actor_with_deep_chain,
        actor_token_type=TokenType.ACCESS_TOKEN,
        max_chain_depth=10,
    )
    response = exchanger.exchange(request)
    assert response.error == "invalid_request"
    assert "max_chain_depth" in response.error_description.lower()


def test_exchange_chain_depth_under_limit_allowed(exchanger):
    """Actor with shallow chain (depth < max_chain_depth) is accepted."""
    actor_with_one_hop = _agent_token(extra={"act": {"sub": "orch-parent"}})
    request = _basic_request(actor_token=actor_with_one_hop)
    response = exchanger.exchange(request)
    assert response.error is None
    assert response.access_token is not None


# ---------------------------------------------------------------------------
# Introspect
# ---------------------------------------------------------------------------

def test_introspect_valid_token_returns_active(exchanger):
    response = exchanger.exchange(_basic_request())
    info = exchanger.introspect(response.access_token)
    assert info["active"] is True
    assert info["sub"] == "u1"


def test_introspect_expired_token_returns_inactive(exchanger):
    # Issue a token with short TTL
    short_exchanger = RFC8693TokenExchangeAdapter(signing_key=_SIGNING_KEY, token_ttl=1)
    response = short_exchanger.exchange(_basic_request())
    # Manually tamper with exp by re-encoding with past exp
    claims = pyjwt.decode(
        response.access_token, _SIGNING_KEY,
        algorithms=[_ALGORITHM], options={"verify_aud": False, "verify_exp": False}
    )
    claims["exp"] = int(time.time()) - 10
    expired_token = pyjwt.encode(claims, _SIGNING_KEY, algorithm=_ALGORITHM)
    info = exchanger.introspect(expired_token)
    assert info["active"] is False


def test_introspect_wrong_issuer_returns_inactive(exchanger):
    # Token issued by a different exchanger (different secret)
    other = RFC8693TokenExchangeAdapter("other-exchanger-signing-key-32-bytes!!")
    other_response = other.exchange(_basic_request())
    info = exchanger.introspect(other_response.access_token)
    assert info["active"] is False


def test_introspect_garbage_returns_inactive(exchanger):
    assert exchanger.introspect("not.a.token")["active"] is False


# ---------------------------------------------------------------------------
# ADR-026 guardrail: no ProviderCredential produced by the exchange adapter
# ---------------------------------------------------------------------------

def test_exchange_does_not_produce_provider_credential(exchanger):
    """
    ADR-026 Rule 6 / ADR-027 invariant:
    RFC8693TokenExchangeAdapter must not produce ProviderCredential directly.
    It issues delegation JWTs; the CredentialBrokerPort is NOT called here.
    Provider credentials are vended by the broker when the delegation token
    is presented (Stage 7 ACPOrchestrator).
    """
    from swarm_auth.ports.credential_broker_port import ProviderCredential

    response = exchanger.exchange(_basic_request())

    # The response is a TokenExchangeResponse, not a ProviderCredential
    assert not isinstance(response, ProviderCredential)
    # access_token is a JWT string, not provider-specific credential material
    assert isinstance(response.access_token, str)
    # Decoding reveals it is a delegation token, not an STS token
    claims = pyjwt.decode(
        response.access_token, _SIGNING_KEY,
        algorithms=[_ALGORITHM], options={"verify_aud": False}
    )
    assert claims.get("token_type") == "delegation"
