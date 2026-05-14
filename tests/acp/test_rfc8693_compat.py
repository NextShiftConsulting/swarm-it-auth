"""
Stage 0 xfail: RFC 8693 token exchange compatibility.

Stage 7 status:
  - test_rfc8693_token_exchange_carries_act_claim: stays xfail (authlib not installed)
  - test_rfc8693_act_chain_preserved_across_exchange: CONVERTED — Stage 7

Contract (ADR-028 SD-2):
- RFC8693TokenExchangeAdapter preserves an existing act chain from the actor_token
  in the issued delegation token, matching RFC 8693 §4.1 semantics.
- ActorChain.from_jwt_claim() reconstructs the chain without data loss.
"""

import time

import jwt as pyjwt
import pytest

from swarm_auth.adapters.rfc8693_token_exchange import RFC8693TokenExchangeAdapter
from swarm_auth.domain.agent_identity import ActorChain
from swarm_auth.ports.token_exchange_port import (
    DelegationType,
    TokenExchangeRequest,
    TokenType,
)

_KEY = "test-exchange-preserve-chain-key!!"
_ALG = "HS256"


@pytest.mark.xfail(
    reason=(
        "authlib not installed — integration with authlib OAuth2Session "
        "is out of scope until a real authorization server is wired. "
        "RFC8693TokenExchangeAdapter provides the implementation; "
        "this test covers the authlib integration layer only."
    ),
    strict=True,
)
def test_rfc8693_token_exchange_carries_act_claim() -> None:
    """
    authlib completes RFC 8693 token exchange without custom shims.

    Success criteria:
    1. Token exchange request uses grant_type=urn:ietf:params:oauth:grant-type:token-exchange
    2. Response token decodes to a JWT with an `act` claim
    3. `act.sub` identifies the acting agent (AgentIdentity.agent_id)
    4. No custom protocol shims needed beyond authlib OAuth2Session
    """
    from authlib.integrations.requests_client import OAuth2Session  # noqa: F401

    # Fixture: a local test authorization server that speaks RFC 8693
    raise NotImplementedError("authlib OAuth2Session integration not wired (no test server)")


def test_rfc8693_act_chain_preserved_across_exchange() -> None:
    """
    An existing act chain in the actor_token is preserved after RFC 8693 exchange.

    Scenario: orch-A delegated to orch-B (actor_token has act.sub = "orch-A").
    After exchange with subject "alice", the output token must carry the full
    three-node chain: alice → orch-B → orch-A.

    Success criteria:
    1. Output token act.sub == "orch-B" (immediate actor)
    2. Output token act.act.sub == "orch-A" (prior delegator preserved)
    3. ActorChain.from_jwt_claim() reconstructs the chain without data loss
    4. chain.sub == "orch-B", chain.act.sub == "orch-A"

    Contract reference: ADR-028 SD-2, ADR-027 Gap 4 (flat delegation fix)
    """
    now = int(time.time())

    # subject_token: human user "alice"
    subject_token = pyjwt.encode(
        {"sub": "alice", "principal_kind": "human", "iat": now, "exp": now + 3600},
        _KEY, algorithm=_ALG,
    )

    # actor_token: orch-B, which was itself delegated-to by orch-A
    # (two-hop chain already in the actor token: orch-A → orch-B)
    actor_token = pyjwt.encode(
        {
            "sub": "orch-B",
            "principal_kind": "agent",
            "agent_type": "orchestrator",
            "iat": now,
            "exp": now + 3600,
            "act": {"sub": "orch-A"},   # orch-A delegated to orch-B
        },
        _KEY, algorithm=_ALG,
    )

    exchanger = RFC8693TokenExchangeAdapter(signing_key=_KEY)
    response = exchanger.exchange(TokenExchangeRequest(
        subject_token=subject_token,
        subject_token_type=TokenType.ACCESS_TOKEN,
        requested_token_type=TokenType.ACCESS_TOKEN,
        actor_token=actor_token,
        actor_token_type=TokenType.ACCESS_TOKEN,
        delegation_type=DelegationType.DELEGATION,
    ))

    assert response.error is None, response.error_description
    assert response.access_token is not None

    claims = pyjwt.decode(
        response.access_token, _KEY,
        algorithms=[_ALG], options={"verify_aud": False},
    )

    # Full chain preserved: alice delegates to orch-B which was delegated by orch-A
    assert "act" in claims, "act claim missing from issued delegation token"
    assert claims["act"]["sub"] == "orch-B"
    assert "act" in claims["act"], "prior delegation hop (orch-A) lost after exchange"
    assert claims["act"]["act"]["sub"] == "orch-A"

    # ActorChain domain type reconstructs without data loss
    chain = ActorChain.from_jwt_claim(claims["act"])
    assert chain.sub == "orch-B"
    assert chain.act is not None
    assert chain.act.sub == "orch-A"
    assert chain.act.act is None  # two-hop chain — leaf reached
