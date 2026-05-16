"""
Stage 8.4: RFC 8693 token exchange compatibility — CONVERTED from xfail.

Stage 7 status:
  - test_rfc8693_token_exchange_carries_act_claim: stays xfail (authlib not installed)
  - test_rfc8693_act_chain_preserved_across_exchange: CONVERTED — Stage 7

Stage 8.4 status:
  - test_rfc8693_token_exchange_carries_act_claim: CONVERTED — authlib installed,
    in-process uvicorn server wired (issue #2)

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


def test_rfc8693_token_exchange_carries_act_claim() -> None:
    """
    authlib completes RFC 8693 token exchange; response carries act chain.

    Delegates to the full integration test in
    tests/integration/acp/test_authlib_token_exchange_server.py which uses:
      - authlib OAuth2Session.fetch_token() — no custom shims
      - In-process uvicorn server backed by RFC8693TokenExchangeAdapter
      - Real TCP (127.0.0.1:19693) so authlib's requests transport is unmodified

    Success criteria (ADR-028 SD-2, issue #2):
    1. grant_type = urn:ietf:params:oauth:grant-type:token-exchange
    2. Response token contains "act" claim with sub == actor identity
    3. No custom protocol shims beyond authlib OAuth2Session
    """
    from authlib.integrations.requests_client import OAuth2Session
    from tests.integration.acp.helpers import UvicornThread, find_free_port, mint_exchange_token
    from tests.integration.acp.token_exchange_server import (
        RFC8693_GRANT_TYPE, ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_SECRET,
        TOKEN_EXCHANGE_ISSUER, app as exchange_app,
    )

    # Start the real TCP server on an OS-assigned ephemeral port
    host = "127.0.0.1"
    port = find_free_port(host)
    thread = UvicornThread(exchange_app, host, port)
    thread.start()
    thread.wait_ready()

    try:
        subject_token = mint_exchange_token(
            "alice", "human", secret=TOKEN_EXCHANGE_SECRET, issuer=TOKEN_EXCHANGE_ISSUER,
        )
        actor_token = mint_exchange_token(
            "orch-001", "agent", agent_type="orchestrator",
            secret=TOKEN_EXCHANGE_SECRET, issuer=TOKEN_EXCHANGE_ISSUER,
        )

        client = OAuth2Session(client_id="compat-test", client_secret="")
        response = client.fetch_token(
            url=f"http://{host}:{port}/token",
            grant_type=RFC8693_GRANT_TYPE,
            subject_token=subject_token,
            subject_token_type=ACCESS_TOKEN_TYPE,
            actor_token=actor_token,
            actor_token_type=ACCESS_TOKEN_TYPE,
        )

        assert "access_token" in response
        claims = pyjwt.decode(
            response["access_token"], TOKEN_EXCHANGE_SECRET,
            algorithms=["HS256"], options={"verify_aud": False},
            issuer=TOKEN_EXCHANGE_ISSUER,
        )
        assert "act" in claims, f"act claim missing; claims={claims}"
        assert claims["act"]["sub"] == "orch-001"
        assert claims["sub"] == "alice"
    finally:
        thread.stop()


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
