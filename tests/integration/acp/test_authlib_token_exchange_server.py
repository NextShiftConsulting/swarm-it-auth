"""
Stage 8.4: Authlib RFC 8693 token exchange integration test.

ADR-027 Stage 0 acceptance criterion (SD-2):
  A real third-party OAuth 2.1 client (authlib) completes a token exchange
  against the broker without custom shims.

Converts: test_rfc8693_token_exchange_carries_act_claim (issue #2)

Server: tests/integration/acp/token_exchange_server.py (FastAPI on real TCP port)
Client: authlib OAuth2Session.fetch_token() — standard RFC 8693 grant type
"""

import jwt as pyjwt
import pytest

from tests.integration.acp.token_exchange_server import (
    RFC8693_GRANT_TYPE,
    ACCESS_TOKEN_TYPE,
    TOKEN_EXCHANGE_SECRET,
    TOKEN_EXCHANGE_ISSUER,
)

_ALG = "HS256"


# ---------------------------------------------------------------------------
# Accept test (issue #2)
# ---------------------------------------------------------------------------

def test_rfc8693_token_exchange_carries_act_claim(
    token_exchange_server_url, human_subject_token, agent_actor_token
):
    """
    authlib completes RFC 8693 token exchange; response carries act chain.

    DoD (issue #2):
    1. fetch_token() uses grant_type=urn:ietf:params:oauth:grant-type:token-exchange
    2. No custom protocol shims — authlib OAuth2Session is the client as-is
    3. Response token contains "act" claim with sub == "orch-001"
    4. Issued token is a valid HS256 JWT (round-trip decode succeeds)
    """
    from authlib.integrations.requests_client import OAuth2Session

    client = OAuth2Session(client_id="test-orchestrator", client_secret="")
    token_url = f"{token_exchange_server_url}/token"

    response = client.fetch_token(
        url=token_url,
        grant_type=RFC8693_GRANT_TYPE,
        subject_token=human_subject_token,
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token=agent_actor_token,
        actor_token_type=ACCESS_TOKEN_TYPE,
    )

    # authlib populates response["access_token"]
    assert "access_token" in response, f"no access_token in response: {dict(response)}"
    assert response.get("token_type", "").lower() == "bearer"

    # Decode and verify act claim (RFC 8693 §4.1)
    claims = pyjwt.decode(
        response["access_token"],
        TOKEN_EXCHANGE_SECRET,
        algorithms=[_ALG],
        options={"verify_aud": False},
        issuer=TOKEN_EXCHANGE_ISSUER,
    )
    assert "act" in claims, f"act claim missing from issued token; claims={claims}"
    assert claims["act"]["sub"] == "orch-001", (
        f"act.sub should be the actor agent, got {claims['act']['sub']!r}"
    )
    assert claims["sub"] == "alice", f"sub should be the human subject, got {claims['sub']!r}"


# ---------------------------------------------------------------------------
# Undelegated exchange (no actor_token — baseline)
# ---------------------------------------------------------------------------

def test_rfc8693_undelegated_exchange_succeeds(
    token_exchange_server_url, human_subject_token
):
    """
    Token exchange without actor_token succeeds and produces no act claim.

    This is the baseline: a simple subject-token refresh without delegation.
    """
    from authlib.integrations.requests_client import OAuth2Session

    client = OAuth2Session(client_id="test-client", client_secret="")
    response = client.fetch_token(
        url=f"{token_exchange_server_url}/token",
        grant_type=RFC8693_GRANT_TYPE,
        subject_token=human_subject_token,
        subject_token_type=ACCESS_TOKEN_TYPE,
    )

    assert "access_token" in response
    claims = pyjwt.decode(
        response["access_token"],
        TOKEN_EXCHANGE_SECRET,
        algorithms=[_ALG],
        options={"verify_aud": False},
    )
    assert claims["sub"] == "alice"
    assert "act" not in claims, "undelegated exchange must not produce act claim"


# ---------------------------------------------------------------------------
# Nested act chain survives exchange
# ---------------------------------------------------------------------------

def test_rfc8693_nested_act_chain_preserved(
    token_exchange_server_url, human_subject_token
):
    """
    Pre-existing act chain in actor_token is preserved after exchange.

    Scenario: orch-A delegated to orch-B (actor_token.act.sub == "orch-A").
    After exchange with subject "alice", the output token must carry:
      act.sub == "orch-B"   (immediate actor)
      act.act.sub == "orch-A"  (prior delegator preserved — RFC 8693 §4.1)
    """
    import time
    now = int(time.time())

    # actor_token: orch-B which was itself delegated-to by orch-A
    actor_with_chain = pyjwt.encode(
        {
            "sub": "orch-B",
            "iss": TOKEN_EXCHANGE_ISSUER,
            "principal_kind": "agent",
            "agent_type": "orchestrator",
            "iat": now,
            "exp": now + 3600,
            "act": {"sub": "orch-A"},
        },
        TOKEN_EXCHANGE_SECRET,
        algorithm=_ALG,
    )

    from authlib.integrations.requests_client import OAuth2Session

    client = OAuth2Session(client_id="test-orchestrator", client_secret="")
    response = client.fetch_token(
        url=f"{token_exchange_server_url}/token",
        grant_type=RFC8693_GRANT_TYPE,
        subject_token=human_subject_token,
        subject_token_type=ACCESS_TOKEN_TYPE,
        actor_token=actor_with_chain,
        actor_token_type=ACCESS_TOKEN_TYPE,
    )

    claims = pyjwt.decode(
        response["access_token"],
        TOKEN_EXCHANGE_SECRET,
        algorithms=[_ALG],
        options={"verify_aud": False},
    )
    assert claims["act"]["sub"] == "orch-B"
    assert "act" in claims["act"], "prior delegation hop (orch-A) was lost"
    assert claims["act"]["act"]["sub"] == "orch-A"
