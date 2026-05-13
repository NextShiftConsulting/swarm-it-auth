"""
Stage 0 xfail: RFC 8693 token exchange compatibility.

This test is expected to fail until Stage 5 (RFC8693TokenExchange adapter)
is implemented. It defines the contract for SD-2 (OAuth 2.1 + RFC 8693).

Contract (ADR-028 SD-2):
- authlib OAuth2Session.exchange_token() completes an RFC 8693 token exchange
  against a test authorization server without requiring custom protocol shims.
- The resulting token carries an `act` claim identifying the acting agent.
- The `subject_token_type` is `urn:ietf:params:oauth:token-type:access_token`.
- The `requested_token_type` is `urn:ietf:params:oauth:token-type:access_token`.

When this test passes unexpectedly (xpass), it means the implementation
landed outside the plan — treat as a build break and investigate.
"""

import pytest


@pytest.mark.xfail(
    reason=(
        "RFC8693TokenExchange adapter not yet implemented — Stage 0 placeholder. "
        "Implement in Stage 5 per ADR-027-implementation-plan.md."
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
    from swarm_auth.acp.adapters.rfc8693_token_exchange import RFC8693TokenExchange  # noqa: F401

    # Fixture: a local test authorization server that speaks RFC 8693
    # This fixture does not exist yet — it will be added in Stage 5.
    raise NotImplementedError("RFC8693TokenExchange adapter not implemented (Stage 5)")


@pytest.mark.xfail(
    reason=(
        "ActorChain not yet implemented — Stage 0 placeholder. "
        "Implement in Stage 1 per ADR-027-implementation-plan.md."
    ),
    strict=True,
)
def test_rfc8693_act_chain_preserved_across_exchange() -> None:
    """
    An existing `act` chain in the subject token is preserved after exchange.

    Success criteria:
    1. Input token has act.act.sub (two-hop delegation: human -> orchestrator -> tool)
    2. After RFC 8693 exchange, the output token retains the full act chain
    3. ActorChain.from_jwt() reconstructs the chain without data loss

    Contract reference: ADR-028 SD-2, ADR-027 SD-4 (flat delegation fix)
    """
    from swarm_auth.acp.domain.actor_chain import ActorChain  # noqa: F401

    raise NotImplementedError("ActorChain not implemented (Stage 1)")
