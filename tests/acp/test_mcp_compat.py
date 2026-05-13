"""
Stage 0 xfail: MCP server token compatibility.

This test is expected to fail until Stage 7 (MCP integration) is implemented.
It defines the contract for SD-5 (MCP auth spec 2025-06-18).

Contract (ADR-028 SD-5):
- An ACP-issued token is accepted by an MCP server's Authorization header.
- The token includes an RFC 8707 resource indicator matching the MCP server's
  resource URI (e.g., https://mcp.swarms.network/discovery).
- The MCP server validates the resource indicator and rejects tokens without it.
- Token type in Authorization header: Bearer <acp_token>

When this test passes unexpectedly (xpass), it means the implementation
landed outside the plan — treat as a build break and investigate.
"""

import pytest


@pytest.mark.xfail(
    reason=(
        "MCP auth integration not yet implemented — Stage 0 placeholder. "
        "Implement in Stage 7 per ADR-027-implementation-plan.md."
    ),
    strict=True,
)
def test_mcp_server_accepts_acp_token_with_resource_indicator() -> None:
    """
    MCP server validates ACP-issued token carrying RFC 8707 resource indicator.

    Success criteria:
    1. ACP issues a token with `resource=https://mcp.swarms.network/discovery`
       (RFC 8707 resource indicator, ADR-028 SD-3)
    2. Token is presented in Authorization: Bearer <token> header
    3. MCP server (test double) accepts the token and returns 200
    4. No protocol shims required beyond the MCP auth spec (2025-06-18)

    Contract reference: ADR-028 SD-3, SD-5
    """
    from swarm_auth.acp.adapters.scope_policy_adapter import ScopePolicyAdapter  # noqa: F401

    # Fixture: a local test MCP server that enforces RFC 8707 resource indicators
    # This fixture does not exist yet — it will be added in Stage 7.
    raise NotImplementedError("MCP auth integration not implemented (Stage 7)")


@pytest.mark.xfail(
    reason=(
        "ScopePolicyAdapter not yet implemented — Stage 0 placeholder. "
        "Implement in Stage 4 per ADR-027-implementation-plan.md."
    ),
    strict=True,
)
def test_mcp_server_rejects_token_without_resource_indicator() -> None:
    """
    MCP server rejects ACP token that lacks the required resource indicator.

    Success criteria:
    1. ACP issues a token WITHOUT a `resource` parameter
    2. MCP server (test double) rejects the token with 401
    3. Error response includes WWW-Authenticate: Bearer error="invalid_token"
       error_description="resource indicator required"

    Contract reference: ADR-028 SD-3 (RFC 8707 enforcement)
    """
    from swarm_auth.acp.adapters.scope_policy_adapter import ScopePolicyAdapter  # noqa: F401

    raise NotImplementedError("ScopePolicyAdapter not implemented (Stage 4)")
