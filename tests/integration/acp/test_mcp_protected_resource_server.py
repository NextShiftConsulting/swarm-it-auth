"""
Stage 8.4: MCP protected-resource integration tests — in-process MCP server.

ADR-027 Stage 0 acceptance criterion:
  A real MCP server validates a token issued by the broker, including audience
  and resource indicator checks per RFC 8707.

Tracks:
  - Accept test: https://github.com/NextShiftConsulting/swarm-it-auth/issues/3
  - Reject test: https://github.com/NextShiftConsulting/swarm-it-auth/issues/4

Converts:
  - test_mcp_server_accepts_acp_token_with_resource_indicator (xfail)
  - test_mcp_server_rejects_token_without_resource_indicator (xfail)
  Both in tests/acp/test_mcp_compat.py

Infrastructure required:
  - MCP Python SDK (pip install mcp) — official reference implementation
  - An in-process HTTP test server to host the MCP resource server

Design:
  1. Spin up an in-process MCP server configured as an OAuth Resource Server
     - Exposes GET /.well-known/oauth-protected-resource
     - Validates Bearer tokens: checks audience, resource indicator (RFC 8707)
  2. ACPOrchestrator issues a token with resource=<mcp_server_uri>
  3. Accept test: token with resource indicator → MCP server validates successfully
  4. Reject test: token without resource indicator → MCP server returns 401

Guardrails (ADR-027 Stage 8.4):
  - Test-only. No production MCP server.
  - No new credential broker logic, no new production wiring.
  - Scope: tests/integration/acp/ only.
  - Reject test shares server fixture with accept test (issue #4 depends on #3).
"""

import pytest

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

mcp = pytest.importorskip(
    "mcp",
    reason="mcp SDK not installed — pip install mcp to run Stage 8.4 tests",
)
pytest_httpserver = pytest.importorskip(
    "pytest_httpserver",
    reason="pytest-httpserver not installed — pip install pytest-httpserver to run Stage 8.4 tests",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# TODO (Stage 8.4): implement MCP resource server fixture
# Suggested approach:
#   @pytest.fixture
#   def mcp_resource_server(httpserver):
#       """In-process MCP server acting as an OAuth Resource Server (RFC 8707)."""
#       resource_uri = httpserver.url_for("/")
#       # Configure .well-known/oauth-protected-resource response
#       httpserver.expect_request("/.well-known/oauth-protected-resource").respond_with_json({
#           "resource": resource_uri,
#           "authorization_servers": [...],
#       })
#       # Configure token validation endpoint
#       ...
#       return httpserver


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="Stage 8.4: MCP server fixture not yet implemented — tracked in issue #3")
def test_mcp_server_accepts_acp_token_with_resource_indicator(mcp_resource_server) -> None:
    """
    MCP server accepts an ACP-issued token that includes a resource indicator (RFC 8707).

    DoD:
    - ACPOrchestrator issues token with resource=<mcp_server_uri>
    - MCP server validates the token — audience and resource indicator checks pass
    - No 401/403 response
    """
    resource_uri = mcp_resource_server.url_for("/")

    # TODO: issue token from ACPOrchestrator with resource=resource_uri
    # token = orchestrator.issue_token(principal=human_principal, resource=resource_uri)

    # TODO: present token to MCP server
    # result = mcp_resource_server.validate_token(token)
    # assert result.valid
    # assert result.audience_matched

    raise NotImplementedError("implement MCP server fixture — issue #3")


@pytest.mark.skip(reason="Stage 8.4: MCP server fixture not yet implemented — tracked in issue #4")
def test_mcp_server_rejects_token_without_resource_indicator(mcp_resource_server) -> None:
    """
    MCP server rejects an ACP-issued token that lacks a resource indicator (RFC 8707).

    DoD:
    - ACPOrchestrator issues token WITHOUT resource parameter
    - MCP server rejects the token — returns 401 or equivalent error
    - Confirms the MCP server enforces RFC 8707 — not just a permissive validator

    Depends on: issue #3 (shared server fixture)
    """
    # TODO: issue token from ACPOrchestrator WITHOUT resource parameter
    # token = orchestrator.issue_token(principal=human_principal)  # no resource

    # TODO: present token to MCP server
    # result = mcp_resource_server.validate_token(token)
    # assert not result.valid
    # assert result.error_code in ("invalid_token", "insufficient_scope")

    raise NotImplementedError("implement MCP server fixture — issue #4")
