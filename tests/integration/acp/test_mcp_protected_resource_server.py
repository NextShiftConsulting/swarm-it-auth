"""
Stage 8.4: MCP protected-resource integration tests.

ADR-027 Stage 0 acceptance criterion (SD-5):
  A real MCP server validates a token issued by the broker, including audience
  and resource indicator checks per RFC 8707.

Converts:
  - test_mcp_server_accepts_acp_token_with_resource_indicator (issue #3)
  - test_mcp_server_rejects_token_without_resource_indicator (issue #4)

Both xfails in tests/acp/test_mcp_compat.py are closed by this file.

Server: tests/integration/acp/mcp_test_server.py (FastAPI + starlette TestClient)
Fixtures: tests/integration/acp/conftest.py
"""

from tests.integration.acp.mcp_test_server import MCP_RESOURCE_URI


# ---------------------------------------------------------------------------
# Protected-resource metadata
# ---------------------------------------------------------------------------


def test_well_known_metadata_returns_resource_uri(client):
    """/.well-known/oauth-protected-resource returns expected resource metadata."""
    r = client.get("/.well-known/oauth-protected-resource")
    assert r.status_code == 200
    body = r.json()
    assert body["resource"] == MCP_RESOURCE_URI
    assert "authorization_servers" in body


# ---------------------------------------------------------------------------
# Accept test (issue #3)
# ---------------------------------------------------------------------------


def test_mcp_server_accepts_acp_token_with_resource_indicator(
    client, acp_token_with_resource
):
    """
    MCP server accepts a valid ACP token that carries the correct RFC 8707
    resource indicator and matching audience claim.

    DoD (issue #3):
    - GET /mcp with Authorization: Bearer <token> returns 200
    - Response body contains {"ok": true}
    """
    r = client.get("/mcp", headers={"Authorization": f"Bearer {acp_token_with_resource}"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


# ---------------------------------------------------------------------------
# Reject tests (issue #4)
# ---------------------------------------------------------------------------


def test_mcp_server_rejects_token_without_resource_indicator(
    client, acp_token_without_resource
):
    """
    MCP server rejects a token that lacks the RFC 8707 resource indicator.

    DoD (issue #4):
    - GET /mcp returns 401
    - WWW-Authenticate header present
    - error="invalid_token", error_description contains "resource indicator"
    """
    r = client.get("/mcp", headers={"Authorization": f"Bearer {acp_token_without_resource}"})
    assert r.status_code == 401
    assert "WWW-Authenticate" in r.headers
    www_auth = r.headers["WWW-Authenticate"]
    assert 'error="invalid_token"' in www_auth
    assert "resource indicator" in www_auth


def test_mcp_server_rejects_token_with_wrong_resource(client, acp_token_wrong_resource):
    """Token issued for a different resource URI is rejected."""
    r = client.get("/mcp", headers={"Authorization": f"Bearer {acp_token_wrong_resource}"})
    assert r.status_code == 401
    assert 'error="invalid_token"' in r.headers["WWW-Authenticate"]


def test_mcp_server_rejects_expired_token(client, acp_token_expired):
    """Expired token is rejected regardless of valid resource indicator."""
    r = client.get("/mcp", headers={"Authorization": f"Bearer {acp_token_expired}"})
    assert r.status_code == 401
    assert "expired" in r.headers["WWW-Authenticate"]


def test_mcp_server_rejects_missing_authorization_header(client):
    """Request with no Authorization header is rejected."""
    r = client.get("/mcp")
    assert r.status_code == 401


def test_mcp_server_rejects_malformed_token(client):
    """Malformed (non-JWT) bearer token is rejected."""
    r = client.get("/mcp", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401
