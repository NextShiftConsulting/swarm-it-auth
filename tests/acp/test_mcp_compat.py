"""
Stage 8.4: MCP server token compatibility — CONVERTED from xfail.

Both tests now pass via the in-process MCP test double in
tests/integration/acp/mcp_test_server.py (FastAPI + starlette TestClient).

Contract (ADR-028 SD-5, issues #3 and #4):
- ACP-issued token with RFC 8707 resource indicator is accepted (200).
- ACP token without resource indicator is rejected (401 + WWW-Authenticate).

Stage 8 status:
  - test_mcp_server_accepts_acp_token_with_resource_indicator: CONVERTED — Stage 8.4
  - test_mcp_server_rejects_token_without_resource_indicator:  CONVERTED — Stage 8.4
"""

import time
import jwt as pyjwt
import pytest
from starlette.testclient import TestClient

from tests.integration.acp.mcp_test_server import (
    ALG,
    ISSUER,
    MCP_RESOURCE_URI,
    SECRET,
    app,
)


def _mint(resource=MCP_RESOURCE_URI, aud=MCP_RESOURCE_URI, ttl=3600):
    now = int(time.time())
    payload = {"sub": "alice", "iss": ISSUER, "iat": now, "exp": now + ttl, "principal_kind": "human"}
    if resource is not None:
        payload["resource"] = resource
    if aud is not None:
        payload["aud"] = aud
    return pyjwt.encode(payload, SECRET, algorithm=ALG)


@pytest.fixture
def mcp_client():
    return TestClient(app, raise_server_exceptions=True)


def test_mcp_server_accepts_acp_token_with_resource_indicator(mcp_client) -> None:
    """
    MCP server accepts ACP-issued token with correct RFC 8707 resource indicator.

    Success criteria (ADR-028 SD-3, SD-5):
    1. Token carries resource=MCP_RESOURCE_URI and aud=MCP_RESOURCE_URI
    2. Presented in Authorization: Bearer <token>
    3. MCP server returns 200 {"ok": true}
    """
    token = _mint()
    r = mcp_client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_mcp_server_rejects_token_without_resource_indicator(mcp_client) -> None:
    """
    MCP server rejects ACP token that lacks the resource indicator.

    Success criteria (ADR-028 SD-3):
    1. Token has no resource or aud claim
    2. MCP server returns 401
    3. WWW-Authenticate: Bearer error="invalid_token" error_description="resource indicator required"
    """
    token = _mint(resource=None, aud=None)
    r = mcp_client.get("/mcp", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert "WWW-Authenticate" in r.headers
    www_auth = r.headers["WWW-Authenticate"]
    assert 'error="invalid_token"' in www_auth
    assert "resource indicator" in www_auth
