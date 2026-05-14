"""
Minimal MCP protected-resource test double.

Implements just enough of the MCP 2025-06-18 authorization spec to convert
the Stage 8.4 xfails:
  - test_mcp_server_accepts_acp_token_with_resource_indicator (#3)
  - test_mcp_server_rejects_token_without_resource_indicator (#4)

Spec reference: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization

What this server implements:
  GET /.well-known/oauth-protected-resource
    Returns OAuth Protected Resource Metadata (RFC 8707 / MCP spec §Authorization).
    Required field: resource, authorization_servers.

  GET /mcp
    Protected endpoint. Validates Bearer JWT:
      - signature (HS256, shared test secret)
      - exp (not expired)
      - iss (must equal ISSUER)
      - resource claim (must equal MCP_RESOURCE_URI)
      - aud claim (must equal MCP_RESOURCE_URI)
    Returns 200 {"ok": true} on success.
    Returns 401 with WWW-Authenticate header on any failure.

What this server does NOT implement (out of scope for Stage 8.4):
  - Dynamic client registration
  - Authorization code flow
  - Token endpoint
  - Persistent state
  - Real MCP tool execution

Usage (via starlette TestClient — no real server started):
    from tests.integration.acp.mcp_test_server import app, MCP_RESOURCE_URI, ISSUER, SECRET
    from starlette.testclient import TestClient
    client = TestClient(app)
"""

from __future__ import annotations

import jwt as pyjwt
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

# ---------------------------------------------------------------------------
# Test constants (shared with conftest.py)
# ---------------------------------------------------------------------------

MCP_RESOURCE_URI = "https://mcp.swarms.network/discovery"
ISSUER = "swarm-it-auth"
SECRET = "mcp-test-secret-that-is-at-least-32-bytes!"
ALG = "HS256"

# WWW-Authenticate realm for 401 responses
_WWW_AUTH_BASE = f'Bearer realm="{MCP_RESOURCE_URI}"'

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="MCP Protected Resource Test Double")


def _unauthorized(error: str, description: str) -> Response:
    """Return 401 with a spec-compliant WWW-Authenticate header."""
    www_auth = (
        f'{_WWW_AUTH_BASE}, '
        f'error="{error}", '
        f'error_description="{description}"'
    )
    return JSONResponse(
        status_code=401,
        content={"error": error, "error_description": description},
        headers={"WWW-Authenticate": www_auth},
    )


@app.get("/.well-known/oauth-protected-resource")
def oauth_protected_resource_metadata() -> dict:
    """
    OAuth Protected Resource Metadata (RFC 8707 / MCP spec §Authorization).

    MCP clients use this to discover which authorization server issued
    the tokens this resource accepts.
    """
    return {
        "resource": MCP_RESOURCE_URI,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
        "resource_signing_alg_values_supported": [ALG],
    }


@app.get("/mcp")
def mcp_endpoint(request: Request) -> Response:
    """
    Protected MCP endpoint. Validates Bearer JWT per MCP 2025-06-18 auth spec.

    Validation order:
      1. Authorization header present and starts with 'Bearer '
      2. JWT signature valid (HS256, shared secret)
      3. Token not expired (exp claim)
      4. Issuer matches (iss == ISSUER)
      5. Resource indicator present and matches (resource == MCP_RESOURCE_URI)
      6. Audience present and matches (aud == MCP_RESOURCE_URI)
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return _unauthorized("invalid_token", "Bearer token required")

    token = auth_header[len("Bearer "):]

    try:
        claims = pyjwt.decode(
            token,
            SECRET,
            algorithms=[ALG],
            issuer=ISSUER,
            options={
                "verify_aud": False,  # we check aud manually below
                "require": ["exp", "iss", "sub"],
            },
        )
    except pyjwt.ExpiredSignatureError:
        return _unauthorized("invalid_token", "token expired")
    except pyjwt.InvalidIssuerError:
        return _unauthorized("invalid_token", "invalid issuer")
    except pyjwt.InvalidSignatureError:
        return _unauthorized("invalid_token", "invalid signature")
    except pyjwt.DecodeError:
        return _unauthorized("invalid_token", "malformed token")

    # RFC 8707: resource indicator must be present and match this server
    resource = claims.get("resource")
    if resource != MCP_RESOURCE_URI:
        return _unauthorized("invalid_token", "resource indicator required")

    # Audience must match this server's resource URI
    aud = claims.get("aud")
    if aud not in (MCP_RESOURCE_URI, [MCP_RESOURCE_URI]):
        return _unauthorized("invalid_token", "audience mismatch")

    return JSONResponse({"ok": True, "sub": claims.get("sub")})
