"""
Shared fixtures for Stage 8.4 integration tests.

Provides:
  client              — TestClient for the MCP test server
  acp_token_with_resource   — valid JWT with resource + aud = MCP_RESOURCE_URI
  acp_token_without_resource — valid JWT missing resource/aud claims
"""

from __future__ import annotations

import time
from typing import Optional

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


def _mint_token(
    sub: str = "alice",
    resource: Optional[str] = MCP_RESOURCE_URI,
    aud: Optional[str] = MCP_RESOURCE_URI,
    ttl: int = 3600,
) -> str:
    """Mint a test JWT. Pass resource=None / aud=None to omit those claims."""
    now = int(time.time())
    payload: dict = {
        "sub": sub,
        "iss": ISSUER,
        "iat": now,
        "exp": now + ttl,
        "principal_kind": "human",
    }
    if resource is not None:
        payload["resource"] = resource
    if aud is not None:
        payload["aud"] = aud
    return pyjwt.encode(payload, SECRET, algorithm=ALG)


@pytest.fixture
def client() -> TestClient:
    """Starlette TestClient wrapping the MCP test server (no real HTTP)."""
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def acp_token_with_resource() -> str:
    """Valid ACP token with correct resource + aud claims for MCP_RESOURCE_URI."""
    return _mint_token()


@pytest.fixture
def acp_token_without_resource() -> str:
    """Valid ACP token missing resource and aud claims."""
    return _mint_token(resource=None, aud=None)


@pytest.fixture
def acp_token_wrong_resource() -> str:
    """ACP token with wrong resource URI (different server)."""
    return _mint_token(
        resource="https://other.example.com/mcp",
        aud="https://other.example.com/mcp",
    )


@pytest.fixture
def acp_token_expired() -> str:
    """Expired ACP token."""
    return _mint_token(ttl=-1)
