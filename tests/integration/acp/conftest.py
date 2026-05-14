"""
Shared fixtures for Stage 8.4 integration tests.

Provides:
  MCP fixtures:
    client                     — TestClient for the MCP test server (in-process)
    acp_token_with_resource    — valid JWT with resource + aud = MCP_RESOURCE_URI
    acp_token_without_resource — valid JWT missing resource/aud claims
    acp_token_wrong_resource   — valid JWT with wrong resource URI
    acp_token_expired          — expired JWT

  RFC 8693 / authlib fixtures:
    token_exchange_server_url  — localhost URL of running uvicorn server
    human_subject_token        — HS256 JWT for subject "alice"
    agent_actor_token          — HS256 JWT for actor "orch-001"
"""

from __future__ import annotations

import threading
import time
from typing import Generator, Optional

import jwt as pyjwt
import pytest
import uvicorn
from starlette.testclient import TestClient

from tests.integration.acp.mcp_test_server import (
    ALG,
    ISSUER,
    MCP_RESOURCE_URI,
    SECRET,
    app as mcp_app,
)
from tests.integration.acp.token_exchange_server import (
    TOKEN_EXCHANGE_SECRET,
    TOKEN_EXCHANGE_ISSUER,
    app as exchange_app,
)


# ---------------------------------------------------------------------------
# MCP token helpers
# ---------------------------------------------------------------------------

def _mint_mcp_token(
    sub: str = "alice",
    resource: Optional[str] = MCP_RESOURCE_URI,
    aud: Optional[str] = MCP_RESOURCE_URI,
    ttl: int = 3600,
) -> str:
    """Mint a test JWT for MCP tests. Pass resource=None / aud=None to omit."""
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


# ---------------------------------------------------------------------------
# RFC 8693 / authlib token helpers
# ---------------------------------------------------------------------------

def _mint_exchange_token(
    sub: str,
    principal_kind: str = "human",
    agent_type: Optional[str] = None,
    act: Optional[dict] = None,
    ttl: int = 3600,
) -> str:
    """Mint a JWT for token exchange tests (signed with TOKEN_EXCHANGE_SECRET)."""
    now = int(time.time())
    payload: dict = {
        "sub": sub,
        "iss": TOKEN_EXCHANGE_ISSUER,
        "iat": now,
        "exp": now + ttl,
        "principal_kind": principal_kind,
    }
    if agent_type:
        payload["agent_type"] = agent_type
    if act:
        payload["act"] = act
    return pyjwt.encode(payload, TOKEN_EXCHANGE_SECRET, algorithm="HS256")


# ---------------------------------------------------------------------------
# MCP fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client() -> TestClient:
    """Starlette TestClient wrapping the MCP test server (in-process, no TCP)."""
    return TestClient(mcp_app, raise_server_exceptions=True)


@pytest.fixture
def acp_token_with_resource() -> str:
    """Valid ACP token with correct resource + aud claims for MCP_RESOURCE_URI."""
    return _mint_mcp_token()


@pytest.fixture
def acp_token_without_resource() -> str:
    """Valid ACP token missing resource and aud claims."""
    return _mint_mcp_token(resource=None, aud=None)


@pytest.fixture
def acp_token_wrong_resource() -> str:
    """ACP token with wrong resource URI (different server)."""
    return _mint_mcp_token(
        resource="https://other.example.com/mcp",
        aud="https://other.example.com/mcp",
    )


@pytest.fixture
def acp_token_expired() -> str:
    """Expired ACP token."""
    return _mint_mcp_token(ttl=-1)


# ---------------------------------------------------------------------------
# RFC 8693 / authlib fixtures — real TCP server via uvicorn
# ---------------------------------------------------------------------------

class _UvicornThread(threading.Thread):
    """Run uvicorn in a background thread; signal shutdown via should_exit."""

    def __init__(self, app, host: str, port: int) -> None:
        super().__init__(daemon=True)
        config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        self.server = uvicorn.Server(config)

    def run(self) -> None:
        self.server.run()

    def stop(self) -> None:
        self.server.should_exit = True
        self.join(timeout=5)


@pytest.fixture(scope="module")
def token_exchange_server_url() -> Generator[str, None, None]:
    """
    Start the RFC 8693 token exchange server on a real TCP port.

    authlib's OAuth2Session uses requests under the hood — it requires a real
    HTTP server. We start uvicorn in a background thread and yield the base URL.
    Server is stopped after the module's tests complete.
    """
    host, port = "127.0.0.1", 19693  # port chosen to avoid common conflicts
    thread = _UvicornThread(exchange_app, host=host, port=port)
    thread.start()

    # Wait for server to be ready (up to 3 seconds)
    url = f"http://{host}:{port}"
    import requests as _requests
    for _ in range(30):
        try:
            _requests.get(f"{url}/docs", timeout=0.1)
            break
        except Exception:
            time.sleep(0.1)

    yield url
    thread.stop()


@pytest.fixture
def human_subject_token() -> str:
    """HS256 JWT for human subject 'alice' (signed with TOKEN_EXCHANGE_SECRET)."""
    return _mint_exchange_token(sub="alice", principal_kind="human")


@pytest.fixture
def agent_actor_token() -> str:
    """HS256 JWT for agent actor 'orch-001' (no prior act chain)."""
    return _mint_exchange_token(
        sub="orch-001",
        principal_kind="agent",
        agent_type="orchestrator",
    )
