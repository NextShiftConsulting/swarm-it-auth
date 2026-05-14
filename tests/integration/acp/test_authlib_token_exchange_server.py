"""
Stage 8.4: Authlib RFC 8693 integration test — in-process token exchange server.

ADR-027 Stage 0 acceptance criterion:
  A real third-party OAuth 2.1 client (authlib) completes a token exchange against
  the broker without custom shims.

Tracks: https://github.com/NextShiftConsulting/swarm-it-auth/issues/2

Converts: test_rfc8693_token_exchange_carries_act_claim (xfail in tests/acp/test_rfc8693_compat.py)

Infrastructure required:
  - authlib (pip install authlib)
  - pytest-httpserver or starlette.testclient for in-process HTTP server

Design:
  1. Spin up an in-process WSGI/ASGI server exposing POST /token
  2. The endpoint calls RFC8693TokenExchangeAdapter.exchange()
  3. authlib OAuth2Session.exchange_token() calls the endpoint as a standard client
  4. Assert: response contains "act" claim with correct RFC 8693 sub chain
  5. Assert: no custom shims — authlib receives a standard RFC 6749 token response

Guardrails (ADR-027 Stage 8.4):
  - Test-only. No production OAuth server.
  - No new broker logic, no new production wiring.
  - Scope: tests/integration/acp/ only.
"""

import pytest

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

authlib = pytest.importorskip(
    "authlib",
    reason="authlib not installed — pip install authlib to run Stage 8.4 tests",
)
pytest_httpserver = pytest.importorskip(
    "pytest_httpserver",
    reason="pytest-httpserver not installed — pip install pytest-httpserver to run Stage 8.4 tests",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# TODO (Stage 8.4): implement token exchange server fixture
# Suggested approach:
#   @pytest.fixture
#   def token_exchange_server(httpserver):
#       """In-process server exposing POST /token backed by RFC8693TokenExchangeAdapter."""
#       from swarm_auth.adapters.rfc8693_token_exchange import RFC8693TokenExchangeAdapter
#       adapter = RFC8693TokenExchangeAdapter(signing_key="test-key", issuer="http://localhost")
#       def handler(request):
#           ...  # parse form body, call adapter.exchange(), return JSON
#       httpserver.expect_request("/token", method="POST").respond_with_handler(handler)
#       return httpserver


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.skip(reason="Stage 8.4: server fixture not yet implemented — tracked in issue #2")
def test_authlib_token_exchange_carries_act_claim(token_exchange_server) -> None:
    """
    RFC 8693: authlib completes token exchange, response carries act chain.

    DoD:
    - authlib OAuth2Session.exchange_token() succeeds against the test server
    - Response "act" claim contains {"sub": orchestrator_id}
    - No custom shims — authlib is used as a stock OAuth 2.1 client
    """
    from authlib.integrations.requests_client import OAuth2Session  # type: ignore[import]

    client = OAuth2Session(client_id="test-orchestrator")
    response = client.exchange_token(
        token_exchange_server.url_for("/token"),
        subject_token="<human-jwt>",
        subject_token_type="urn:ietf:params:oauth:token-type:jwt",
        actor_token="<orchestrator-jwt>",
        actor_token_type="urn:ietf:params:oauth:token-type:jwt",
    )
    assert "act" in response, "RFC 8693: act claim must be present in token exchange response"
    assert response["act"]["sub"] == "test-orchestrator", "act.sub must match actor token sub"
