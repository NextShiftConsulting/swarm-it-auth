"""
Minimal RFC 8693 token exchange test server.

A FastAPI app that exposes POST /token, backed by RFC8693TokenExchangeAdapter.
Used by the Stage 8.4 authlib integration test (issue #2).

Spec: RFC 8693 §2.1 token exchange request format
  grant_type = urn:ietf:params:oauth:grant-type:token-exchange
  subject_token, subject_token_type
  actor_token, actor_token_type  (optional — activates delegation)

Response format: RFC 8693 §2.2
  {"access_token": "<jwt>", "token_type": "Bearer", "issued_token_type": "..."}

The issued access_token is a JWT containing:
  sub  = subject identity
  act  = {"sub": actor_identity}  (RFC 8693 §4.1 act claim)

No state, no persistence, no real OAuth infrastructure.
"""

from __future__ import annotations

from typing import Optional

import jwt as pyjwt
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import JSONResponse

from swarm_auth.adapters.rfc8693_token_exchange import RFC8693TokenExchangeAdapter
from swarm_auth.ports.token_exchange_port import (
    DelegationType,
    TokenExchangeRequest,
    TokenType,
)

# ---------------------------------------------------------------------------
# Constants (shared with conftest / tests)
# ---------------------------------------------------------------------------

TOKEN_EXCHANGE_SECRET = "rfc8693-test-secret-at-least-32-bytes!!"
TOKEN_EXCHANGE_ISSUER = "swarm-it-auth"
RFC8693_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

# ---------------------------------------------------------------------------
# Adapter (shared instance — stateless, safe for tests)
# ---------------------------------------------------------------------------

_adapter = RFC8693TokenExchangeAdapter(
    signing_key=TOKEN_EXCHANGE_SECRET,
    issuer=TOKEN_EXCHANGE_ISSUER,
)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(title="RFC 8693 Token Exchange Test Server")


@app.post("/token")
def token_endpoint(
    grant_type: str = Form(...),
    subject_token: str = Form(...),
    subject_token_type: str = Form(...),
    actor_token: Optional[str] = Form(None),
    actor_token_type: Optional[str] = Form(None),
    requested_token_type: Optional[str] = Form(None),
) -> JSONResponse:
    """
    RFC 8693 §2.1 token exchange endpoint.

    Validates grant_type, delegates to RFC8693TokenExchangeAdapter,
    returns RFC 6749-style JSON response.
    """
    if grant_type != RFC8693_GRANT_TYPE:
        raise HTTPException(
            status_code=400,
            detail={"error": "unsupported_grant_type",
                    "error_description": f"expected {RFC8693_GRANT_TYPE}"},
        )

    req = TokenExchangeRequest(
        subject_token=subject_token,
        subject_token_type=TokenType.ACCESS_TOKEN,
        requested_token_type=TokenType.ACCESS_TOKEN,
        actor_token=actor_token,
        actor_token_type=TokenType.ACCESS_TOKEN if actor_token else None,
        delegation_type=DelegationType.DELEGATION if actor_token else None,
    )
    result = _adapter.exchange(req)

    if result.error:
        raise HTTPException(
            status_code=400,
            detail={"error": result.error, "error_description": result.error_description},
        )

    return JSONResponse({
        "access_token": result.access_token,
        "token_type": "Bearer",
        "issued_token_type": ACCESS_TOKEN_TYPE,
    })
