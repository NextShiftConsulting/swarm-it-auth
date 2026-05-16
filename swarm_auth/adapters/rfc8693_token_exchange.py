"""
RFC 8693 Token Exchange Adapter — delegation token issuance.

ADR-027 Stage 6. Closes Gap 4 (flat delegation chains) and Gap 5 (no
standard HTTP grant).

Standards references:
  - RFC 8693 §2.1: request parameters
  - RFC 8693 §2.2: response parameters
  - RFC 8693 §4.1: act claim (delegation chain)
  - RFC 8693 §8: security — chain depth, token substitution
  - RFC 7662: introspect endpoint
  - RFC 8707 §2: resource indicator validation (via ScopePolicyAdapter)

What this adapter does
----------------------
Issues a short-lived internal JWT ("delegation token") whose act claim
(RFC 8693 §4.1) records the delegation chain:

    {"sub": "<human_or_outer_agent>", "act": {"sub": "<orchestrator>"}}

For deeper chains the act claim is nested:
    {"sub": "u1", "act": {"sub": "orch-A", "act": {"sub": "orch-B"}}}

The issued token is returned as TokenExchangeResponse.access_token.
It can then be presented to the CredentialBrokerPort (Stage 7 ACP
orchestrator) to authorize provider credential vending.

Broker call
-----------
Credential production (ProviderCredential) happens in the credential
broker, not here. This adapter issues the DELEGATION PROOF (the JWT with
act claim). The Stage 7 ACPOrchestrator wires the delegation token into
the broker call.

ADR-026 Rule 6: this adapter never produces ProviderCredential directly.

Validation rules
----------------
- subject_token: decoded from the shared HS256 signing_key (must be valid JWT)
- actor_token: if present, must decode to an AgentIdentity with
  agent_type == "orchestrator"
- Chain depth: count nested act levels from actor_token; reject if
  ≥ request.max_chain_depth

Usage:
    exchanger = RFC8693TokenExchangeAdapter(signing_key="shared-hs256-signing_key")
    response = exchanger.exchange(TokenExchangeRequest(
        subject_token=human_jwt,
        subject_token_type=TokenType.ACCESS_TOKEN,
        requested_token_type=TokenType.ACCESS_TOKEN,
        actor_token=orchestrator_jwt,
        actor_token_type=TokenType.ACCESS_TOKEN,
        scope=["aws.s3.get"],
        resource="arn:aws:s3:::swarm-data/",
    ))
    # response.access_token: JWT with sub=human, act={sub=orchestrator}
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

import jwt as pyjwt

from swarm_auth.ports.token_exchange_port import (
    DelegationType,
    TokenExchangePort,
    TokenExchangeRequest,
    TokenExchangeResponse,
    TokenType,
)

_ALGORITHM = "HS256"
_DEFAULT_TTL_SECONDS = 3600  # 1 hour


def _count_act_depth(claims: Dict[str, Any]) -> int:
    """Count the number of nested act hops in a decoded JWT payload."""
    depth = 0
    current = claims.get("act")
    while current is not None:
        depth += 1
        current = current.get("act")
    return depth


class RFC8693TokenExchangeAdapter(TokenExchangePort):
    """
    RFC 8693 token exchange: validates delegation and issues act-claim JWT.

    Args:
        signing_key:          HS256 signing signing_key (same as JWTAuthAdapter signing_key).
        token_ttl:       Lifetime of issued tokens in seconds (default 3600).
        issuer:          "iss" claim in issued tokens (default "swarm-it-auth").
    """

    def __init__(
        self,
        signing_key: str,
        token_ttl: int = _DEFAULT_TTL_SECONDS,
        issuer: str = "swarm-it-auth",
    ) -> None:
        self._signing_key = signing_key
        self._token_ttl = token_ttl
        self._issuer = issuer

    # ------------------------------------------------------------------
    # TokenExchangePort interface
    # ------------------------------------------------------------------

    def exchange(self, request: TokenExchangeRequest) -> TokenExchangeResponse:
        """
        Issue a delegation token per RFC 8693.

        Validation order:
        1. Decode and validate subject_token
        2. If actor_token present: decode, assert AgentIdentity + ORCHESTRATOR
        3. Count existing act chain depth; reject if >= max_chain_depth
        4. Issue new JWT with RFC 8693 §4.1 act claim
        5. Return TokenExchangeResponse

        On validation error, returns TokenExchangeResponse with error
        populated (does not raise).
        """
        # Blocker B3 (Stage 6): fail closed on dpop_jkt and resource until Stage 7.
        # dpop_jkt requires a cnf claim + token_type="DPoP" wired to DPoPValidatorPort.
        # resource requires scope policy validation wired to ScopePolicyAdapter.
        # Both are Stage 7 ACPOrchestrator responsibilities.
        if request.dpop_jkt is not None:
            return TokenExchangeResponse(
                error="invalid_request",
                error_description=(
                    "DPoP-bound exchange tokens (dpop_jkt) are not supported until "
                    "Stage 7: ACPOrchestrator wires DPoPValidatorPort to the exchange flow."
                ),
            )
        if request.resource is not None:
            return TokenExchangeResponse(
                error="invalid_request",
                error_description=(
                    "resource indicator validation is not supported until "
                    "Stage 7: ACPOrchestrator wires ScopePolicyAdapter to the exchange flow."
                ),
            )

        # Blocker B2: DELEGATION requires actor_token (RFC 8693 §4.1).
        # Impersonation may omit actor_token (actor_token optional per RFC 8693 §1.1).
        if request.delegation_type == DelegationType.DELEGATION and not request.actor_token:
            return TokenExchangeResponse(
                error="invalid_request",
                error_description=(
                    "actor_token is required for DelegationType.DELEGATION. "
                    "Provide the orchestrator's access token as actor_token."
                ),
            )

        if request.actor_token is not None and request.actor_token_type is None:
            return TokenExchangeResponse(
                error="invalid_request",
                error_description="actor_token_type is required when actor_token is provided.",
            )

        # Step 1: decode subject token
        subject_claims = self._decode_token(request.subject_token)
        if subject_claims is None:
            return TokenExchangeResponse(
                error="invalid_request",
                error_description="subject_token is invalid or expired.",
            )

        subject_sub = subject_claims.get("sub")
        if not subject_sub:
            return TokenExchangeResponse(
                error="invalid_request",
                error_description="subject_token missing 'sub' claim.",
            )

        # Step 2: decode and validate actor token
        act_claim: Optional[Dict[str, Any]] = None

        if request.actor_token is not None:
            actor_claims = self._decode_token(request.actor_token)
            if actor_claims is None:
                return TokenExchangeResponse(
                    error="invalid_request",
                    error_description="actor_token is invalid or expired.",
                )

            # Actor must be an agent with agent_type == orchestrator
            if actor_claims.get("principal_kind") != "agent":
                return TokenExchangeResponse(
                    error="invalid_request",
                    error_description=(
                        "actor_token must represent an AgentIdentity "
                        "(principal_kind='agent'). Got: "
                        f"{actor_claims.get('principal_kind')!r}"
                    ),
                )

            if actor_claims.get("agent_type") != "orchestrator":
                return TokenExchangeResponse(
                    error="invalid_request",
                    error_description=(
                        "Only ORCHESTRATOR agents may perform token exchange. "
                        f"Got agent_type={actor_claims.get('agent_type')!r}"
                    ),
                )

            # Step 3: chain depth check (RFC 8693 §8)
            existing_depth = _count_act_depth(actor_claims)
            if existing_depth >= request.max_chain_depth:
                return TokenExchangeResponse(
                    error="invalid_request",
                    error_description=(
                        f"Delegation chain depth {existing_depth + 1} would exceed "
                        f"max_chain_depth={request.max_chain_depth}."
                    ),
                )

            # Build RFC 8693 §4.1 act claim
            actor_sub = actor_claims.get("sub")
            if not actor_sub:
                return TokenExchangeResponse(
                    error="invalid_request",
                    error_description="actor_token missing 'sub' claim; cannot build act claim.",
                )
            act_claim = {"sub": actor_sub}
            # Carry forward any existing act chain from the actor token
            if "act" in actor_claims:
                act_claim["act"] = actor_claims["act"]

        # Step 4: issue delegation token
        now = int(time.time())
        payload: Dict[str, Any] = {
            "iss": self._issuer,
            "sub": subject_sub,
            "iat": now,
            "exp": now + self._token_ttl,
            "token_type": "delegation",
        }

        if act_claim is not None:
            payload["act"] = act_claim                    # RFC 8693 §4.1

        if request.scope:
            payload["scope"] = " ".join(request.scope)

        if request.audience:
            payload["aud"] = request.audience

        # resource and dpop_jkt are fail-closed above; no payload writes here.

        if request.delegation_type == DelegationType.IMPERSONATION:
            payload["may_act"] = {"sub": act_claim["sub"]} if act_claim else {}

        access_token = pyjwt.encode(payload, self._signing_key, algorithm=_ALGORITHM)

        return TokenExchangeResponse(
            access_token=access_token,
            issued_token_type=TokenType.ACCESS_TOKEN,
            token_type="Bearer",
            expires_in=self._token_ttl,
            scope=" ".join(request.scope) if request.scope else None,
            act_claim=act_claim,
        )

    def introspect(self, token: str) -> Dict[str, Any]:
        """
        Introspect a delegation token issued by this adapter.

        Returns {"active": True, ...claims...} if the token is valid
        and has not expired. Returns {"active": False} otherwise.
        """
        claims = self._decode_token(token)
        if claims is None:
            return {"active": False}

        # Only introspect tokens issued by us
        if claims.get("iss") != self._issuer:
            return {"active": False}

        return {"active": True, **claims}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Decode an HS256 JWT. Returns claims dict or None on failure.

        Verifies signature and expiry. Does not raise.
        """
        try:
            return pyjwt.decode(
                token,
                self._signing_key,
                algorithms=[_ALGORITHM],
                options={"verify_aud": False},
            )
        except pyjwt.ExpiredSignatureError:
            return None
        except pyjwt.InvalidTokenError:
            return None
