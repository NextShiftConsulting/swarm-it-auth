"""
Token Exchange Port — OAuth 2.0 Token Exchange for agent delegation chains.

ADR-027 Stage 5 / ADR-028 Sub-decision 5 (Gap 4: flat delegation chains, Gap 5: no HTTP grant).

Standards references:
  - RFC 8693: OAuth 2.0 Token Exchange
    §2.1: Request parameters (grant_type, subject_token, actor_token, …)
    §2.2: Response parameters (access_token, issued_token_type, expires_in, …)
    §3:   Token type identifiers (urn:ietf:params:oauth:token-type:*)
    §4:   Actors and delegation (act claim structure)
    §8:   Security considerations (token substitution, chain depth)
  - RFC 8707: Resource Indicators for OAuth 2.0
    §2:   resource parameter (URI identifying the target resource)
  - RFC 9449 §5: DPoP-bound access tokens (ath claim)

Token exchange is how an orchestrator agent requests a short-lived token scoped
to a specific sub-agent's capabilities (delegation), or how a sub-agent acts on
behalf of a human user (impersonation). The resulting token carries an RFC 8693
act claim recording the full delegation chain.

Gap 4 closed: ADR-027 Gap 4 — delegation chains were flat (no act claim).
Gap 5 closed: ADR-027 Gap 5 — no standard OAuth 2.0 HTTP grant existed.

No implementation in this file. Adapters live in swarm_auth/adapters/:
  - Stage 6: RFC8693TokenExchangeAdapter (full RFC 8693 §2 compliance)

Usage (Stage 7+):
    from swarm_auth.ports.token_exchange_port import (
        TokenExchangePort, TokenExchangeRequest, TokenType,
    )

    exchanger: TokenExchangePort = RFC8693TokenExchangeAdapter(...)
    response = exchanger.exchange(TokenExchangeRequest(
        subject_token=human_jwt,
        subject_token_type=TokenType.ACCESS_TOKEN,
        actor_token=orchestrator_jwt,
        actor_token_type=TokenType.ACCESS_TOKEN,
        requested_token_type=TokenType.ACCESS_TOKEN,
        scope=["aws.s3.get"],
        resource="arn:aws:s3:::swarm-data/",
    ))
    # response.access_token carries act claim: {sub: human, act: {sub: orchestrator}}
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class TokenType(Enum):
    """
    RFC 8693 §3 token type URNs.

    Used in subject_token_type and actor_token_type request fields, and in
    issued_token_type response field.
    """
    ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
    REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token"
    ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
    SAML1 = "urn:ietf:params:oauth:token-type:saml1"
    SAML2 = "urn:ietf:params:oauth:token-type:saml2"
    JWT = "urn:ietf:params:oauth:token-type:jwt"


class ExchangeGrantType(Enum):
    """
    RFC 8693 §2.1: grant_type for the token exchange request.

    Exactly one value is defined in RFC 8693. The enum exists so
    implementations can add extensions without raw strings.
    """
    TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"


class DelegationType(Enum):
    """
    Whether the exchange represents delegation or impersonation (RFC 8693 §1.1).

    DELEGATION:   actor acts WITH AUTHORITY derived from the subject.
                  Subject remains the primary identity; actor_token required.
                  Produces an act claim (RFC 8693 §4.1).

    IMPERSONATION: actor acts AS the subject.
                  Subject's identity is adopted; actor_token optional.
                  No act claim — the caller appears to be the subject.
    """
    DELEGATION = "delegation"
    IMPERSONATION = "impersonation"


@dataclass
class TokenExchangeRequest:
    """
    RFC 8693 §2.1: Token exchange request parameters.

    This dataclass maps 1-to-1 to the OAuth 2.0 token endpoint request body.
    All field names follow the RFC snake_case convention.
    """
    # Required (RFC 8693 §2.1)
    subject_token: str                      # The token representing the subject
    subject_token_type: TokenType           # Type of subject_token
    requested_token_type: TokenType         # Desired output token type

    # Delegation-specific (required for DELEGATION type)
    actor_token: Optional[str] = None       # Token representing the acting agent
    actor_token_type: Optional[TokenType] = None

    # Scope and audience
    scope: List[str] = field(default_factory=list)   # Requested scopes
    audience: Optional[str] = None          # Intended audience (aud claim)

    # RFC 8707 §2: resource indicator (URI of target resource)
    resource: Optional[str] = None          # e.g. "https://api.swarms.network/"

    # Delegation vs impersonation (RFC 8693 §1.1)
    delegation_type: DelegationType = DelegationType.DELEGATION

    # Chain depth guard (RFC 8693 §8 security consideration)
    # Adapters MUST reject exchanges that would exceed this depth.
    max_chain_depth: int = 10               # Matches domain.agent_identity.MAX_ACT_CHAIN_DEPTH

    # DPoP binding (RFC 9449 §5): if set, the issued token is DPoP-bound
    dpop_jkt: Optional[str] = None         # JWK Thumbprint of the DPoP key


@dataclass
class TokenExchangeResponse:
    """
    RFC 8693 §2.2: Token exchange response.

    On success, contains the issued token and its metadata.
    On failure, error and error_description are populated.
    """
    # Success fields (RFC 8693 §2.2)
    access_token: Optional[str] = None
    issued_token_type: Optional[TokenType] = None
    token_type: str = "Bearer"              # or "DPoP" when dpop_jkt was set
    expires_in: Optional[int] = None        # Lifetime in seconds
    scope: Optional[str] = None             # Space-separated granted scopes

    # Error fields (RFC 6749 §5.2, referenced by RFC 8693)
    error: Optional[str] = None
    error_description: Optional[str] = None

    # Metadata
    issued_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # Act claim snapshot — preserved for audit logging
    act_claim: Optional[Dict[str, Any]] = None   # RFC 8693 §4.1 act structure


class TokenExchangeError(Exception):
    """
    Raised by TokenExchangePort.exchange() on non-recoverable errors.

    Carries the RFC 6749 §5.2 error code and an optional description.
    """
    def __init__(self, error: str, description: Optional[str] = None) -> None:
        self.error = error
        self.error_description = description
        super().__init__(f"Token exchange failed: {error}" + (
            f" — {description}" if description else ""
        ))


class TokenExchangePort(ABC):
    """
    Port: OAuth 2.0 Token Exchange (RFC 8693).

    Issues short-lived, scoped tokens that carry RFC 8693 act claims
    representing the agent delegation chain. Called by the ACP orchestrator
    (Stage 7) to transform an incoming principal token into a delegation-aware
    token scoped to the target resource.

    Closes ADR-027 Gap 4 (act claims in delegation tokens) and Gap 5 (standard
    OAuth 2.0 HTTP grant for agent-to-agent token exchange).

    Implementors MUST:
      - Validate subject_token and actor_token before issuing
      - Enforce max_chain_depth from the request (RFC 8693 §8)
      - Include an act claim in delegation-type responses (RFC 8693 §4.1)
      - Scope the issued token to only the requested scopes (least privilege)
      - Bind to the DPoP key when dpop_jkt is present (RFC 9449 §5)
      - Validate the resource indicator against ScopePolicyAdapter when set (RFC 8707 §2)
    """

    @abstractmethod
    def exchange(self, request: TokenExchangeRequest) -> TokenExchangeResponse:
        """
        Perform a token exchange per RFC 8693 §2.

        Args:
            request: Token exchange parameters.

        Returns:
            TokenExchangeResponse with the issued token on success.
            On validation failure, returns a response with error populated
            (does not raise) so callers can log before returning HTTP 400.

        Raises:
            TokenExchangeError: For unrecoverable server-side errors
                                (e.g. key store unavailable, signing key missing).
        """
        pass

    @abstractmethod
    def introspect(self, token: str) -> Dict[str, Any]:
        """
        Introspect a previously issued exchange token (RFC 7662).

        Returns the token's claims if active, or {"active": False} if the
        token is expired, revoked, or not issued by this exchange service.

        Args:
            token: Compact-serialized JWT issued by exchange().

        Returns:
            Dict with "active": bool and, when active, the full claims.
        """
        pass
