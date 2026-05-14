"""
ACPOrchestrator — Agentic Credential Protocol orchestrator.

ADR-027 Stage 7. Wires all Stage 5-6 ports into a single, ordered credential
request pipeline.

Standards references:
  - RFC 8693 §4.1: act claim (delegation chain)
  - RFC 9449 §4.2: DPoP proof validation (10 steps)
  - RFC 8707 §2: resource indicator
  - ADR-026 Rule 6: ProviderCredential only from CredentialBrokerPort
  - ADR-028 SD-1: principal_kind discriminator (human | agent)

Pipeline order
--------------
1. Decode subject_token → Principal
2. Validate DPoP proof (if dpop_proof present and dpop_validator wired)
3. Token exchange — extract act claim (if actor_token present and token_exchange wired)
4. Scope policy evaluation (ScopePolicyAdapter / PolicyDecisionPoint)
5. Broker call: CredentialBrokerPort.vend_credential()
6. Emit AuditEvent (ALLOW or DENY)

ADR-026 Rule 6 invariant
------------------------
ACPOrchestrator NEVER creates ProviderCredential directly.
All credential material comes exclusively from CredentialBrokerPort.vend_credential().

Usage:
    orchestrator = ACPOrchestrator(
        broker=MyBrokerAdapter(),
        scope_policy=ScopePolicyAdapter(...),
        audit=MemoryAuditAdapter(),
        signing_key="shared-hs256-key",
        token_exchange=RFC8693TokenExchangeAdapter(...),
        dpop_validator=StrictDPoPValidator(...),
    )
    response = orchestrator.request_credential(DelegatedCredentialRequest(
        tool_request=ToolRequest(...),
        subject_token=human_jwt,
        actor_token=orchestrator_jwt,
        dpop_proof=dpop_proof_object,
        expected_htm="POST",
        expected_htu="https://auth.swarms.network/credentials",
    ))
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

import jwt as pyjwt

from swarm_auth.domain.agent_identity import AgentIdentity, AgentType
from swarm_auth.domain.human_user import HumanUser
from swarm_auth.domain.principal import Principal
from swarm_auth.domain.roles import UserRole
from swarm_auth.ports.audit_port import (
    ActorChainSnapshot,
    AuditEvent,
    AuditEventType,
    AuditPort,
)
from swarm_auth.ports.credential_broker_port import (
    CredentialBrokerPort,
    ProviderCredential,
    ToolRequest,
)
from swarm_auth.ports.dpop_validator_port import DPoPProof, DPoPValidatorPort
from swarm_auth.ports.policy_port import Action, Decision, PolicyDecisionPoint, Resource
from swarm_auth.ports.token_exchange_port import (
    DelegationType,
    TokenExchangePort,
    TokenExchangeRequest,
    TokenType,
)

_ALGORITHM = "HS256"


# ---------------------------------------------------------------------------
# Request / Response types
# ---------------------------------------------------------------------------


@dataclass
class DelegatedCredentialRequest:
    """
    Input to ACPOrchestrator.request_credential().

    All credential requests must carry a subject_token. actor_token and
    dpop_proof are optional; when present they activate the corresponding
    pipeline steps (token exchange and DPoP validation respectively).
    """

    tool_request: ToolRequest
    subject_token: str
    actor_token: Optional[str] = None
    dpop_proof: Optional[DPoPProof] = None
    expected_htm: str = "POST"
    expected_htu: str = ""
    expected_nonce: Optional[str] = None
    access_token_hash: Optional[str] = None


@dataclass
class CredentialResponse:
    """
    Output from ACPOrchestrator.request_credential().

    On success, credential is populated and error is None.
    On failure, credential is None and error/error_description are populated.
    """

    credential: Optional[ProviderCredential]
    error: Optional[str] = None
    error_description: Optional[str] = None


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class ACPOrchestrator:
    """
    ACP pipeline: DPoP validation → token exchange → scope check → broker → audit.

    Constructor requirements:
        broker:       MANDATORY — all credential material flows through it
        scope_policy: MANDATORY — evaluated before every broker call
        audit:        MANDATORY — every allow and deny is logged
        signing_key:  MANDATORY — used to decode subject/actor tokens (HS256)
        token_exchange: optional — wire RFC8693TokenExchangeAdapter for delegation
        dpop_validator: optional — wire StrictDPoPValidator for DPoP-bound tokens

    ADR-026 Rule 6: ACPOrchestrator.request_credential() never instantiates
    ProviderCredential. It only returns the instance from broker.vend_credential().
    """

    def __init__(
        self,
        broker: CredentialBrokerPort,
        scope_policy: PolicyDecisionPoint,
        audit: AuditPort,
        signing_key: str,
        token_exchange: Optional[TokenExchangePort] = None,
        dpop_validator: Optional[DPoPValidatorPort] = None,
    ) -> None:
        self._broker = broker
        self._scope_policy = scope_policy
        self._audit = audit
        self._signing_key = signing_key
        self._token_exchange = token_exchange
        self._dpop_validator = dpop_validator

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def request_credential(self, request: DelegatedCredentialRequest) -> CredentialResponse:
        """
        Run the ACP pipeline and return a ProviderCredential on success.

        Returns CredentialResponse with error populated on any failure —
        does not raise for expected validation failures.
        """
        # Step 1: decode subject_token → Principal
        principal, err = self._decode_principal(request.subject_token)
        if err:
            self._emit_deny("<unknown>", err, request.tool_request)
            return CredentialResponse(credential=None, error="invalid_request", error_description=err)

        # Step 2: DPoP validation (optional port)
        if request.dpop_proof is not None:
            if self._dpop_validator is None:
                reason = "DPoP proof provided but dpop_validator port not wired"
                self._emit_deny(principal.user_id, reason, request.tool_request)
                return CredentialResponse(credential=None, error="invalid_request", error_description=reason)
            dpop_result = self._dpop_validator.validate_proof(
                request.dpop_proof,
                request.expected_htm,
                request.expected_htu,
                expected_nonce=request.expected_nonce,
                access_token_hash=request.access_token_hash,
            )
            if not dpop_result.valid:
                reason = f"dpop_invalid: {dpop_result.error_description}"
                self._emit_deny(principal.user_id, reason, request.tool_request)
                return CredentialResponse(credential=None, error="invalid_dpop_proof", error_description=dpop_result.error_description)

        # Step 3: token exchange — build act claim from delegation (optional port)
        act_claim = None
        if request.actor_token is not None:
            if self._token_exchange is None:
                reason = "actor_token provided but token_exchange port not wired"
                self._emit_deny(principal.user_id, reason, request.tool_request)
                return CredentialResponse(credential=None, error="invalid_request", error_description=reason)
            exchange_req = TokenExchangeRequest(
                subject_token=request.subject_token,
                subject_token_type=TokenType.ACCESS_TOKEN,
                requested_token_type=TokenType.ACCESS_TOKEN,
                actor_token=request.actor_token,
                actor_token_type=TokenType.ACCESS_TOKEN,
                delegation_type=DelegationType.DELEGATION,
            )
            exchange_resp = self._token_exchange.exchange(exchange_req)
            if exchange_resp.error:
                reason = f"exchange_failed: {exchange_resp.error_description}"
                self._emit_deny(principal.user_id, reason, request.tool_request)
                return CredentialResponse(
                    credential=None,
                    error=exchange_resp.error,
                    error_description=exchange_resp.error_description,
                )
            act_claim = exchange_resp.act_claim

        # Step 4: scope policy check
        action, resource = self._parse_action_resource(request.tool_request)
        policy_decision = self._scope_policy.evaluate(principal, action, resource)
        if policy_decision.decision != Decision.ALLOW:
            reason = policy_decision.reason or "scope policy denied"
            self._emit_deny(principal.user_id, reason, request.tool_request, act_claim=act_claim)
            return CredentialResponse(credential=None, error="access_denied", error_description=reason)

        # Step 5: broker call (ADR-026 Rule 6 — only source of ProviderCredential)
        try:
            credential = self._broker.vend_credential(principal, request.tool_request)
        except Exception as exc:
            reason = f"broker_error: {exc}"
            self._emit_deny(principal.user_id, reason, request.tool_request, act_claim=act_claim)
            return CredentialResponse(credential=None, error="server_error", error_description=str(exc))

        # Step 6: emit ALLOW audit event
        self._emit_allow(principal.user_id, request.tool_request, act_claim=act_claim)
        return CredentialResponse(credential=credential)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _decode_principal(self, token: str) -> Tuple[Optional[Principal], Optional[str]]:
        """
        Decode an HS256 JWT and build the matching Principal subclass.

        Returns (principal, None) on success, (None, error_str) on failure.
        """
        try:
            claims = pyjwt.decode(
                token,
                self._signing_key,
                algorithms=[_ALGORITHM],
                options={"verify_aud": False},
            )
        except pyjwt.ExpiredSignatureError:
            return None, "subject_token is expired"
        except pyjwt.InvalidTokenError:
            return None, "subject_token is invalid"

        sub = claims.get("sub")
        if not sub:
            return None, "subject_token missing 'sub' claim"

        principal_kind = claims.get("principal_kind", "human")
        if principal_kind == "agent":
            agent_type_str = claims.get("agent_type", "service")
            try:
                agent_type = AgentType(agent_type_str)
            except ValueError:
                agent_type = AgentType.SERVICE
            return AgentIdentity(
                user_id=sub,
                username=sub,
                role=UserRole.SERVICE,
                agent_type=agent_type,
            ), None
        else:
            return HumanUser(user_id=sub, username=sub, role=UserRole.GUEST), None

    def _parse_action_resource(self, tool_request: ToolRequest) -> Tuple[Action, Resource]:
        """
        Build Action and Resource from a ToolRequest.

        ToolRequest.action uses provider-native notation:
          AWS:    "s3:PutObject"   → resource_type="s3",   verb="PutObject"
          Others: "chat.generate"  → resource_type="chat", verb="generate"
        """
        action_str = tool_request.action
        provider = tool_request.provider.value
        if ":" in action_str:
            resource_type, verb = action_str.split(":", 1)
        elif "." in action_str:
            resource_type, verb = action_str.split(".", 1)
        else:
            resource_type, verb = action_str, "unknown"
        action = Action(provider=provider, resource_type=resource_type, verb=verb)
        resource = Resource(
            provider=provider,
            resource_type=resource_type,
            identifier=tool_request.resource,
            attributes={},
        )
        return action, resource

    def _make_actor_chain_snapshot(
        self, principal_id: str, act_claim: Optional[dict]
    ) -> Optional[ActorChainSnapshot]:
        """Build ActorChainSnapshot from an RFC 8693 act claim dict."""
        if act_claim is None:
            return None
        actor_sub = act_claim.get("sub", "")
        depth = 1
        current = act_claim.get("act")
        while current is not None:
            depth += 1
            current = current.get("act")
        return ActorChainSnapshot(
            subject=principal_id,
            actor=actor_sub,
            chain_depth=depth,
            raw_act_claim=act_claim,
        )

    def _emit_allow(
        self, principal_id: str, tool_request: ToolRequest, *, act_claim: Optional[dict] = None
    ) -> None:
        self._audit.emit(AuditEvent(
            event_type=AuditEventType.CREDENTIAL_VENDED,
            principal_id=principal_id,
            provider=tool_request.provider.value,
            action=tool_request.action,
            resource=tool_request.resource,
            actor_chain=self._make_actor_chain_snapshot(principal_id, act_claim),
        ))

    def _emit_deny(
        self,
        principal_id: str,
        reason: str,
        tool_request: Optional[ToolRequest],
        *,
        act_claim: Optional[dict] = None,
    ) -> None:
        self._audit.emit(AuditEvent(
            event_type=AuditEventType.POLICY_DENY,
            principal_id=principal_id,
            provider=tool_request.provider.value if tool_request else None,
            action=tool_request.action if tool_request else None,
            resource=tool_request.resource if tool_request else None,
            decision_reason=reason,
            actor_chain=self._make_actor_chain_snapshot(principal_id, act_claim),
        ))
