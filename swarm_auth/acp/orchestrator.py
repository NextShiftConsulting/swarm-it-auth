"""
ACPOrchestrator — Agentic Credential Protocol orchestrator.

ADR-027 Stage 7 / Stage 7 security-review fix.

Standards references:
  - RFC 8693 §4.1: act claim (delegation chain)
  - RFC 9449 §4.2: DPoP proof validation (10 steps)
  - RFC 9449 §7.1: DPoP proof binding to actor key
  - RFC 8707 §2: resource indicator
  - ADR-026 Rule 6: ProviderCredential only from CredentialBrokerPort
  - ADR-028 SD-1: principal_kind discriminator (human | agent)

Pipeline order
--------------
1.  Decode subject_token → Principal (via auth port if wired, direct decode otherwise)
2.  Validate DPoP proof (if dpop_proof present and dpop_validator wired)
2b. Bind DPoP agent_id to actor_token subject or agent subject (RFC 9449 §7.1)
3.  Token exchange — extract act claim (if actor_token present and token_exchange wired)
4.  Policy pipeline: evaluate ALL PDPs in sequence; first DENY short-circuits
5.  Enrich ToolRequest with actor-chain context (scope_restrictions + principal_id)
6.  Broker call: CredentialBrokerPort.vend_credential()
7.  Emit AuditEvent (ALLOW or DENY) with principal_kind in metadata

ADR-026 Rule 6 invariant
------------------------
ACPOrchestrator NEVER creates ProviderCredential directly.
All credential material comes exclusively from CredentialBrokerPort.vend_credential().

Security notes
--------------
- Policy pipeline: pass [RBACPolicyAdapter, ScopePolicyAdapter] to enforce
  RBAC ∩ scope. Passing only ScopePolicyAdapter skips RBAC — the caller
  is responsible for including all required PDPs.
- DPoP binding: dpop_result.agent_id must equal actor_token sub (or subject
  agent user_id for subject-only flows). Key registration must use the same
  id as the JWT sub for the binding to be enforceable.
- principal_kind: tokens with a non-null unknown principal_kind are rejected;
  missing principal_kind defaults to "human" for backward compatibility.

Usage:
    orchestrator = ACPOrchestrator(
        broker=MyBrokerAdapter(),
        policy_pipeline=[RBACPolicyAdapter(...), ScopePolicyAdapter(...)],
        audit=MemoryAuditAdapter(),
        signing_key="shared-hs256-key",
        token_exchange=RFC8693TokenExchangeAdapter(...),
        dpop_validator=StrictDPoPValidator(...),
        auth=JWTAuthAdapter(...),  # optional — use when auth port is already wired
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

import dataclasses
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Tuple

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
from swarm_auth.ports.auth_port import AuthenticationPort
from swarm_auth.ports.credential_broker_port import (
    CredentialBrokerPort,
    ProviderCredential,
    ToolRequest,
)
from swarm_auth.ports.dpop_validator_port import DPoPProof, DPoPValidatorPort
from swarm_auth.ports.policy_port import Decision, PolicyDecisionPoint
from swarm_auth.ports.token_exchange_port import (
    DelegationType,
    TokenExchangePort,
    TokenExchangeRequest,
    TokenType,
)

_ALGORITHM = "HS256"
_KNOWN_PRINCIPAL_KINDS = frozenset({"human", "agent"})


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
    ACP pipeline: authenticate → DPoP → exchange → policy pipeline → broker → audit.

    Constructor requirements:
        broker:          MANDATORY — all credential material flows through it
        policy_pipeline: MANDATORY — list of PDPs, all evaluated (RBAC first,
                         then scope). Empty list → every request is denied.
        audit:           MANDATORY — every allow and deny is logged
        signing_key:     MANDATORY — used to decode subject/actor tokens (HS256)
                         when auth port is not wired
        token_exchange:  optional — wire RFC8693TokenExchangeAdapter for delegation
        dpop_validator:  optional — wire StrictDPoPValidator for DPoP-bound tokens
        auth:            optional — wire AuthenticationPort to delegate principal
                         construction to the canonical adapter

    Policy pipeline semantics:
        All PDPs in policy_pipeline are evaluated in order. The first DENY
        short-circuits and the request is denied. Pass [RBACPolicyAdapter(),
        ScopePolicyAdapter(...)] to enforce RBAC ∩ scope.

    ADR-026 Rule 6: ACPOrchestrator.request_credential() never instantiates
    ProviderCredential. It only returns the instance from broker.vend_credential().
    """

    def __init__(
        self,
        broker: CredentialBrokerPort,
        policy_pipeline: Sequence[PolicyDecisionPoint],
        audit: AuditPort,
        signing_key: str,
        token_exchange: Optional[TokenExchangePort] = None,
        dpop_validator: Optional[DPoPValidatorPort] = None,
        auth: Optional[AuthenticationPort] = None,
    ) -> None:
        self._broker = broker
        self._policy_pipeline = list(policy_pipeline)
        self._audit = audit
        self._signing_key = signing_key
        self._token_exchange = token_exchange
        self._dpop_validator = dpop_validator
        self._auth = auth

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def request_credential(self, request: DelegatedCredentialRequest) -> CredentialResponse:
        """
        Run the ACP pipeline and return a ProviderCredential on success.

        Returns CredentialResponse with error populated on any failure —
        does not raise for expected validation failures.
        """
        # Step 1: authenticate subject_token → Principal
        principal, err = self._authenticate(request.subject_token)
        if err:
            self._emit_deny("<unknown>", "human", err, request.tool_request)
            return CredentialResponse(credential=None, error="invalid_request", error_description=err)

        principal_kind = principal.kind()

        # Step 2: DPoP validation (optional port)
        dpop_result = None
        if request.dpop_proof is not None:
            if self._dpop_validator is None:
                reason = "DPoP proof provided but dpop_validator port not wired"
                self._emit_deny(principal.user_id, principal_kind, reason, request.tool_request)
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
                self._emit_deny(principal.user_id, principal_kind, reason, request.tool_request)
                return CredentialResponse(credential=None, error="invalid_dpop_proof", error_description=dpop_result.error_description)

            # Step 2b: bind DPoP agent_id to actor_token subject or subject agent
            # (RFC 9449 §7.1: the DPoP key must belong to the proximate actor)
            binding_err = self._check_dpop_binding(dpop_result.agent_id, request, principal)
            if binding_err:
                self._emit_deny(principal.user_id, principal_kind, binding_err, request.tool_request)
                return CredentialResponse(credential=None, error="invalid_dpop_proof", error_description=binding_err)

        # Step 3: token exchange — build act claim from delegation (optional port)
        act_claim = None
        if request.actor_token is not None:
            if self._token_exchange is None:
                reason = "actor_token provided but token_exchange port not wired"
                self._emit_deny(principal.user_id, principal_kind, reason, request.tool_request)
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
                self._emit_deny(principal.user_id, principal_kind, reason, request.tool_request)
                return CredentialResponse(
                    credential=None,
                    error=exchange_resp.error,
                    error_description=exchange_resp.error_description,
                )
            act_claim = exchange_resp.act_claim

        # Step 4: policy pipeline — ALL PDPs must ALLOW (first DENY short-circuits)
        action, resource = self._parse_action_resource(request.tool_request)
        for pdp in self._policy_pipeline:
            decision = pdp.evaluate(principal, action, resource)
            if decision.decision != Decision.ALLOW:
                reason = decision.reason or "policy pipeline denied"
                self._emit_deny(
                    principal.user_id, principal_kind, reason, request.tool_request,
                    act_claim=act_claim,
                )
                return CredentialResponse(credential=None, error="access_denied", error_description=reason)

        # Step 5: enrich ToolRequest with actor-chain and principal context
        # Brokers may use these fields for session naming, CloudTrail tagging,
        # or fine-grained STS policy injection (ADR-027 Gap 3).
        delegation_ctx: Dict[str, Any] = {
            "principal_kind": principal_kind,
            "originating_principal_id": principal.user_id,
        }
        if act_claim is not None:
            delegation_ctx["actor_chain"] = act_claim
        enriched_request = dataclasses.replace(
            request.tool_request,
            principal_id=principal.user_id,
            scope_restrictions={
                **(request.tool_request.scope_restrictions or {}),
                **delegation_ctx,
            },
        )

        # Step 6: broker call (ADR-026 Rule 6 — only source of ProviderCredential)
        try:
            credential = self._broker.vend_credential(principal, enriched_request)
        except Exception as exc:
            reason = f"broker_error: {exc}"
            self._emit_deny(
                principal.user_id, principal_kind, reason, request.tool_request,
                act_claim=act_claim,
            )
            return CredentialResponse(credential=None, error="server_error", error_description=str(exc))

        # Step 7: emit ALLOW audit event
        self._emit_allow(principal.user_id, principal_kind, request.tool_request, act_claim=act_claim)
        return CredentialResponse(credential=credential)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _authenticate(self, token: str) -> Tuple[Optional[Principal], Optional[str]]:
        """
        Authenticate a subject_token and return the matching Principal.

        Uses AuthenticationPort when wired; falls back to direct HS256 decode.
        Returns (principal, None) on success, (None, error_str) on failure.
        """
        if self._auth is not None:
            try:
                principal = self._auth.authenticate(token)
                if principal is None:
                    return None, "subject_token is invalid or expired"
                return principal, None
            except Exception as exc:
                return None, f"subject_token authentication failed: {exc}"

        # Direct decode fallback (no AuthenticationPort wired)
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

        principal_kind = claims.get("principal_kind")
        if principal_kind is not None and principal_kind not in _KNOWN_PRINCIPAL_KINDS:
            return None, (
                f"subject_token has unknown principal_kind: {principal_kind!r}. "
                f"Must be one of: {sorted(_KNOWN_PRINCIPAL_KINDS)}"
            )
        if principal_kind is None:
            principal_kind = "human"  # backward compat: tokens without discriminator

        role_str = claims.get("role")
        try:
            role = UserRole(role_str) if role_str else (
                UserRole.GUEST if principal_kind == "human" else UserRole.SERVICE
            )
        except ValueError:
            role = UserRole.GUEST if principal_kind == "human" else UserRole.SERVICE

        if principal_kind == "agent":
            agent_type_str = claims.get("agent_type", "service")
            try:
                agent_type = AgentType(agent_type_str)
            except ValueError:
                agent_type = AgentType.SERVICE
            return AgentIdentity(
                user_id=sub,
                username=sub,
                role=role,
                agent_type=agent_type,
            ), None
        else:
            return HumanUser(user_id=sub, username=sub, role=role), None

    def _decode_sub(self, token: str) -> Optional[str]:
        """
        Extract the 'sub' claim from a JWT without building a Principal.
        Used for DPoP binding checks against actor_token.
        """
        try:
            claims = pyjwt.decode(
                token,
                self._signing_key,
                algorithms=[_ALGORITHM],
                options={"verify_aud": False},
            )
            return claims.get("sub")
        except Exception:
            return None

    def _check_dpop_binding(
        self,
        dpop_agent_id: Optional[str],
        request: DelegatedCredentialRequest,
        principal: Principal,
    ) -> Optional[str]:
        """
        Verify DPoP proof is bound to the proximate actor (RFC 9449 §7.1).

        Returns None if binding is valid, error string if invalid.
        Binding is only enforced when dpop_agent_id is non-None (i.e., a
        registered key was found). If dpop_agent_id is None the validator
        returned KEY_NOT_FOUND — that error already denied the request.
        """
        if dpop_agent_id is None:
            return None  # key lookup already failed upstream

        if request.actor_token is not None:
            actor_sub = self._decode_sub(request.actor_token)
            if not actor_sub:
                return (
                    "dpop_agent_mismatch: actor_token sub claim is missing or undecodable; "
                    "cannot bind DPoP proof to an anonymous actor (RFC 9449 §7.1)"
                )
            if dpop_agent_id != actor_sub:
                return (
                    f"dpop_agent_mismatch: DPoP proof belongs to agent {dpop_agent_id!r} "
                    f"but actor_token subject is {actor_sub!r} (RFC 9449 §7.1)"
                )
        elif isinstance(principal, AgentIdentity):
            if dpop_agent_id != principal.user_id:
                return (
                    f"dpop_agent_mismatch: DPoP proof belongs to agent {dpop_agent_id!r} "
                    f"but subject agent is {principal.user_id!r} (RFC 9449 §7.1)"
                )
        return None

    def _parse_action_resource(self, tool_request: ToolRequest):
        """
        Build Action and Resource from a ToolRequest.

        ToolRequest.action uses provider-native notation:
          AWS:    "s3:PutObject"   → resource_type="s3",   verb="PutObject"
          Others: "chat.generate"  → resource_type="chat", verb="generate"
        """
        from swarm_auth.ports.policy_port import Action, Resource

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
        self,
        principal_id: str,
        principal_kind: str,
        tool_request: ToolRequest,
        *,
        act_claim: Optional[dict] = None,
    ) -> None:
        self._audit.emit(AuditEvent(
            event_type=AuditEventType.CREDENTIAL_VENDED,
            principal_id=principal_id,
            provider=tool_request.provider.value,
            action=tool_request.action,
            resource=tool_request.resource,
            actor_chain=self._make_actor_chain_snapshot(principal_id, act_claim),
            metadata={"principal_kind": principal_kind},
        ))

    def _emit_deny(
        self,
        principal_id: str,
        principal_kind: str,
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
            metadata={"principal_kind": principal_kind},
        ))
