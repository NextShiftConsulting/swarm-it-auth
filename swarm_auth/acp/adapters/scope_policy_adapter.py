"""
Scope Policy Adapter — resource allow-list enforcement.

ADR-028 Stage 4 / ADR-027 Gap 2 (unvalidated ToolRequest.resource).

Enforces scope_constraints.yaml before any credential is vended. The deny
happens before the STS/OpenAI/Vault call — no provider is contacted on denial.

RBAC intersection rule:
    A request passes if and only if BOTH conditions hold:
    1. RBACPolicyAdapter.evaluate() returns ALLOW (role has the capability)
    2. ScopePolicyAdapter.validate() returns allowed=True (resource is in allow-list)

    ScopePolicyAdapter runs first. A scope-denied request never reaches RBAC or
    the provider. A RBAC-denied request never reaches the provider either, but
    that is enforced by the caller, not this adapter.

Usage:
    from swarm_auth.acp.adapters.scope_policy_adapter import (
        ScopePolicyAdapter,
        ScopeEnforcingBrokerAdapter,
        ScopePolicyDecision,
    )

    policy = ScopePolicyAdapter()          # loads bundled defaults
    # or:
    policy = ScopePolicyAdapter("/path/to/scope_constraints.yaml")

    # Standalone validation:
    decision = policy.validate(principal, tool_request)
    if not decision.allowed:
        raise PermissionDeniedError(decision.reason)

    # Decorator pattern (preferred — wraps any CredentialBrokerPort):
    enforced_broker = ScopeEnforcingBrokerAdapter(inner=aws_broker, scope_policy=policy)
    cred = enforced_broker.vend_credential(principal, tool_request)  # scope-gated

Stage 5 TODO:
- TODO(Stage 5): pass audit_port to ScopePolicyAdapter constructor (AuditPort ABC, Stage 5)
- TODO(Stage 5): emit AuditEvent on every decision (not just denials)
"""

import fnmatch
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

from swarm_auth.domain.principal import Principal
from swarm_auth.domain.agent_identity import AgentIdentity
from swarm_auth.ports.credential_broker_port import (
    CredentialBrokerPort,
    ProviderCredential,
    ProviderType,
    ToolRequest,
)
from swarm_auth.ports.policy_port import (
    PolicyDecisionPoint,
    Action,
    Resource,
    PolicyContext,
    PolicyDecision,
    Decision,
)

_DEFAULT_CONSTRAINTS_PATH = Path(__file__).parent.parent / "scope_constraints.yaml"


@dataclass
class ScopeConstraint:
    """One entry from scope_constraints.yaml."""
    id: str
    provider: str
    action_pattern: str
    allowed_resources: List[str]
    agent_types: Optional[List[str]] = None  # None means any principal type
    expires_at: Optional[datetime] = None
    read_only: bool = False


@dataclass
class ScopePolicyDecision:
    """Result of a scope policy validation check."""
    allowed: bool
    reason: str
    matched_constraint_id: Optional[str] = None
    matched_resource_pattern: Optional[str] = None


class ScopePolicyAdapter(PolicyDecisionPoint):
    """
    Validates ToolRequest.resource against scope_constraints.yaml before vending.

    Implements PolicyDecisionPoint so it can be composed with RBACPolicyAdapter
    in a standard PDP pipeline (RBAC ∩ ScopePolicy — both must ALLOW).

    The primary entry point is validate(principal, tool_request) which accepts a
    ToolRequest directly. The PDP interface evaluate(principal, action, resource)
    bridges from the abstract Action/Resource types to ToolRequest using the
    provider-native action-string convention:
      - AWS:  "{resource_type}:{verb}"  e.g. "s3:PutObject"
      - Others: "{resource_type}.{verb}" e.g. "chat.generate"

    Addresses ADR-027 Gap 2: ToolRequest.resource was previously unvalidated —
    any string could be passed as a resource identifier, bypassing the intended
    scope boundary.

    Resource matching uses fnmatch-style wildcards (same as shell glob):
      *  matches any sequence of characters (except path separators in some modes)
      ?  matches any single character

    Expiry check: constraints with expires_at in the past are treated as DENY.
    Agent type check: if constraint.agent_types is set, the principal must be an
    AgentIdentity whose agent_type.value is in the list.
    """

    def __init__(self, constraints_path: Optional[str] = None) -> None:
        path = Path(constraints_path) if constraints_path else _DEFAULT_CONSTRAINTS_PATH
        self._constraints: List[ScopeConstraint] = self._load(path)

    def _load(self, path: Path) -> List[ScopeConstraint]:
        if not _HAS_YAML:
            # PyYAML not installed — return empty list (no constraints = default-allow).
            # Stage 5 TODO: make yaml a hard dependency once AuditPort is wired.
            return []

        if not path.exists():
            return []

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        constraints = []
        for entry in data.get("constraints", []):
            expires_raw = entry.get("expires_at")
            expires_at = None
            if expires_raw:
                expires_at = datetime.fromisoformat(str(expires_raw).rstrip("Z")).replace(
                    tzinfo=timezone.utc
                )

            constraints.append(ScopeConstraint(
                id=entry["id"],
                provider=entry["provider"],
                action_pattern=entry["action_pattern"],
                allowed_resources=entry.get("allowed_resources", []),
                agent_types=entry.get("agent_types"),
                expires_at=expires_at,
                read_only=entry.get("read_only", False),
            ))

        return constraints

    def validate(
        self,
        principal: Principal,
        tool_request: ToolRequest,
    ) -> ScopePolicyDecision:
        """
        Validate that the requested resource is in the scope allow-list.

        Evaluation order:
        1. Find all constraints matching provider + action_pattern.
        2. For each matching constraint (in order):
           a. If expired, skip.
           b. If agent_types set and principal doesn't match, skip.
           c. If read_only and request is a write action, skip.
           d. If resource matches any allowed_resource pattern, return ALLOW.
        3. If no constraint matched: DENY.

        Args:
            principal: The authenticated principal making the request.
            tool_request: The tool/provider request to validate.

        Returns:
            ScopePolicyDecision with allowed=True/False and reason.
        """
        provider_val = tool_request.provider.value
        action = tool_request.action
        resource = tool_request.resource
        now = datetime.now(timezone.utc)

        matching_constraints = [
            c for c in self._constraints
            if c.provider == provider_val
            and fnmatch.fnmatch(action, c.action_pattern)
        ]

        if not matching_constraints:
            # No constraints defined for this provider+action — default DENY.
            # Fail-closed: unknown scope is not permitted.
            return ScopePolicyDecision(
                allowed=False,
                reason=(
                    f"No scope constraint defined for provider={provider_val!r} "
                    f"action={action!r}. Add an entry to scope_constraints.yaml."
                ),
            )

        for constraint in matching_constraints:
            # 1. Expiry check
            if constraint.expires_at and now >= constraint.expires_at:
                continue

            # 2. Agent type check
            if constraint.agent_types is not None:
                if not isinstance(principal, AgentIdentity):
                    continue
                if principal.agent_type.value not in constraint.agent_types:
                    continue

            # 3. Read-only check — deny write actions if constraint is read_only
            if constraint.read_only and self._is_write_action(action):
                continue

            # 4. Resource pattern match
            for pattern in constraint.allowed_resources:
                if fnmatch.fnmatch(resource, pattern):
                    return ScopePolicyDecision(
                        allowed=True,
                        reason=f"Resource matched constraint {constraint.id!r}, pattern {pattern!r}",
                        matched_constraint_id=constraint.id,
                        matched_resource_pattern=pattern,
                    )

        # No constraint allowed the resource
        return ScopePolicyDecision(
            allowed=False,
            reason=(
                f"Resource {resource!r} did not match any allowed pattern "
                f"for provider={provider_val!r} action={action!r}."
            ),
        )

    def validate_resource_indicator(self, resource: str, provider: str) -> bool:
        """
        RFC 8707 resource indicator check — is this resource URI valid for the provider?

        Simplified check: resource must match at least one allowed_resource pattern
        across any non-expired constraint for the given provider.
        Used by MCP token validation (Stage 7) to confirm the resource indicator
        in the token matches a known allowed resource.
        """
        now = datetime.now(timezone.utc)
        for constraint in self._constraints:
            if constraint.provider != provider:
                continue
            if constraint.expires_at and now >= constraint.expires_at:
                continue
            for pattern in constraint.allowed_resources:
                if fnmatch.fnmatch(resource, pattern):
                    return True
        return False

    def loaded_constraint_count(self) -> int:
        """Return number of loaded constraints. Useful for health checks."""
        return len(self._constraints)

    # ------------------------------------------------------------------
    # PolicyDecisionPoint interface (PDP composition with RBACPolicyAdapter)
    # ------------------------------------------------------------------

    def evaluate(
        self,
        principal: Principal,
        action: Action,
        resource: Resource,
        context: Optional[PolicyContext] = None,
    ) -> PolicyDecision:
        """
        Evaluate scope policy via the PolicyDecisionPoint interface.

        Bridges Action/Resource to ToolRequest using provider-native notation:
          - AWS:    "{resource_type}:{verb}"  matches yaml patterns like "s3:*"
          - Others: "{resource_type}.{verb}"  matches yaml patterns like "chat.*"

        Called by a PDP pipeline after RBAC evaluate(); both must return ALLOW.
        """
        try:
            provider_type = ProviderType(action.provider)
        except ValueError:
            return PolicyDecision(
                decision=Decision.DENY,
                reason=f"Unknown provider: {action.provider!r}. Add to ProviderType enum.",
                policy_id="scope-unknown-provider",
                evaluated_rules=[],
            )

        if action.provider == "aws":
            action_str = f"{action.resource_type}:{action.verb}"
        else:
            action_str = f"{action.resource_type}.{action.verb}"

        tool_request = ToolRequest(
            tool_name=f"{action.provider}_{action.resource_type}_{action.verb}",
            provider=provider_type,
            action=action_str,
            resource=resource.identifier,
        )

        scope_decision = self.validate(principal, tool_request)

        return PolicyDecision(
            decision=Decision.ALLOW if scope_decision.allowed else Decision.DENY,
            reason=scope_decision.reason,
            policy_id=scope_decision.matched_constraint_id,
            evaluated_rules=(
                [scope_decision.matched_constraint_id]
                if scope_decision.matched_constraint_id else []
            ),
        )

    def batch_evaluate(
        self,
        principal: Principal,
        requests: List[tuple],  # List[tuple[Action, Resource]]
        context: Optional[PolicyContext] = None,
    ) -> List[PolicyDecision]:
        """Evaluate multiple scope checks in order."""
        return [
            self.evaluate(principal, action, resource, context)
            for action, resource in requests
        ]

    def get_allowed_actions(
        self,
        principal: Principal,
        resource: Resource,
    ) -> List[Action]:
        """
        Return Action objects the principal may perform on the resource.

        Iterates non-expired, principal-applicable constraints for the given
        provider. Returns one Action per matching constraint, with the
        action_pattern decomposed into (resource_type, verb).
        """
        now = datetime.now(timezone.utc)
        allowed: List[Action] = []
        seen: set = set()

        for constraint in self._constraints:
            if constraint.provider != resource.provider:
                continue
            if constraint.expires_at and now >= constraint.expires_at:
                continue
            if constraint.agent_types is not None:
                if not isinstance(principal, AgentIdentity):
                    continue
                if principal.agent_type.value not in constraint.agent_types:
                    continue

            # Only yield if resource identifier matches at least one pattern
            resource_match = any(
                fnmatch.fnmatch(resource.identifier, pat)
                for pat in constraint.allowed_resources
            )
            if not resource_match:
                continue

            key = (constraint.provider, constraint.action_pattern)
            if key in seen:
                continue
            seen.add(key)

            # Decompose action_pattern into (resource_type, verb)
            pat = constraint.action_pattern
            if ":" in pat:
                resource_type, verb = pat.split(":", 1)
            elif "." in pat:
                resource_type, verb = pat.split(".", 1)
            else:
                resource_type, verb = "*", pat

            allowed.append(Action(
                verb=verb,
                provider=constraint.provider,
                resource_type=resource_type,
            ))

        return allowed

    @staticmethod
    def _is_write_action(action: str) -> bool:
        """Heuristic: identify write actions from their name."""
        write_keywords = (
            "Put", "Create", "Upload", "Write", "Delete", "Update",
            "Modify", "Post", "publish", "send",
        )
        return any(kw.lower() in action.lower() for kw in write_keywords)


class ScopeEnforcingBrokerAdapter(CredentialBrokerPort):
    """
    Decorator that adds scope policy enforcement to any CredentialBrokerPort.

    Wraps an existing broker and calls ScopePolicyAdapter.validate() before
    delegating to the inner broker. This is the preferred integration point:
    no existing broker adapter needs to be modified.

    Usage:
        aws_broker = AWSCredentialBroker(...)
        policy = ScopePolicyAdapter()
        safe_broker = ScopeEnforcingBrokerAdapter(inner=aws_broker, scope_policy=policy)

        # vend_credential will DENY before calling AWS STS if resource not in allow-list
        cred = safe_broker.vend_credential(principal, tool_request)

    Raises:
        PermissionError: if scope policy denies the request
    """

    def __init__(
        self,
        inner: CredentialBrokerPort,
        scope_policy: ScopePolicyAdapter,
    ) -> None:
        self._inner = inner
        self._scope_policy = scope_policy

    def vend_credential(
        self,
        principal: Principal,
        tool_request: ToolRequest,
    ) -> ProviderCredential:
        """Validate scope policy before delegating to inner broker."""
        decision = self._scope_policy.validate(principal, tool_request)
        if not decision.allowed:
            raise PermissionError(
                f"Scope policy denied credential request: {decision.reason}"
            )
        return self._inner.vend_credential(principal, tool_request)

    def revoke_credential(self, credential_id: str) -> bool:
        return self._inner.revoke_credential(credential_id)

    def list_active_credentials(
        self,
        principal: Principal,
        provider: Optional[ProviderType] = None,
    ) -> list:
        return self._inner.list_active_credentials(principal, provider)

    def validate_credential(self, credential: ProviderCredential) -> bool:
        return self._inner.validate_credential(credential)

    def refresh_credential(self, credential: ProviderCredential) -> ProviderCredential:
        return self._inner.refresh_credential(credential)
