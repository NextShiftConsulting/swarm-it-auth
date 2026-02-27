"""
RBAC Policy Adapter - Role-based policy decisions.

Maps user roles to allowed actions on resources.
Good starting point before graduating to ABAC or OPA.
"""

from typing import Dict, Any, List, Optional, Set
from swarm_auth.ports.policy_port import (
    PolicyDecisionPoint,
    Action,
    Resource,
    PolicyContext,
    PolicyDecision,
    Decision,
)
from swarm_auth.domain.user import User, UserRole


class RBACPolicyAdapter(PolicyDecisionPoint):
    """
    Role-Based Access Control policy adapter.

    Maps roles to capabilities:
    - ADMIN: all actions
    - DEVELOPER: llm.*, aws.s3.*, gcp.storage.* (read/write)
    - SERVICE: llm.generate, aws.s3.get (read-only for non-LLM)
    - AUDITOR: *.read (read-only everything)
    - GUEST: llm.generate (limited)

    Extensible via policy configuration.
    """

    def __init__(self, policy_config: Optional[Dict[str, Any]] = None):
        """
        Initialize RBAC policy.

        Args:
            policy_config: Optional policy overrides
        """
        self._config = policy_config or {}
        self._init_default_policies()

    def _init_default_policies(self):
        """Initialize default role-to-capability mappings."""
        self._role_capabilities: Dict[UserRole, Set[str]] = {
            UserRole.ADMIN: {"*"},  # All capabilities
            UserRole.DEVELOPER: {
                # LLM providers (format: provider.resource_type.verb)
                "openai.chat.generate",
                "openai.embed.create",
                "openai.files.upload",
                "anthropic.messages.create",
                "huggingface.models.inference",
                # AWS (format: aws.resource_type.verb)
                "aws.s3.get",
                "aws.s3.put",
                "aws.s3.list",
                "aws.dynamodb.read",
                "aws.dynamodb.write",
                # GCP (format: gcp.resource_type.verb)
                "gcp.storage.read",
                "gcp.storage.write",
                "gcp.bigquery.read",
            },
            UserRole.SERVICE: {
                # LLM providers (read-only equivalent)
                "openai.chat.generate",
                "openai.embed.create",
                "anthropic.messages.create",
                "huggingface.models.inference",
                # AWS (read-only)
                "aws.s3.get",
                "aws.dynamodb.read",
                # GCP (read-only)
                "gcp.storage.read",
                "gcp.bigquery.read",
            },
            UserRole.AUDITOR: {
                "*.*.read",  # Read-only everything
                "aws.s3.get",
                "aws.dynamodb.read",
                "aws.logs.read",
                "gcp.storage.read",
            },
            UserRole.GUEST: {
                # Limited LLM access only
                "openai.chat.generate",
                "anthropic.messages.create",
            },
        }

        # Budget limits by role (max cost per hour)
        self._role_budgets: Dict[UserRole, float] = {
            UserRole.ADMIN: float("inf"),
            UserRole.DEVELOPER: 100.0,  # $100/hour
            UserRole.SERVICE: 10.0,     # $10/hour
            UserRole.AUDITOR: 1.0,      # $1/hour (minimal)
            UserRole.GUEST: 0.1,        # $0.10/hour
        }

        # Token limits by role (per request)
        self._role_token_limits: Dict[UserRole, int] = {
            UserRole.ADMIN: 100000,
            UserRole.DEVELOPER: 10000,
            UserRole.SERVICE: 5000,
            UserRole.AUDITOR: 1000,
            UserRole.GUEST: 500,
        }

    def evaluate(
        self,
        principal: User,
        action: Action,
        resource: Resource,
        context: Optional[PolicyContext] = None,
    ) -> PolicyDecision:
        """Evaluate RBAC policy."""

        # Build action string
        action_str = f"{action.provider}.{action.resource_type}.{action.verb}"

        # Check if role has capability
        capabilities = self._role_capabilities.get(principal.role, set())

        # Check wildcard
        if "*" in capabilities:
            return self._allow_decision(principal, action_str, context)

        # Check exact match
        if action_str in capabilities:
            return self._allow_decision(principal, action_str, context)

        # Check pattern match (e.g., "*.read")
        for cap in capabilities:
            if self._matches_pattern(action_str, cap):
                return self._allow_decision(principal, action_str, context)

        # Deny by default
        return PolicyDecision(
            decision=Decision.DENY,
            reason=f"Role {principal.role.value} not authorized for {action_str}",
        )

    def _allow_decision(
        self,
        principal: User,
        action_str: str,
        context: Optional[PolicyContext],
    ) -> PolicyDecision:
        """Build allow decision with obligations."""
        role = principal.role

        # Get budget limits
        max_cost = self._role_budgets.get(role, 0.0)
        max_tokens = self._role_token_limits.get(role, 1000)

        # Check if request exceeds limits
        if context:
            if context.cost_estimate and context.cost_estimate > max_cost:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason=f"Cost estimate ${context.cost_estimate} exceeds budget ${max_cost}",
                )

            if context.token_estimate and context.token_estimate > max_tokens:
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason=f"Token estimate {context.token_estimate} exceeds limit {max_tokens}",
                )

        return PolicyDecision(
            decision=Decision.ALLOW,
            reason=f"Role {role.value} authorized for {action_str}",
            must_log=True,
            max_tokens=max_tokens,
            max_cost=max_cost,
            rate_limit={"per_minute": 60, "per_hour": 1000},
        )

    def batch_evaluate(
        self,
        principal: User,
        requests: List[tuple[Action, Resource]],
        context: Optional[PolicyContext] = None,
    ) -> List[PolicyDecision]:
        """Evaluate multiple requests."""
        return [
            self.evaluate(principal, action, resource, context)
            for action, resource in requests
        ]

    def get_allowed_actions(
        self,
        principal: User,
        resource: Resource,
    ) -> List[Action]:
        """Get allowed actions for principal on resource."""
        capabilities = self._role_capabilities.get(principal.role, set())

        actions = []
        for cap in capabilities:
            if cap == "*":
                # All actions allowed
                actions.append(Action(verb="*", provider="*", resource_type="*"))
            else:
                parts = cap.split(".")
                if len(parts) >= 3:
                    provider, resource_type, verb = parts[0], parts[1], parts[2]
                    actions.append(Action(
                        verb=verb,
                        provider=provider,
                        resource_type=resource_type,
                    ))

        return actions

    @staticmethod
    def _matches_pattern(action: str, pattern: str) -> bool:
        """Check if action matches pattern (supports * wildcard)."""
        if pattern == "*":
            return True

        action_parts = action.split(".")
        pattern_parts = pattern.split(".")

        if len(action_parts) != len(pattern_parts):
            return False

        for a, p in zip(action_parts, pattern_parts):
            if p != "*" and a != p:
                return False

        return True
