"""
OPA Policy Adapter - Graduate to this for multi-service policy.

Use Open Policy Agent for centralized policy decisions.
Works with Envoy ext_authz for service mesh authorization.
"""

from typing import Dict, Any, List, Optional
import httpx
from swarm_auth.ports.policy_port import (
    PolicyDecisionPoint,
    Action,
    Resource,
    PolicyContext,
    PolicyDecision,
    Decision,
)
from swarm_auth.domain.user import User


class OPAPolicyAdapter(PolicyDecisionPoint):
    """
    OPA-based policy decision point.

    Calls OPA server for policy evaluation using Rego rules.

    Setup:
    1. Deploy OPA server
    2. Load Rego policies
    3. Configure API endpoint

    Example Rego policy:
        package swarm.authz

        default allow = false

        allow {
            input.principal.role == "admin"
        }

        allow {
            input.principal.role == "developer"
            input.action.verb == "generate"
            input.action.provider == "openai"
        }
    """

    def __init__(
        self,
        opa_url: str = "http://localhost:8181",
        policy_path: str = "v1/data/swarm/authz",
    ):
        """
        Initialize OPA policy adapter.

        Args:
            opa_url: OPA server URL
            policy_path: Policy evaluation path
        """
        self._opa_url = opa_url.rstrip("/")
        self._policy_path = policy_path.lstrip("/")
        self._client = httpx.Client(base_url=self._opa_url, timeout=5.0)

    def evaluate(
        self,
        principal: User,
        action: Action,
        resource: Resource,
        context: Optional[PolicyContext] = None,
    ) -> PolicyDecision:
        """
        Evaluate policy via OPA.

        Sends input to OPA and interprets result.
        """
        # Build OPA input
        input_data = {
            "principal": {
                "user_id": principal.user_id,
                "username": principal.username,
                "role": principal.role.value,
                "email": principal.email,
            },
            "action": {
                "verb": action.verb,
                "provider": action.provider,
                "resource_type": action.resource_type,
            },
            "resource": {
                "provider": resource.provider,
                "resource_type": resource.resource_type,
                "identifier": resource.identifier,
                "attributes": resource.attributes,
            },
            "context": self._context_to_dict(context) if context else {},
        }

        # Call OPA
        try:
            response = self._client.post(
                f"/{self._policy_path}",
                json={"input": input_data},
            )
            response.raise_for_status()

            result = response.json()

            # Parse OPA response
            allow = result.get("result", {}).get("allow", False)
            obligations = result.get("result", {}).get("obligations", {})

            if allow:
                return PolicyDecision(
                    decision=Decision.ALLOW,
                    reason="OPA policy allowed",
                    must_log=obligations.get("must_log", True),
                    max_tokens=obligations.get("max_tokens"),
                    max_cost=obligations.get("max_cost"),
                    rate_limit=obligations.get("rate_limit"),
                )
            else:
                reason = result.get("result", {}).get("reason", "OPA policy denied")
                return PolicyDecision(
                    decision=Decision.DENY,
                    reason=reason,
                )

        except Exception as e:
            # Fail closed (deny on error)
            return PolicyDecision(
                decision=Decision.DENY,
                reason=f"OPA evaluation failed: {e}",
            )

    def batch_evaluate(
        self,
        principal: User,
        requests: List[tuple[Action, Resource]],
        context: Optional[PolicyContext] = None,
    ) -> List[PolicyDecision]:
        """Batch evaluate (call OPA for each - could optimize with batch API)."""
        return [
            self.evaluate(principal, action, resource, context)
            for action, resource in requests
        ]

    def get_allowed_actions(
        self,
        principal: User,
        resource: Resource,
    ) -> List[Action]:
        """
        Get allowed actions (requires OPA policy that lists actions).

        Not typically implemented - OPA is for allow/deny, not discovery.
        """
        return []

    @staticmethod
    def _context_to_dict(context: PolicyContext) -> Dict[str, Any]:
        """Convert PolicyContext to dict for OPA."""
        return {
            "timestamp": context.timestamp,
            "ip_address": context.ip_address,
            "user_agent": context.user_agent,
            "request_id": context.request_id,
            "cost_estimate": context.cost_estimate,
            "token_estimate": context.token_estimate,
        }
