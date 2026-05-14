"""
CompositePDP — AND-composition of multiple PolicyDecisionPoints.

ADR-027 Stage 8. Closes Gap 3: makes RBAC ∩ scope self-documenting
and guards against callers accidentally wiring scope-only pipelines.

All PDPs are evaluated in order. The first DENY short-circuits and is
returned immediately. Only when all PDPs allow does the composite return
ALLOW.

Usage:
    from swarm_auth.ports.composite_pdp import CompositePDP, make_acp_pipeline

    # Standard RBAC ∩ scope pipeline
    pipeline = make_acp_pipeline(
        rbac=RBACPolicyAdapter(role=principal.role),
        scope=ScopePolicyAdapter(constraints_path="scope_constraints.yaml"),
    )

    # Pass to ACPOrchestrator as a single PDP
    orchestrator = ACPOrchestrator(
        policy_pipeline=[pipeline],
        ...
    )

    # Or directly
    decision = pipeline.evaluate(principal, action, resource)
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from swarm_auth.domain.principal import Principal
from swarm_auth.ports.policy_port import (
    Action,
    Decision,
    PolicyContext,
    PolicyDecision,
    PolicyDecisionPoint,
    Resource,
)


class CompositePDP(PolicyDecisionPoint):
    """
    AND-composition of PolicyDecisionPoints.

    Evaluates all PDPs in insertion order. First DENY short-circuits and
    is returned with its reason intact. If all PDPs allow, returns ALLOW.

    Empty pipeline → DENY (fail-closed). Pass at least one PDP.
    ACPOrchestrator also raises ValueError at construction when given an
    empty pipeline, so this path only triggers when CompositePDP is used
    standalone outside the orchestrator.

    Args:
        pdps: Sequence of PDPs to evaluate in order. Typically
              [RBACPolicyAdapter(...), ScopePolicyAdapter(...)].
    """

    def __init__(self, pdps: Sequence[PolicyDecisionPoint]) -> None:
        self._pdps = list(pdps)

    # ------------------------------------------------------------------
    # PolicyDecisionPoint interface
    # ------------------------------------------------------------------

    def evaluate(
        self,
        principal: Principal,
        action: Action,
        resource: Resource,
        context: Optional[PolicyContext] = None,
    ) -> PolicyDecision:
        """Evaluate all PDPs; return first DENY or final ALLOW.

        Empty pipeline → DENY (fail-closed). Pass at least one PDP.
        """
        if not self._pdps:
            return PolicyDecision(
                decision=Decision.DENY,
                reason="empty policy pipeline: no PDPs configured — denying by default",
            )
        for pdp in self._pdps:
            decision = pdp.evaluate(principal, action, resource, context)
            if decision.decision != Decision.ALLOW:
                return decision
        return PolicyDecision(
            decision=Decision.ALLOW,
            reason="all policy checks passed",
        )

    def batch_evaluate(
        self,
        principal: Principal,
        actions_resources: Sequence,
        context: Optional[PolicyContext] = None,
    ) -> List[PolicyDecision]:
        """Evaluate (action, resource) pairs in sequence."""
        return [self.evaluate(principal, a, r, context) for a, r in actions_resources]

    def get_allowed_actions(
        self,
        principal: Principal,
        resource: Resource,
        context: Optional[PolicyContext] = None,
    ) -> List[Action]:
        """
        Return actions allowed by ALL PDPs in the composition (intersection).

        Uses PDP[0] as the candidate set, then filters each candidate
        through the remaining PDPs.
        """
        if not self._pdps:
            return []
        candidates = self._pdps[0].get_allowed_actions(principal, resource, context)
        if len(self._pdps) == 1:
            return candidates
        result = []
        for action in candidates:
            if all(
                pdp.evaluate(principal, action, resource, context).decision == Decision.ALLOW
                for pdp in self._pdps[1:]
            ):
                result.append(action)
        return result


def make_acp_pipeline(
    rbac: PolicyDecisionPoint,
    scope: PolicyDecisionPoint,
) -> CompositePDP:
    """
    Create the standard RBAC ∩ scope pipeline.

    Evaluates RBAC first (role-based access), then scope (tool/resource
    constraints from scope_constraints.yaml). Both must ALLOW.

    Args:
        rbac:  RBACPolicyAdapter (or equivalent) — role-based check
        scope: ScopePolicyAdapter (or equivalent) — tool scope check

    Returns:
        CompositePDP([rbac, scope])
    """
    return CompositePDP([rbac, scope])
