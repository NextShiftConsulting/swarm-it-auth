"""
Policy Decision Point (PDP) Port - Fine-grained authorization.

Tool-centric authorization for agent systems:
- Actions: llm.generate, aws.s3.put, gcp.storage.read, etc.
- Resources: bucket, dataset, project, model
- Obligations: logging, rate limits, budget constraints
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from enum import Enum


class Decision(Enum):
    """Authorization decision."""
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class Action:
    """
    Capability-based action.

    Examples:
    - llm.generate
    - aws.s3.put
    - gcp.storage.read
    - openai.files.upload
    - hf.inference
    """
    verb: str           # generate, put, read, upload, inference
    provider: str       # aws, gcp, openai, hf, anthropic
    resource_type: str  # s3, storage, files, model


@dataclass
class Resource:
    """
    Resource being accessed.

    Examples:
    - s3://bucket/prefix
    - gs://bucket/path
    - openai/project-123/files
    - hf/model/org/model-name
    """
    provider: str
    resource_type: str
    identifier: str
    attributes: Dict[str, Any]  # region, org, project, etc.


@dataclass
class PolicyContext:
    """
    Additional context for policy evaluation.

    Used for dynamic rules based on time, location, budget, etc.
    """
    timestamp: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    cost_estimate: Optional[float] = None  # Estimated cost of operation
    token_estimate: Optional[int] = None   # Estimated tokens (for LLMs)


@dataclass
class PolicyDecision:
    """
    Authorization decision with obligations and constraints.
    """
    decision: Decision
    reason: str

    # Obligations (must be enforced)
    must_log: bool = True
    max_tokens: Optional[int] = None
    max_cost: Optional[float] = None
    rate_limit: Optional[Dict[str, int]] = None  # {per_minute: 10, per_hour: 100}

    # Constraints (narrow the permission)
    allowed_regions: Optional[List[str]] = None
    allowed_projects: Optional[List[str]] = None
    read_only: bool = False
    time_window: Optional[Dict[str, str]] = None  # {start: "09:00", end: "17:00"}

    # Audit
    policy_id: Optional[str] = None
    evaluated_rules: List[str] = None


class PolicyDecisionPoint(ABC):
    """
    Port: Policy Decision Point for fine-grained authorization.

    Evaluates whether a Principal can perform an Action on a Resource.
    Returns not just allow/deny but also obligations and constraints.
    """

    @abstractmethod
    def evaluate(
        self,
        principal: "User",  # From swarm_auth.domain.user
        action: Action,
        resource: Resource,
        context: Optional[PolicyContext] = None,
    ) -> PolicyDecision:
        """
        Evaluate authorization policy.

        Args:
            principal: Authenticated user/agent
            action: Capability being requested
            resource: Resource being accessed
            context: Additional context for evaluation

        Returns:
            PolicyDecision with allow/deny + obligations/constraints

        Example:
            decision = pdp.evaluate(
                principal=user,
                action=Action(verb="generate", provider="openai", resource_type="chat"),
                resource=Resource(provider="openai", resource_type="project",
                                identifier="proj-123", attributes={}),
                context=PolicyContext(timestamp=now, token_estimate=1000)
            )

            if decision.decision == Decision.ALLOW:
                # Check obligations
                if decision.max_tokens and tokens > decision.max_tokens:
                    raise TooManyTokensError()
                # Proceed with call
        """
        pass

    @abstractmethod
    def batch_evaluate(
        self,
        principal: "User",
        requests: List[tuple[Action, Resource]],
        context: Optional[PolicyContext] = None,
    ) -> List[PolicyDecision]:
        """
        Evaluate multiple authorization requests at once.

        Useful for agents planning multi-step workflows.

        Args:
            principal: Authenticated user/agent
            requests: List of (action, resource) tuples
            context: Shared context

        Returns:
            List of decisions (same order as requests)
        """
        pass

    @abstractmethod
    def get_allowed_actions(
        self,
        principal: "User",
        resource: Resource,
    ) -> List[Action]:
        """
        Get all actions the principal can perform on a resource.

        Args:
            principal: Authenticated user/agent
            resource: Resource to check

        Returns:
            List of allowed actions
        """
        pass
