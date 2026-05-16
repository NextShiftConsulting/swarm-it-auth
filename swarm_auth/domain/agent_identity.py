"""
AgentIdentity, AgentType, ActorChain — agentic identity domain types.

ADR-028 SD-1, SD-2:
- AgentIdentity.kind() == "agent"
- AgentType has no HUMAN value (human identity is expressed by HumanUser)
- ActorChain is the RFC 8693 'act' claim chain
- MAX_ACT_CHAIN_DEPTH guards against malicious/buggy deep delegation tokens

Canonical import path:
    from swarm_auth.domain.agent_identity import ActorChain, AgentIdentity, AgentType

ACP re-exports ActorChain from acp/__init__.py for callers that only
know the ACP surface. The domain is always authoritative.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from swarm_auth.domain.principal import Principal
from swarm_auth.domain.roles import UserRole

MAX_ACT_CHAIN_DEPTH: int = 10
"""Maximum depth of an RFC 8693 act claim chain.

RFC 8693 does not define a limit. This is a production guardrail against
malicious or buggy tokens with unbounded recursion. Chains deeper than
this value are rejected by ActorChain.from_jwt_claim() with ValueError.
"""


class AgentType(Enum):
    """Type of agent — what role it plays in the agentic workflow.

    HUMAN is intentionally absent: human identity is expressed by HumanUser,
    not by AgentIdentity. Instantiating AgentIdentity(agent_type=AgentType.HUMAN)
    would defeat the Principal split introduced in ADR-028 SD-1.
    """
    ASSISTANT = "assistant"
    TOOL = "tool"
    ORCHESTRATOR = "orchestrator"
    SERVICE = "service"
    BOT = "bot"


@dataclass
class AgentIdentity(Principal):
    """A machine-to-machine account: assistant, tool, orchestrator, service, or bot.

    Does NOT hold email or last_login — use HumanUser for human identities.
    isinstance(p, AgentIdentity) replaces the deprecated is_service_account flag.
    """

    agent_type: AgentType = AgentType.SERVICE
    owning_team: Optional[str] = None
    parent_agent_id: Optional[str] = None       # direct parent in delegation chain
    sponsor_id: Optional[str] = None            # human who authorized this agent
    key_rotation_at: Optional[datetime] = None
    capability_skill_url: Optional[str] = None  # SKILL.md endpoint

    def kind(self) -> str:
        return "agent"

    def to_dict(self) -> Dict[str, Any]:
        base = super().to_dict()
        base.update({
            "agent_type": self.agent_type.value,
            "owning_team": self.owning_team,
            "parent_agent_id": self.parent_agent_id,
            "sponsor_id": self.sponsor_id,
            "is_service_account": True,  # deprecated field, compat with jwt_auth.py Stage 2
        })
        return base

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentIdentity":
        return cls(
            user_id=data["user_id"],
            username=data["username"],
            role=UserRole(data.get("role", "service")),
            is_active=data.get("is_active", True),
            metadata=data.get("metadata", {}),
            agent_type=AgentType(data.get("agent_type", "service")),
            owning_team=data.get("owning_team"),
            parent_agent_id=data.get("parent_agent_id"),
            sponsor_id=data.get("sponsor_id"),
        )


@dataclass
class ActorChain:
    """RFC 8693 'act' claim chain — audit-preserving delegation record.

    Chain direction (from outer to inner):
        ActorChain(sub="rudy", act=ActorChain(sub="orchestrator",
                                    act=ActorChain(sub="tool")))

    to_jwt_claim() produces:
        {"sub": "rudy", "act": {"sub": "orchestrator", "act": {"sub": "tool"}}}

    The outermost node (sub="rudy") is the ORIGINATING principal.
    The innermost node (sub="tool") is the PROXIMATE actor.
    This matches RFC 8693 §4.1: the act claim identifies the party acting
    on behalf of the subject.

    Depth is limited to MAX_ACT_CHAIN_DEPTH. from_jwt_claim() raises
    ValueError for chains that exceed this limit.
    """

    sub: str
    role: Optional[str] = None
    agent_type: Optional[str] = None
    act: Optional["ActorChain"] = None

    def to_jwt_claim(self) -> Dict[str, Any]:
        """Serialize to JWT-claim-shaped dict (RFC 8693 act claim)."""
        result: Dict[str, Any] = {"sub": self.sub}
        if self.role:
            result["role"] = self.role
        if self.agent_type:
            result["agent_type"] = self.agent_type
        if self.act is not None:
            result["act"] = self.act.to_jwt_claim()
        return result

    @classmethod
    def from_jwt_claim(cls, claim: Dict[str, Any], _depth: int = 0) -> "ActorChain":
        """Deserialize from JWT-claim-shaped dict.

        Args:
            claim: dict with at minimum {"sub": str}
            _depth: internal recursion counter — do not pass from call sites

        Raises:
            ValueError: if chain depth exceeds MAX_ACT_CHAIN_DEPTH
            KeyError: if "sub" is missing from claim
        """
        if _depth > MAX_ACT_CHAIN_DEPTH:
            raise ValueError(
                f"act chain depth {_depth} exceeds MAX_ACT_CHAIN_DEPTH={MAX_ACT_CHAIN_DEPTH}. "
                "Token may be malicious or the chain is misconfigured."
            )
        return cls(
            sub=claim["sub"],
            role=claim.get("role"),
            agent_type=claim.get("agent_type"),
            act=(
                cls.from_jwt_claim(claim["act"], _depth + 1)
                if "act" in claim
                else None
            ),
        )
