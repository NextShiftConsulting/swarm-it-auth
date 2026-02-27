"""
Ports - Interfaces for authentication, sessions, credentials, and authorization.

Hexagonal architecture: These define WHAT we need, not HOW.
Adapters provide the HOW.
"""

from swarm_auth.ports.auth_port import AuthenticationPort
from swarm_auth.ports.session_port import SessionPort
from swarm_auth.ports.credential_port import CredentialPort
from swarm_auth.ports.policy_port import PolicyDecisionPoint, Action, Resource, PolicyContext, PolicyDecision, Decision
from swarm_auth.ports.credential_broker_port import CredentialBrokerPort, ProviderCredential, ToolRequest, ProviderType

__all__ = [
    # Authentication & Sessions
    "AuthenticationPort",
    "SessionPort",
    "CredentialPort",
    # Authorization (PDP)
    "PolicyDecisionPoint",
    "Action",
    "Resource",
    "PolicyContext",
    "PolicyDecision",
    "Decision",
    # Credential Broker (outbound)
    "CredentialBrokerPort",
    "ProviderCredential",
    "ToolRequest",
    "ProviderType",
]
