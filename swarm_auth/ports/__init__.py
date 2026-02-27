"""
Ports - Interfaces for authentication, sessions, and credentials.

Hexagonal architecture: These define WHAT we need, not HOW.
Adapters provide the HOW.
"""

from swarm_auth.ports.auth_port import AuthenticationPort
from swarm_auth.ports.session_port import SessionPort
from swarm_auth.ports.credential_port import CredentialPort

__all__ = [
    "AuthenticationPort",
    "SessionPort",
    "CredentialPort",
]
