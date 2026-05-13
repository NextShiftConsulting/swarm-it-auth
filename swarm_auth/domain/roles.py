"""
User roles — canonical location for UserRole enum.

Moved here from domain/user.py to break the import cycle created by
the Principal/HumanUser/AgentIdentity hierarchy (ADR-028 Stage 1).

Backward compat: `from swarm_auth.domain.user import UserRole` still works
because user.py re-exports from here.
"""

from enum import Enum


class UserRole(Enum):
    """User roles for RBAC."""
    ADMIN = "admin"              # Full system access
    DEVELOPER = "developer"      # API access, can create API keys
    AUDITOR = "auditor"          # Read-only access to certificates
    SERVICE = "service"          # Machine-to-machine (M2M) account
    GUEST = "guest"              # Limited read access
