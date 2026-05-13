"""
User domain model — backward compatibility shim (ADR-028 Stage 1).

UserRole: re-exported from domain/roles.py (canonical location).
          All adapters doing `from swarm_auth.domain.user import UserRole`
          continue to work unchanged.

User: deprecated alias for HumanUser.
      All adapters doing `from swarm_auth.domain.user import User`
      continue to work unchanged. User(...) constructs a HumanUser.
      Replace with HumanUser in new code.

Scheduled removal: Stage 3 (after jwt_auth.py is updated to use Principal).
"""

from swarm_auth.domain.roles import UserRole  # noqa: F401 — re-export for adapters
from swarm_auth.domain.human_user import HumanUser  # noqa: F401

# Deprecated alias. Use HumanUser directly for new code.
User = HumanUser

__all__ = ["User", "UserRole"]
