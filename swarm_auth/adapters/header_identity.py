"""
Header Identity Adapter - Trust identity headers from gateway.

Use this when you have OAuth2-Proxy or Envoy handling auth.
Your service trusts the gateway to validate identity.
"""

from typing import Optional
from swarm_auth.ports.auth_port import AuthenticationPort
from swarm_auth.domain.user import User, UserRole


class HeaderIdentityAdapter(AuthenticationPort):
    """
    Trust identity headers from auth gateway (OAuth2-Proxy, Envoy).

    Expected headers:
    - X-Auth-Request-User: user ID
    - X-Auth-Request-Email: email
    - X-Auth-Request-Groups: comma-separated roles/groups

    SECURITY: Only use this behind a trusted gateway that strips
    these headers from external requests.
    """

    def __init__(
        self,
        user_header: str = "X-Auth-Request-User",
        email_header: str = "X-Auth-Request-Email",
        groups_header: str = "X-Auth-Request-Groups",
        default_role: UserRole = UserRole.DEVELOPER,
    ):
        """
        Initialize header identity adapter.

        Args:
            user_header: Header containing user ID
            email_header: Header containing email
            groups_header: Header containing comma-separated groups
            default_role: Default role if groups not mapped
        """
        self._user_header = user_header
        self._email_header = email_header
        self._groups_header = groups_header
        self._default_role = default_role

        # Map groups to roles
        self._group_to_role = {
            "admin": UserRole.ADMIN,
            "admins": UserRole.ADMIN,
            "developer": UserRole.DEVELOPER,
            "developers": UserRole.DEVELOPER,
            "auditor": UserRole.AUDITOR,
            "auditors": UserRole.AUDITOR,
            "service": UserRole.SERVICE,
            "guest": UserRole.GUEST,
        }

    def authenticate(self, token: str) -> Optional[User]:
        """
        This method is not used for header-based auth.
        Use verify_request() instead.
        """
        return None

    def verify_request(self, headers: dict) -> Optional[User]:
        """
        Verify request and extract user from headers.

        Args:
            headers: Request headers dict

        Returns:
            User if headers present, None otherwise
        """
        user_id = headers.get(self._user_header)
        if not user_id:
            return None

        email = headers.get(self._email_header)
        groups_str = headers.get(self._groups_header, "")

        # Parse groups
        groups = [g.strip() for g in groups_str.split(",") if g.strip()]

        # Map first matching group to role
        role = self._default_role
        for group in groups:
            if group.lower() in self._group_to_role:
                role = self._group_to_role[group.lower()]
                break

        return User(
            user_id=user_id,
            username=user_id,
            email=email,
            role=role,
            is_active=True,
        )

    def create_token(self, user: User, expires_in: int = 3600) -> str:
        """Not supported for header-based auth."""
        raise NotImplementedError(
            "Header adapter doesn't create tokens. Use gateway (OAuth2-Proxy)."
        )

    def verify_token(self, token: str) -> bool:
        """Not supported for header-based auth."""
        return False

    def revoke_token(self, token: str) -> bool:
        """Not supported for header-based auth."""
        return False
