"""
Integration tests for JWT authentication flow.
"""

import pytest
from swarm_auth import AuthClient, User, UserRole
from swarm_auth.adapters import JWTAuthAdapter, MemorySessionAdapter


class TestJWTAuthFlow:
    """Test complete JWT authentication workflow."""

    def setup_method(self):
        """Set up test fixtures."""
        self.auth = JWTAuthAdapter(secret="test-secret-key")
        self.sessions = MemorySessionAdapter()
        self.client = AuthClient(auth=self.auth, sessions=self.sessions)

    def test_login_and_verify(self):
        """Test login and token verification."""
        # Create user
        user = User(
            user_id="test_user",
            username="alice",
            role=UserRole.DEVELOPER,
            email="alice@test.com"
        )

        # Login
        result = self.client.login(user, ttl=3600)
        assert "token" in result
        assert "session" in result

        token = result["token"]

        # Verify token
        verified_user = self.client.verify(token)
        assert verified_user is not None
        assert verified_user.user_id == user.user_id
        assert verified_user.username == user.username
        assert verified_user.role == user.role

    def test_logout(self):
        """Test logout flow."""
        user = User(user_id="test_user", username="alice", role=UserRole.DEVELOPER)

        # Login
        result = self.client.login(user)
        token = result["token"]

        # Verify token works
        assert self.client.verify(token) is not None

        # Logout
        success = self.client.logout(token)
        assert success is True

        # Token should be invalid after logout
        assert self.client.verify(token) is None

    def test_session_management(self):
        """Test session creation and retrieval."""
        user = User(user_id="test_user", username="alice", role=UserRole.DEVELOPER)

        # Login creates session
        result = self.client.login(user, ttl=3600, metadata={"device": "mobile"})
        session_id = result["session"]["session_id"]

        # Get session
        session = self.client.get_session(session_id)
        assert session is not None
        assert session.user_id == user.user_id
        assert session.is_valid()
        assert session.metadata["device"] == "mobile"

    def test_session_extend(self):
        """Test session TTL extension."""
        user = User(user_id="test_user", username="alice", role=UserRole.DEVELOPER)

        # Create session
        result = self.client.login(user, ttl=3600)
        session_id = result["session"]["session_id"]

        session = self.client.get_session(session_id)
        original_expiry = session.expires_at

        # Extend session
        extended = self.client.extend_session(session_id, ttl=1800)
        assert extended is True

        # Check expiry updated
        session = self.client.get_session(session_id)
        assert session.expires_at > original_expiry

    def test_invalid_token(self):
        """Test handling of invalid tokens."""
        # Invalid token format
        assert self.client.verify("invalid_token") is None

        # Expired/nonexistent token
        assert self.client.verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid") is None

    def test_permissions(self):
        """Test role-based permissions."""
        # Developer can certify
        dev = User(user_id="dev", username="dev", role=UserRole.DEVELOPER)
        assert dev.has_permission("certify")
        assert dev.has_permission("validate")
        assert dev.has_permission("audit")

        # Service can certify but not audit
        service = User(user_id="svc", username="svc", role=UserRole.SERVICE)
        assert service.has_permission("certify")
        assert service.has_permission("validate")
        assert not service.has_permission("audit")

        # Guest can only read
        guest = User(user_id="guest", username="guest", role=UserRole.GUEST)
        assert guest.has_permission("read")
        assert not guest.has_permission("certify")
        assert not guest.has_permission("audit")
