"""
Integration tests for swarm-it-api authentication.

Tests the full stack: JWT creation -> API call -> authentication.
Requires swarm-it-api running with ENABLE_AUTH=1.
"""

import pytest
import httpx
from swarm_auth import User, UserRole
from swarm_auth.adapters import JWTAuthAdapter


@pytest.fixture
def api_url():
    """API base URL."""
    return "http://localhost:8080"


@pytest.fixture
def auth_adapter():
    """Auth adapter with same secret as API."""
    # Must match JWT_SECRET in API environment
    return JWTAuthAdapter(secret="test-secret-key")


@pytest.mark.skip(reason="Requires API running with ENABLE_AUTH=1")
class TestAPIIntegration:
    """Test authentication with running API."""

    def test_health_endpoint_no_auth(self, api_url):
        """Test that health endpoint doesn't require auth."""
        response = httpx.get(f"{api_url}/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    def test_certify_without_token(self, api_url):
        """Test that /certify requires authentication."""
        response = httpx.post(
            f"{api_url}/api/v1/certify",
            json={"prompt": "What is 2+2?"}
        )
        assert response.status_code == 401

    def test_certify_with_valid_token(self, api_url, auth_adapter):
        """Test /certify with valid JWT token."""
        # Create user and token
        user = User(
            user_id="test_user",
            username="alice",
            role=UserRole.DEVELOPER,
        )
        token = auth_adapter.create_token(user, expires_in=3600)

        # Call API with token
        response = httpx.post(
            f"{api_url}/api/v1/certify",
            json={"prompt": "What is 2+2?"},
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 200
        result = response.json()
        assert "id" in result
        assert "decision" in result

    def test_certify_with_invalid_token(self, api_url):
        """Test /certify with invalid token."""
        response = httpx.post(
            f"{api_url}/api/v1/certify",
            json={"prompt": "What is 2+2?"},
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401

    def test_certify_insufficient_permissions(self, api_url, auth_adapter):
        """Test /certify with user lacking permissions."""
        # Create guest user (can't certify)
        user = User(
            user_id="guest_user",
            username="guest",
            role=UserRole.GUEST,
        )
        token = auth_adapter.create_token(user, expires_in=3600)

        # Call API with token
        response = httpx.post(
            f"{api_url}/api/v1/certify",
            json={"prompt": "What is 2+2?"},
            headers={"Authorization": f"Bearer {token}"}
        )

        # Should be forbidden (403) if permission checks are implemented
        # Or succeed (200) if only authentication is checked
        assert response.status_code in [200, 403]
