"""
Unit tests for Header Identity Adapter.
"""

import pytest
from swarm_auth.adapters.header_identity import HeaderIdentityAdapter
from swarm_auth.domain.user import UserRole


def test_header_identity_basic():
    """Test basic header identity extraction."""
    adapter = HeaderIdentityAdapter()

    headers = {
        "X-Auth-Request-User": "alice",
        "X-Auth-Request-Email": "alice@example.com",
    }

    user = adapter.verify_request(headers)

    assert user is not None
    assert user.user_id == "alice"
    assert user.username == "alice"
    assert user.email == "alice@example.com"
    assert user.role == UserRole.DEVELOPER  # Default


def test_header_identity_with_groups():
    """Test group-to-role mapping."""
    adapter = HeaderIdentityAdapter()

    headers = {
        "X-Auth-Request-User": "bob",
        "X-Auth-Request-Email": "bob@example.com",
        "X-Auth-Request-Groups": "admin,developers",
    }

    user = adapter.verify_request(headers)

    assert user is not None
    assert user.role == UserRole.ADMIN  # First matching group


def test_header_identity_missing_user():
    """Test missing user header."""
    adapter = HeaderIdentityAdapter()

    headers = {
        "X-Auth-Request-Email": "test@example.com",
    }

    user = adapter.verify_request(headers)

    assert user is None


def test_header_identity_service_account():
    """Test service account mapping."""
    adapter = HeaderIdentityAdapter()

    headers = {
        "X-Auth-Request-User": "service-bot",
        "X-Auth-Request-Groups": "service",
    }

    user = adapter.verify_request(headers)

    assert user is not None
    assert user.role == UserRole.SERVICE


def test_header_identity_custom_headers():
    """Test custom header names."""
    adapter = HeaderIdentityAdapter(
        user_header="X-User-ID",
        email_header="X-User-Email",
        groups_header="X-User-Roles",
    )

    headers = {
        "X-User-ID": "charlie",
        "X-User-Email": "charlie@example.com",
        "X-User-Roles": "auditor",
    }

    user = adapter.verify_request(headers)

    assert user is not None
    assert user.user_id == "charlie"
    assert user.role == UserRole.AUDITOR
