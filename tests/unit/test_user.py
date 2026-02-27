"""
Unit tests for User domain model.
"""

import pytest
from datetime import datetime
from swarm_auth.domain.user import User, UserRole


def test_user_creation():
    """Test basic user creation."""
    user = User(
        user_id="usr_1",
        username="alice",
        role=UserRole.DEVELOPER,
        email="alice@example.com"
    )

    assert user.user_id == "usr_1"
    assert user.username == "alice"
    assert user.role == UserRole.DEVELOPER
    assert user.email == "alice@example.com"
    assert user.is_active is True
    assert user.is_service_account is False


def test_user_permissions():
    """Test user permission checks."""
    admin = User(user_id="1", username="admin", role=UserRole.ADMIN)
    developer = User(user_id="2", username="dev", role=UserRole.DEVELOPER)
    auditor = User(user_id="3", username="audit", role=UserRole.AUDITOR)
    service = User(user_id="4", username="svc", role=UserRole.SERVICE)
    guest = User(user_id="5", username="guest", role=UserRole.GUEST)

    # Admin has all permissions
    assert admin.has_permission("certify")
    assert admin.has_permission("validate")
    assert admin.has_permission("audit")
    assert admin.has_permission("anything")

    # Developer can certify, validate, audit
    assert developer.has_permission("certify")
    assert developer.has_permission("validate")
    assert developer.has_permission("audit")
    assert developer.has_permission("read")

    # Auditor can only read and audit
    assert auditor.has_permission("read")
    assert auditor.has_permission("audit")
    assert not auditor.has_permission("certify")
    assert not auditor.has_permission("validate")

    # Service can certify, validate, read (no audit)
    assert service.has_permission("certify")
    assert service.has_permission("validate")
    assert service.has_permission("read")
    assert not service.has_permission("audit")

    # Guest can only read
    assert guest.has_permission("read")
    assert not guest.has_permission("certify")
    assert not guest.has_permission("audit")


def test_user_serialization():
    """Test user to_dict and from_dict."""
    user = User(
        user_id="usr_1",
        username="alice",
        role=UserRole.DEVELOPER,
        email="alice@example.com",
        org_id="org_1",
    )

    # Serialize
    data = user.to_dict()
    assert data["user_id"] == "usr_1"
    assert data["username"] == "alice"
    assert data["role"] == "developer"
    assert data["email"] == "alice@example.com"

    # Deserialize
    restored = User.from_dict(data)
    assert restored.user_id == user.user_id
    assert restored.username == user.username
    assert restored.role == user.role
    assert restored.email == user.email


def test_service_account():
    """Test service account creation."""
    service = User(
        user_id="svc_1",
        username="api-service",
        role=UserRole.SERVICE,
        is_service_account=True,
    )

    assert service.is_service_account is True
    assert service.email is None  # Service accounts don't need email
    assert service.has_permission("certify")
    assert not service.has_permission("audit")  # Service can't audit
