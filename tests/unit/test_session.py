"""
Unit tests for Session domain model.
"""

import pytest
from datetime import datetime, timedelta
from swarm_auth.domain.session import Session, SessionStatus


def test_session_creation():
    """Test session creation."""
    session = Session.create(user_id="usr_1", ttl=3600)

    assert session.user_id == "usr_1"
    assert session.status == SessionStatus.ACTIVE
    assert session.is_valid()
    assert len(session.session_id) > 20  # Random ID


def test_session_expiration():
    """Test session expiration."""
    # Create session that expires in 1 second
    session = Session.create(user_id="usr_1", ttl=1)
    assert session.is_valid()

    # Manually set expiration to past
    session.expires_at = datetime.utcnow() - timedelta(seconds=1)
    assert not session.is_valid()


def test_session_extend():
    """Test session extension."""
    session = Session.create(user_id="usr_1", ttl=3600)
    original_expiry = session.expires_at

    # Extend by 1800 seconds
    extended = session.extend(1800)
    assert extended is True
    assert session.expires_at > original_expiry


def test_session_extend_max_duration():
    """Test session extension respects max duration."""
    session = Session.create(user_id="usr_1", ttl=3600)

    # Try to extend beyond 24 hours (max_duration)
    extended = session.extend(seconds=86400, max_duration=3600)
    assert extended is False  # Should fail


def test_session_revoke():
    """Test session revocation."""
    session = Session.create(user_id="usr_1", ttl=3600)
    assert session.is_valid()

    session.revoke()
    assert session.status == SessionStatus.REVOKED
    assert not session.is_valid()


def test_session_serialization():
    """Test session to_dict and from_dict."""
    session = Session.create(
        user_id="usr_1",
        ttl=3600,
        ip_address="192.168.1.1",
        user_agent="Mozilla/5.0",
        metadata={"device": "mobile"}
    )

    # Serialize
    data = session.to_dict()
    assert data["user_id"] == "usr_1"
    assert data["status"] == "active"
    assert data["ip_address"] == "192.168.1.1"
    assert data["metadata"]["device"] == "mobile"

    # Deserialize
    restored = Session.from_dict(data)
    assert restored.user_id == session.user_id
    assert restored.session_id == session.session_id
    assert restored.status == session.status
