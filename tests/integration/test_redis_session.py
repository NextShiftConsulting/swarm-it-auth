"""
Integration tests for Redis session adapter.

Requires Redis running on localhost:6379
Skip tests if Redis is not available.
"""

import pytest
from swarm_auth.domain.session import Session


@pytest.fixture
def redis_adapter():
    """Create Redis session adapter (skip if Redis unavailable)."""
    try:
        from swarm_auth.adapters import RedisSessionAdapter
        import redis

        # Test connection
        r = redis.Redis(host="localhost", port=6379, decode_responses=True)
        r.ping()

        adapter = RedisSessionAdapter(prefix="test:session:")
        yield adapter

        # Cleanup: delete all test sessions
        for key in r.scan_iter("test:session:*"):
            r.delete(key)

    except (ImportError, redis.exceptions.ConnectionError):
        pytest.skip("Redis not available")


class TestRedisSessionAdapter:
    """Test Redis session storage."""

    def test_create_session(self, redis_adapter):
        """Test session creation in Redis."""
        session = redis_adapter.create(user_id="user123", ttl=3600)

        assert session.session_id is not None
        assert session.user_id == "user123"
        assert session.is_valid()

    def test_get_session(self, redis_adapter):
        """Test session retrieval."""
        created = redis_adapter.create(user_id="user123", ttl=3600)

        retrieved = redis_adapter.get(created.session_id)
        assert retrieved is not None
        assert retrieved.session_id == created.session_id
        assert retrieved.user_id == created.user_id

    def test_update_session(self, redis_adapter):
        """Test session metadata update."""
        session = redis_adapter.create(user_id="user123", ttl=3600)

        updated = redis_adapter.update(session.session_id, {"device": "mobile"})
        assert updated is True

        retrieved = redis_adapter.get(session.session_id)
        assert retrieved.metadata["device"] == "mobile"

    def test_delete_session(self, redis_adapter):
        """Test session deletion."""
        session = redis_adapter.create(user_id="user123", ttl=3600)

        deleted = redis_adapter.delete(session.session_id)
        assert deleted is True

        retrieved = redis_adapter.get(session.session_id)
        assert retrieved is None

    def test_list_by_user(self, redis_adapter):
        """Test listing user sessions."""
        # Create multiple sessions for same user
        session1 = redis_adapter.create(user_id="user123", ttl=3600)
        session2 = redis_adapter.create(user_id="user123", ttl=3600)
        session3 = redis_adapter.create(user_id="user456", ttl=3600)

        # List user123 sessions
        sessions = redis_adapter.list_by_user("user123")
        assert len(sessions) == 2

        session_ids = [s.session_id for s in sessions]
        assert session1.session_id in session_ids
        assert session2.session_id in session_ids
        assert session3.session_id not in session_ids

    def test_extend_session(self, redis_adapter):
        """Test session TTL extension."""
        session = redis_adapter.create(user_id="user123", ttl=3600)
        original_expiry = session.expires_at

        extended = redis_adapter.extend(session.session_id, ttl=1800)
        assert extended is True

        retrieved = redis_adapter.get(session.session_id)
        assert retrieved.expires_at > original_expiry

    def test_session_ttl_expiration(self, redis_adapter):
        """Test that Redis TTL works (session auto-expires)."""
        import time

        # Create session with 1 second TTL
        session = redis_adapter.create(user_id="user123", ttl=1)

        # Session should exist immediately
        assert redis_adapter.get(session.session_id) is not None

        # Wait for expiration
        time.sleep(2)

        # Session should be gone (expired by Redis TTL)
        assert redis_adapter.get(session.session_id) is None
