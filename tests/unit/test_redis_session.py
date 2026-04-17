import json
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from swarm_auth.adapters.redis_session import RedisSessionAdapter
from swarm_auth.domain.session import Session, SessionStatus


def _make_session(user_id: str = "usr_1", ttl: int = 3600) -> Session:
    return Session.create(user_id=user_id, ttl=ttl)


def _serialize(session: Session) -> str:
    return json.dumps(session.to_dict())


@pytest.fixture
def mock_redis():
    return MagicMock()


@pytest.fixture
def adapter(mock_redis):
    return RedisSessionAdapter(redis_client=mock_redis)


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

def test_create_stores_session_and_adds_to_user_set(adapter, mock_redis):
    session = adapter.create(user_id="usr_1", ttl=3600, metadata={"role": "admin"})

    key = f"swarm:session:{session.session_id}"
    user_key = "swarm:session:user:usr_1"

    mock_redis.setex.assert_called_once()
    call_args = mock_redis.setex.call_args[0]
    assert call_args[0] == key
    assert call_args[1] == 3600
    stored = json.loads(call_args[2])
    assert stored["user_id"] == "usr_1"
    assert stored["metadata"] == {"role": "admin"}

    mock_redis.sadd.assert_called_once_with(user_key, session.session_id)
    mock_redis.expire.assert_called_once_with(user_key, 3600)

    assert isinstance(session, Session)
    assert session.user_id == "usr_1"


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------

def test_get_returns_session_when_found_and_valid(adapter, mock_redis):
    session = _make_session()
    mock_redis.get.return_value = _serialize(session)

    result = adapter.get(session.session_id)

    mock_redis.get.assert_called_once_with(f"swarm:session:{session.session_id}")
    assert result is not None
    assert result.session_id == session.session_id
    assert result.user_id == session.user_id


def test_get_returns_none_when_key_missing(adapter, mock_redis):
    mock_redis.get.return_value = None

    result = adapter.get("nonexistent-id")

    assert result is None


def test_get_returns_none_on_malformed_json(adapter, mock_redis):
    mock_redis.get.return_value = "not-valid-json{"

    result = adapter.get("some-id")

    assert result is None


def test_get_returns_none_when_session_expired(adapter, mock_redis):
    session = _make_session(ttl=1)
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
    mock_redis.get.return_value = _serialize(session)

    result = adapter.get(session.session_id)

    assert result is None


def test_get_returns_none_when_session_revoked(adapter, mock_redis):
    session = _make_session()
    session.revoke()
    mock_redis.get.return_value = _serialize(session)

    result = adapter.get(session.session_id)

    assert result is None


# ---------------------------------------------------------------------------
# update
# ---------------------------------------------------------------------------

def test_update_merges_metadata_and_restores_with_remaining_ttl(adapter, mock_redis):
    session = _make_session(user_id="usr_2")
    mock_redis.get.return_value = _serialize(session)
    mock_redis.ttl.return_value = 1800

    result = adapter.update(session.session_id, {"env": "prod"})

    assert result is True
    mock_redis.ttl.assert_called_once_with(f"swarm:session:{session.session_id}")
    mock_redis.setex.assert_called_once()
    call_args = mock_redis.setex.call_args[0]
    assert call_args[1] == 1800
    stored = json.loads(call_args[2])
    assert stored["metadata"]["env"] == "prod"


def test_update_returns_false_when_session_not_found(adapter, mock_redis):
    mock_redis.get.return_value = None

    result = adapter.update("missing-id", {"x": 1})

    assert result is False
    mock_redis.setex.assert_not_called()


def test_update_returns_false_when_ttl_is_negative_one(adapter, mock_redis):
    session = _make_session()
    mock_redis.get.return_value = _serialize(session)
    mock_redis.ttl.return_value = -1

    result = adapter.update(session.session_id, {"x": 1})

    assert result is False
    mock_redis.setex.assert_not_called()


def test_update_returns_false_when_ttl_is_negative_two(adapter, mock_redis):
    session = _make_session()
    mock_redis.get.return_value = _serialize(session)
    mock_redis.ttl.return_value = -2

    result = adapter.update(session.session_id, {"x": 1})

    assert result is False
    mock_redis.setex.assert_not_called()


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------

def test_delete_removes_key_and_user_set_entry(adapter, mock_redis):
    session = _make_session(user_id="usr_3")
    mock_redis.get.return_value = _serialize(session)

    result = adapter.delete(session.session_id)

    assert result is True
    mock_redis.delete.assert_called_once_with(f"swarm:session:{session.session_id}")
    mock_redis.srem.assert_called_once_with(
        f"swarm:session:user:{session.user_id}", session.session_id
    )


def test_delete_returns_false_when_session_not_found(adapter, mock_redis):
    mock_redis.get.return_value = None

    result = adapter.delete("missing-id")

    assert result is False
    mock_redis.delete.assert_not_called()
    mock_redis.srem.assert_not_called()


# ---------------------------------------------------------------------------
# list_by_user
# ---------------------------------------------------------------------------

def test_list_by_user_returns_valid_sessions_and_cleans_expired(adapter, mock_redis):
    valid_session = _make_session(user_id="usr_4", ttl=3600)
    expired_session = _make_session(user_id="usr_4", ttl=1)
    expired_session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)

    session_data = {
        valid_session.session_id: _serialize(valid_session),
        expired_session.session_id: _serialize(expired_session),
    }

    mock_redis.smembers.return_value = {
        valid_session.session_id,
        expired_session.session_id,
    }
    mock_redis.get.side_effect = lambda key: session_data.get(key.replace("swarm:session:", ""))

    result = adapter.list_by_user("usr_4")

    assert len(result) == 1
    assert result[0].session_id == valid_session.session_id
    mock_redis.srem.assert_called_once_with(
        "swarm:session:user:usr_4", expired_session.session_id
    )


def test_list_by_user_returns_empty_when_no_sessions(adapter, mock_redis):
    mock_redis.smembers.return_value = set()

    result = adapter.list_by_user("usr_empty")

    assert result == []


# ---------------------------------------------------------------------------
# extend
# ---------------------------------------------------------------------------

def test_extend_extends_session_and_restores(adapter, mock_redis):
    session = _make_session(user_id="usr_5", ttl=3600)
    mock_redis.get.return_value = _serialize(session)

    result = adapter.extend(session.session_id, ttl=1800)

    assert result is True
    mock_redis.setex.assert_called_once()
    call_args = mock_redis.setex.call_args[0]
    assert call_args[0] == f"swarm:session:{session.session_id}"
    assert call_args[1] > 0
    stored = json.loads(call_args[2])
    assert stored["session_id"] == session.session_id


def test_extend_returns_false_when_session_not_found(adapter, mock_redis):
    mock_redis.get.return_value = None

    result = adapter.extend("missing-id", ttl=600)

    assert result is False
    mock_redis.setex.assert_not_called()


def test_extend_returns_false_when_extend_would_exceed_max_duration(adapter, mock_redis):
    # Create session with 23h already elapsed — extending by 2h would exceed 24h max
    session = _make_session(user_id="usr_6", ttl=3600)
    # Push created_at back so remaining window is tiny
    session.created_at = datetime.now(timezone.utc) - timedelta(hours=23, minutes=30)
    session.expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
    mock_redis.get.return_value = _serialize(session)

    # Extending by 7200s (2h) would exceed 24h max
    result = adapter.extend(session.session_id, ttl=7200)

    assert result is False
    mock_redis.setex.assert_not_called()


# ---------------------------------------------------------------------------
# cleanup_expired
# ---------------------------------------------------------------------------

def test_cleanup_expired_returns_zero(adapter):
    result = adapter.cleanup_expired()

    assert result == 0


# ---------------------------------------------------------------------------
# _get_redis lazy load
# ---------------------------------------------------------------------------

def test_get_redis_raises_import_error_when_redis_not_installed():
    adapter = RedisSessionAdapter(redis_client=None)
    with patch.dict("sys.modules", {"redis": None}):
        with pytest.raises(ImportError, match="redis package required"):
            adapter._get_redis()
