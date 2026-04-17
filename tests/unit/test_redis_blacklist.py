from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

import pytest

from swarm_auth.adapters.redis_blacklist import RedisBlacklistAdapter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_adapter(mock_redis=None, prefix="swarm:jwt:blacklist:", default_ttl=86400):
    if mock_redis is None:
        mock_redis = MagicMock()
    return RedisBlacklistAdapter(redis_client=mock_redis, prefix=prefix, default_ttl=default_ttl), mock_redis


TOKEN = "header.payload.signature"


# ---------------------------------------------------------------------------
# add()
# ---------------------------------------------------------------------------

def test_add_succeeds_when_token_not_yet_blacklisted():
    adapter, mock_redis = _make_adapter()
    mock_redis.exists.return_value = 0

    result = adapter.add(TOKEN, ttl=300)

    assert result is True
    mock_redis.setex.assert_called_once_with(adapter._key(TOKEN), 300, "1")


def test_add_uses_default_ttl_when_ttl_is_none():
    adapter, mock_redis = _make_adapter(default_ttl=7200)
    mock_redis.exists.return_value = 0

    adapter.add(TOKEN, ttl=None)

    mock_redis.setex.assert_called_once_with(adapter._key(TOKEN), 7200, "1")


def test_add_returns_false_when_already_blacklisted():
    adapter, mock_redis = _make_adapter()
    mock_redis.exists.return_value = 1

    result = adapter.add(TOKEN)

    assert result is False
    mock_redis.setex.assert_not_called()


def test_add_returns_false_on_redis_error():
    adapter, mock_redis = _make_adapter()
    mock_redis.exists.side_effect = Exception("connection refused")

    result = adapter.add(TOKEN)

    assert result is False


# ---------------------------------------------------------------------------
# is_blacklisted()
# ---------------------------------------------------------------------------

def test_is_blacklisted_returns_true_when_key_exists():
    adapter, mock_redis = _make_adapter()
    mock_redis.exists.return_value = 1

    assert adapter.is_blacklisted(TOKEN) is True


def test_is_blacklisted_returns_false_when_key_missing():
    adapter, mock_redis = _make_adapter()
    mock_redis.exists.return_value = 0

    assert adapter.is_blacklisted(TOKEN) is False


def test_is_blacklisted_returns_false_on_redis_error():
    adapter, mock_redis = _make_adapter()
    mock_redis.exists.side_effect = ConnectionError("timeout")

    assert adapter.is_blacklisted(TOKEN) is False


# ---------------------------------------------------------------------------
# remove()
# ---------------------------------------------------------------------------

def test_remove_returns_true_when_key_deleted():
    adapter, mock_redis = _make_adapter()
    mock_redis.delete.return_value = 1

    result = adapter.remove(TOKEN)

    assert result is True
    mock_redis.delete.assert_called_once_with(adapter._key(TOKEN))


def test_remove_returns_false_when_key_not_found():
    adapter, mock_redis = _make_adapter()
    mock_redis.delete.return_value = 0

    result = adapter.remove(TOKEN)

    assert result is False


def test_remove_returns_false_on_redis_error():
    adapter, mock_redis = _make_adapter()
    mock_redis.delete.side_effect = Exception("network error")

    result = adapter.remove(TOKEN)

    assert result is False


# ---------------------------------------------------------------------------
# cleanup_expired()
# ---------------------------------------------------------------------------

def test_cleanup_expired_returns_zero():
    adapter, _ = _make_adapter()
    assert adapter.cleanup_expired() == 0


# ---------------------------------------------------------------------------
# _key()
# ---------------------------------------------------------------------------

def test_key_produces_sha256_based_key_with_prefix():
    adapter, _ = _make_adapter(prefix="swarm:jwt:blacklist:")

    key = adapter._key(TOKEN)

    expected_hash = hashlib.sha256(TOKEN.encode()).hexdigest()[:16]
    assert key == f"swarm:jwt:blacklist:{expected_hash}"


def test_key_is_consistent_for_same_token():
    adapter, _ = _make_adapter()

    assert adapter._key(TOKEN) == adapter._key(TOKEN)


def test_key_differs_for_different_tokens():
    adapter, _ = _make_adapter()

    assert adapter._key("token_a") != adapter._key("token_b")


def test_key_respects_custom_prefix():
    adapter, _ = _make_adapter(prefix="custom:prefix:")

    assert adapter._key(TOKEN).startswith("custom:prefix:")


# ---------------------------------------------------------------------------
# _get_redis()
# ---------------------------------------------------------------------------

def test_get_redis_returns_injected_client():
    mock_redis = MagicMock()
    adapter = RedisBlacklistAdapter(redis_client=mock_redis)

    assert adapter._get_redis() is mock_redis


def test_get_redis_raises_import_error_when_redis_not_installed():
    adapter = RedisBlacklistAdapter(redis_client=None)

    with patch.dict("sys.modules", {"redis": None}):
        with pytest.raises(ImportError, match="redis package required"):
            adapter._get_redis()


def test_get_redis_lazy_loads_and_caches_client():
    mock_redis_module = MagicMock()
    mock_client = MagicMock()
    mock_redis_module.Redis.return_value = mock_client

    adapter = RedisBlacklistAdapter(redis_client=None)

    with patch.dict("sys.modules", {"redis": mock_redis_module}):
        client_first = adapter._get_redis()
        client_second = adapter._get_redis()

    assert client_first is mock_client
    assert client_second is mock_client
    mock_redis_module.Redis.assert_called_once()
