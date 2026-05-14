"""
Unit tests for MemoryAuditAdapter and LoggingAuditAdapter (ADR-027 Stage 6).
"""

import logging
from datetime import datetime, timedelta, timezone

import pytest

from swarm_auth.adapters.memory_audit import MemoryAuditAdapter
from swarm_auth.adapters.logging_audit import LoggingAuditAdapter
from swarm_auth.ports.audit_port import (
    AuditEvent,
    AuditEventType,
    AuditQuery,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def audit():
    return MemoryAuditAdapter()


def _event(event_type=AuditEventType.POLICY_ALLOW, principal_id="u1", **kwargs):
    return AuditEvent(event_type=event_type, principal_id=principal_id, **kwargs)


# ---------------------------------------------------------------------------
# MemoryAuditAdapter — happy path
# ---------------------------------------------------------------------------

def test_emit_stores_event(audit):
    event = _event()
    audit.emit(event)
    assert len(audit.recorded()) == 1
    assert audit.recorded()[0] is event


def test_recorded_preserves_insertion_order(audit):
    e1 = _event(AuditEventType.AUTH_SUCCESS)
    e2 = _event(AuditEventType.CREDENTIAL_VENDED)
    audit.emit(e1)
    audit.emit(e2)
    assert audit.recorded() == [e1, e2]


def test_clear_resets_events(audit):
    audit.emit(_event())
    audit.clear()
    assert audit.recorded() == []


def test_count_total(audit):
    audit.emit(_event(AuditEventType.AUTH_SUCCESS))
    audit.emit(_event(AuditEventType.CREDENTIAL_VENDED))
    assert audit.count() == 2


def test_count_filtered_by_type(audit):
    audit.emit(_event(AuditEventType.AUTH_SUCCESS))
    audit.emit(_event(AuditEventType.CREDENTIAL_VENDED))
    assert audit.count(AuditEventType.AUTH_SUCCESS) == 1


# ---------------------------------------------------------------------------
# MemoryAuditAdapter — emit never raises
# ---------------------------------------------------------------------------

def test_emit_never_raises_even_on_broken_event(audit):
    """AuditPort contract: emit() must not raise, ever."""
    # Simulate a broken event by monkey-patching timestamp access
    bad_event = _event()
    bad_event.timestamp = None  # Would normally fail serialization
    audit.emit(bad_event)  # Must not raise


# ---------------------------------------------------------------------------
# MemoryAuditAdapter — query filtering
# ---------------------------------------------------------------------------

def test_query_by_principal_id(audit):
    audit.emit(_event(principal_id="u1"))
    audit.emit(_event(principal_id="u2"))
    results = audit.query(AuditQuery(principal_id="u1"))
    assert all(e.principal_id == "u1" for e in results)
    assert len(results) == 1


def test_query_by_event_type(audit):
    audit.emit(_event(AuditEventType.AUTH_SUCCESS))
    audit.emit(_event(AuditEventType.CREDENTIAL_VENDED))
    results = audit.query(AuditQuery(event_type=AuditEventType.AUTH_SUCCESS))
    assert all(e.event_type == AuditEventType.AUTH_SUCCESS for e in results)
    assert len(results) == 1


def test_query_by_provider(audit):
    audit.emit(_event(provider="aws"))
    audit.emit(_event(provider="openai"))
    results = audit.query(AuditQuery(provider="aws"))
    assert all(e.provider == "aws" for e in results)
    assert len(results) == 1


def test_query_by_since(audit):
    past = datetime.now(timezone.utc) - timedelta(hours=2)
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    old_event = _event()
    old_event.timestamp = past
    new_event = _event()
    audit.emit(old_event)
    audit.emit(new_event)
    threshold = datetime.now(timezone.utc) - timedelta(minutes=5)
    results = audit.query(AuditQuery(since=threshold))
    assert old_event not in results
    assert new_event in results


def test_query_limit(audit):
    for _ in range(10):
        audit.emit(_event())
    results = audit.query(AuditQuery(limit=3))
    assert len(results) == 3


def test_query_returns_newest_first(audit):
    """query() results are sorted by timestamp descending."""
    earlier = _event()
    later = _event()
    later.timestamp = datetime.now(timezone.utc) + timedelta(seconds=10)
    audit.emit(earlier)
    audit.emit(later)
    results = audit.query(AuditQuery())
    assert results[0] is later
    assert results[1] is earlier


def test_query_no_match_returns_empty(audit):
    audit.emit(_event(principal_id="u1"))
    results = audit.query(AuditQuery(principal_id="nonexistent"))
    assert results == []


# ---------------------------------------------------------------------------
# LoggingAuditAdapter
# ---------------------------------------------------------------------------

def test_logging_audit_emit_writes_to_logger(caplog):
    audit = LoggingAuditAdapter()
    event = AuditEvent(
        event_type=AuditEventType.CREDENTIAL_VENDED,
        principal_id="u1",
        provider="aws",
        action="s3:PutObject",
    )
    with caplog.at_level(logging.INFO, logger="swarm_auth.audit"):
        audit.emit(event)
    assert any("credential.vended" in r.message for r in caplog.records)


def test_logging_audit_query_returns_empty():
    """LoggingAuditAdapter is write-only; query always returns []."""
    audit = LoggingAuditAdapter()
    audit.emit(_event())
    assert audit.query(AuditQuery()) == []


def test_logging_audit_emit_never_raises():
    """emit() must not raise even if logger is in a bad state."""
    audit = LoggingAuditAdapter(logger_name="swarm_auth.audit.test_broken")
    bad_event = AuditEvent(
        event_type=AuditEventType.AUTH_SUCCESS,
        principal_id="u1",
    )
    bad_event.timestamp = None  # Would fail json.dumps
    audit.emit(bad_event)  # Must not raise
