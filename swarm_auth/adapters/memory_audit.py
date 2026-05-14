"""
Memory Audit Adapter — in-process AuditPort for testing.

ADR-027 Stage 6.

Never raises on emit(). Thread-safe append via threading.Lock.
Do NOT use in production — events are lost on process restart.
Use LoggingAuditAdapter or a persistent adapter in production.

Usage (tests):
    audit = MemoryAuditAdapter()
    broker = ScopeEnforcingBrokerAdapter(..., audit=audit)

    broker.vend_credential(principal, request)

    events = audit.recorded()
    assert any(e.event_type == AuditEventType.CREDENTIAL_VENDED for e in events)
"""

import threading
from typing import List

from swarm_auth.ports.audit_port import AuditEvent, AuditPort, AuditQuery


class MemoryAuditAdapter(AuditPort):
    """
    In-memory AuditPort. Appends every event to an internal list.

    Implements AuditPort.emit() as a no-raise, thread-safe append.
    Implements AuditPort.query() with in-memory filtering.

    Extra helpers for tests:
      - recorded(): returns all events in insertion order
      - clear(): resets the internal list
    """

    def __init__(self) -> None:
        self._events: List[AuditEvent] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # AuditPort interface
    # ------------------------------------------------------------------

    def emit(self, event: AuditEvent) -> None:
        """Append event to internal list. Never raises."""
        try:
            with self._lock:
                self._events.append(event)
        except Exception:
            pass  # AuditPort contract: never raise in emit()

    def query(self, query: AuditQuery) -> List[AuditEvent]:
        """
        Return events matching all specified filter criteria.

        Applies all non-None fields as AND filters, sorts by timestamp
        descending, and caps at query.limit.
        """
        with self._lock:
            events = list(self._events)

        if query.principal_id is not None:
            events = [e for e in events if e.principal_id == query.principal_id]
        if query.event_type is not None:
            events = [e for e in events if e.event_type == query.event_type]
        if query.provider is not None:
            events = [e for e in events if e.provider == query.provider]
        if query.since is not None:
            events = [e for e in events if e.timestamp >= query.since]
        if query.until is not None:
            events = [e for e in events if e.timestamp <= query.until]

        events.sort(key=lambda e: e.timestamp, reverse=True)
        return events[: query.limit]

    # ------------------------------------------------------------------
    # Test helpers (not on AuditPort)
    # ------------------------------------------------------------------

    def recorded(self) -> List[AuditEvent]:
        """Return all recorded events in insertion order."""
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        """Reset recorded events. Useful between test cases."""
        with self._lock:
            self._events.clear()

    def count(self, event_type=None) -> int:
        """Return count of recorded events, optionally filtered by type."""
        events = self.recorded()
        if event_type is not None:
            events = [e for e in events if e.event_type == event_type]
        return len(events)
