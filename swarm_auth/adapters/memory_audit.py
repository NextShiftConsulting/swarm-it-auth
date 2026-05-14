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

import json
import threading
from typing import Any, Dict, List

from swarm_auth.ports.audit_port import AuditEvent, AuditPort, AuditQuery


class MemoryAuditAdapter(AuditPort):
    """
    In-memory AuditPort. Appends every event to an internal list.

    Implements AuditPort.emit() as a no-raise, thread-safe append.
    Implements AuditPort.query() with in-memory filtering.

    Extra helpers for tests:
      - recorded(): returns all events in insertion order
      - get_events(): returns events as SIEM-compatible dicts
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

    def get_events(self) -> List[Dict[str, Any]]:
        """
        Return all recorded events as SIEM-compatible dicts.

        Each dict is JSON-serializable and includes the required SIEM fields:
          timestamp, event_type, principal_kind, subject, actor,
          resource, outcome, reason.

        principal_kind is read from AuditEvent.metadata["principal_kind"]
        when present (ACPOrchestrator sets this via _emit_allow/_emit_deny).
        Falls back to "human" when metadata is absent (legacy events).

        raw_act_claim is included nested under "actor_chain" when present,
        enabling SIEM reconstruction of the full delegation path.
        """
        result = []
        for event in self.recorded():
            # principal_kind: prefer metadata (set by ACPOrchestrator), fall back to "human"
            principal_kind = "human"
            if event.metadata and "principal_kind" in event.metadata:
                principal_kind = event.metadata["principal_kind"]

            # subject and actor from actor_chain snapshot
            if event.actor_chain is not None:
                subject = event.actor_chain.subject
                actor = event.actor_chain.actor
            else:
                subject = event.principal_id
                actor = None

            # outcome: deny event types map to "failure"
            _DENY_EVENT_TYPES = {
                "auth.failure",
                "authz.deny", "authz.scope_deny",
                "delegation.rejected",
                "dpop.invalid",
            }
            outcome = "failure" if event.event_type.value in _DENY_EVENT_TYPES else "success"

            d: Dict[str, Any] = {
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type.value,
                "principal_kind": principal_kind,
                "subject": subject,
                "actor": actor,
                "resource": event.resource,
                "outcome": outcome,
                "reason": event.decision_reason,
            }
            if event.provider:
                d["provider"] = event.provider
            if event.action:
                d["action"] = event.action
            if event.request_id:
                d["request_id"] = event.request_id
            # Include full actor_chain block with raw_act_claim for SIEM reconstruction
            if event.actor_chain is not None:
                chain_block: Dict[str, Any] = {
                    "subject": event.actor_chain.subject,
                    "actor": event.actor_chain.actor,
                    "chain_depth": event.actor_chain.chain_depth,
                }
                if event.actor_chain.raw_act_claim is not None:
                    chain_block["raw_act_claim"] = event.actor_chain.raw_act_claim
                d["actor_chain"] = chain_block
            result.append(d)
        return result
