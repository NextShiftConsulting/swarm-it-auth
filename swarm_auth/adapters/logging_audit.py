"""
Logging Audit Adapter — structured JSON audit log via Python's logging module.

ADR-027 Stage 6.

Emits each AuditEvent as a single JSON line to a named logger.
SIEM integrations consume this stream via CloudWatch, Splunk, etc.

emit() is fire-and-forget and MUST NOT raise — internal failures are
logged at ERROR level to a separate logger so they do not pollute the
audit stream.

query() always returns an empty list — this is a write-only sink. Read
the structured logs directly from CloudWatch Insights or Splunk for query.

Usage:
    import logging
    logging.basicConfig(level=logging.INFO)

    audit = LoggingAuditAdapter()  # → logs to "swarm_auth.audit"
    audit.emit(AuditEvent(
        event_type=AuditEventType.CREDENTIAL_VENDED,
        principal_id="u1",
        provider="aws",
    ))
    # → INFO:swarm_auth.audit:{"event_type":"credential.vended","principal_id":"u1",...}
"""

import json
import logging
from typing import List

from swarm_auth.ports.audit_port import AuditEvent, AuditPort, AuditQuery


class LoggingAuditAdapter(AuditPort):
    """
    Structured JSON log audit adapter.

    Each emit() call produces one JSON object on a single line. The object
    contains all non-None fields from AuditEvent. Fields with no value are
    omitted to keep the log compact.

    The default logger name "swarm_auth.audit" lets operators configure
    a dedicated handler (e.g. a rotating file or CloudWatch forwarder)
    without affecting other swarm_auth log output.
    """

    _FAILURE_LOGGER = "swarm_auth.audit.internal"

    def __init__(self, logger_name: str = "swarm_auth.audit") -> None:
        self._logger = logging.getLogger(logger_name)
        self._failure_logger = logging.getLogger(self._FAILURE_LOGGER)

    # ------------------------------------------------------------------
    # AuditPort interface
    # ------------------------------------------------------------------

    def emit(self, event: AuditEvent) -> None:
        """Emit AuditEvent as a JSON log line. Never raises."""
        try:
            payload = self._to_dict(event)
            self._logger.info(json.dumps(payload, default=str))
        except Exception:
            # Never raise from emit() — log to the internal channel instead
            try:
                self._failure_logger.exception(
                    "LoggingAuditAdapter.emit() failed — event lost"
                )
            except Exception:
                pass

    def query(self, query: AuditQuery) -> List[AuditEvent]:
        """Write-only sink: always returns an empty list."""
        return []

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_dict(event: AuditEvent) -> dict:
        """Serialize AuditEvent to a flat dict, omitting None values."""
        d: dict = {
            "event_type": event.event_type.value,
            "principal_id": event.principal_id,
            "timestamp": event.timestamp.isoformat(),
        }
        if event.request_id:
            d["request_id"] = event.request_id
        if event.session_id:
            d["session_id"] = event.session_id
        if event.ip_address:
            d["ip_address"] = event.ip_address
        if event.provider:
            d["provider"] = event.provider
        if event.action:
            d["action"] = event.action
        if event.resource:
            d["resource"] = event.resource
        if event.constraint_id:
            d["constraint_id"] = event.constraint_id
        if event.decision_reason:
            d["decision_reason"] = event.decision_reason
        if event.policy_ids:
            d["policy_ids"] = event.policy_ids
        if event.actor_chain:
            chain = {
                "subject": event.actor_chain.subject,
                "actor": event.actor_chain.actor,
                "chain_depth": event.actor_chain.chain_depth,
            }
            if event.actor_chain.raw_act_claim is not None:
                chain["raw_act_claim"] = event.actor_chain.raw_act_claim
            d["actor_chain"] = chain
        if event.metadata:
            d["metadata"] = event.metadata
        return d
