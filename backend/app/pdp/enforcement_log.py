"""Enforcement decision log — structured audit record for every PDP evaluation.

Every OPA evaluation produces one EnforcementLogEntry.  The entry captures:
  - Correlated identifiers (request, agent, session)
  - Tool under evaluation
  - Bundle version active at evaluation time
  - Decision and reason code
  - Latency in milliseconds
  - Evaluator backend used (regopy vs native_stub)
  - Whether the request was pre-gated by the complexity checker
  - Session context (deployment tier, taint, trust, blast radius)

The log is structured for downstream consumption by TrustSOC (via Kafka in
Sprint S-E07).  This sprint writes entries to the structured logger;
the Kafka transport is added in S-E07 as the full OCSF schema is formalised.

Sprint S-E04 (E04-T05)
"""

from __future__ import annotations

import collections
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Deque

from app.core.structured_logging import get_logger

logger = get_logger(__name__)

_OCSF_CLASS_UID_POLICY_DECISION = 4001


# ---------------------------------------------------------------------------
# Log entry schema
# ---------------------------------------------------------------------------


@dataclass
class EnforcementLogEntry:
    """A single enforcement decision audit record."""

    # Correlation
    request_id: str
    agent_id: str
    session_id: str

    # Evaluation target
    tool_name: str

    # Policy state at evaluation time
    bundle_version: str

    # Decision
    decision: str          # "ALLOW" | "DENY" | "MODIFY"
    reason_code: str       # from ReasonCode enum

    # Performance
    latency_ms: float

    # Evaluation metadata
    evaluator: str         # "regopy" | "native_stub"
    gated_by_complexity: bool = False

    # Session context
    deployment_tier: str = "HOMEGROWN"
    taint_level: str = "CLEAN"
    trust_score: float = 1.0
    blast_radius_score: float = 0.0

    # Timestamp — set automatically
    timestamp_ms: int = field(default_factory=lambda: int(time.time() * 1000))

    def to_ocsf_dict(self) -> dict[str, Any]:
        """Serialise to a stub OCSF-shaped dict (formalised in S-E07)."""
        return {
            "class_uid": _OCSF_CLASS_UID_POLICY_DECISION,
            "class_name": "ENFORCEMENT_DECISION",
            "category_uid": 4,
            "category_name": "FINDINGS",
            "activity_id": 1 if self.decision == "ALLOW" else 2,
            "activity_name": self.decision,
            "severity_id": 1 if self.decision == "ALLOW" else 3,
            "severity": "INFORMATIONAL" if self.decision == "ALLOW" else "HIGH",
            "time": self.timestamp_ms,
            "start_time": self.timestamp_ms,
            "metadata": {
                "version": "1.0.0",
                "product": {
                    "name": "AgentPEP",
                    "vendor_name": "TrustFabric",
                },
                "event_code": "ENFORCEMENT_DECISION",
                "bundle_version": self.bundle_version,
            },
            "actor": {
                "agent_id": self.agent_id,
                "session_id": self.session_id,
            },
            "resources": [
                {
                    "type": "tool_call",
                    "name": self.tool_name,
                }
            ],
            "finding_info": {
                "uid": self.request_id,
                "title": f"Enforcement decision: {self.decision}",
                "reason_code": self.reason_code,
                "evaluator": self.evaluator,
                "gated_by_complexity": self.gated_by_complexity,
                "latency_ms": self.latency_ms,
            },
            "decision": self.decision,
            "context": {
                "deployment_tier": self.deployment_tier,
                "taint_level": self.taint_level,
                "trust_score": self.trust_score,
                "blast_radius_score": self.blast_radius_score,
            },
        }


# ---------------------------------------------------------------------------
# Log store — in-memory ring buffer + structured logger
# ---------------------------------------------------------------------------


class EnforcementLog:
    """Thread-safe enforcement decision log with in-memory ring buffer.

    Writes every entry to the structured logger (for immediate visibility)
    and retains the last ``max_entries`` entries in memory for inspection
    (useful in tests and the /pdp/decisions diagnostic endpoint added in
    a future sprint).

    The Kafka transport (full OCSF schema) is added in Sprint S-E07.
    """

    def __init__(self, max_entries: int = 10_000) -> None:
        self._lock = threading.RLock()
        self._entries: Deque[EnforcementLogEntry] = collections.deque(
            maxlen=max_entries
        )
        self._counters: dict[str, int] = {"ALLOW": 0, "DENY": 0, "MODIFY": 0}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, entry: EnforcementLogEntry) -> None:
        """Record a decision log entry.

        Appends to the ring buffer and emits a structured log line.
        This method is non-blocking and never raises.
        """
        try:
            with self._lock:
                self._entries.append(entry)
                decision_key = entry.decision if entry.decision in self._counters else "DENY"
                self._counters[decision_key] += 1

            logger.info(
                "enforcement_decision",
                request_id=entry.request_id,
                agent_id=entry.agent_id,
                session_id=entry.session_id,
                tool_name=entry.tool_name,
                bundle_version=entry.bundle_version,
                decision=entry.decision,
                reason_code=entry.reason_code,
                latency_ms=entry.latency_ms,
                evaluator=entry.evaluator,
                gated_by_complexity=entry.gated_by_complexity,
                deployment_tier=entry.deployment_tier,
                taint_level=entry.taint_level,
                trust_score=entry.trust_score,
                blast_radius_score=entry.blast_radius_score,
            )
        except Exception as exc:
            # Logging the log failure should not affect the evaluation path
            logger.error("enforcement_log_record_failed", error=str(exc))

    def recent(self, limit: int = 100) -> list[EnforcementLogEntry]:
        """Return the most recent *limit* entries (newest first)."""
        with self._lock:
            entries = list(self._entries)
        return list(reversed(entries))[:limit]

    def counts(self) -> dict[str, int]:
        """Return cumulative decision counts (ALLOW, DENY, MODIFY)."""
        with self._lock:
            return dict(self._counters)

    def clear(self) -> None:
        """Reset the ring buffer and counters (for testing)."""
        with self._lock:
            self._entries.clear()
            self._counters = {"ALLOW": 0, "DENY": 0, "MODIFY": 0}


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

enforcement_log = EnforcementLog()
