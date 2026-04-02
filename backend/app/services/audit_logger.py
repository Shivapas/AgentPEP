"""AuditLogger — append-only audit log with SHA-256 hash chain.

Sprint 10:
  APEP-081: Append AuditDecision to MongoDB capped collection
  APEP-082: SHA-256 hash chain across sequential audit records
"""

import hashlib
import json
import logging
import threading

from app.db import mongodb as db_module
from app.models.policy import AuditDecision

logger = logging.getLogger(__name__)

# Genesis hash — seed for the very first record in the chain
GENESIS_HASH = hashlib.sha256(b"AGENTPEP_GENESIS").hexdigest()


def compute_record_hash(audit: AuditDecision, previous_hash: str) -> str:
    """Compute SHA-256 hash for an audit record chained to the previous hash.

    The hash covers all semantically meaningful fields to detect any tampering.
    """
    payload = json.dumps(
        {
            "previous_hash": previous_hash,
            "sequence_number": audit.sequence_number,
            "decision_id": str(audit.decision_id),
            "session_id": audit.session_id,
            "agent_id": audit.agent_id,
            "agent_role": audit.agent_role,
            "tool_name": audit.tool_name,
            "tool_args_hash": audit.tool_args_hash,
            "decision": audit.decision.value,
            "risk_score": audit.risk_score,
            "matched_rule_id": str(audit.matched_rule_id) if audit.matched_rule_id else None,
            "taint_flags": audit.taint_flags,
            "delegation_chain": audit.delegation_chain,
            "latency_ms": audit.latency_ms,
            "timestamp": audit.timestamp.isoformat(),
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLogger:
    """Append-only audit logger with SHA-256 hash chain.

    Thread-safe via a lock protecting the sequence counter and previous hash.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sequence: int = 0
        self._previous_hash: str = GENESIS_HASH
        self._initialized: bool = False

    async def initialize(self) -> None:
        """Load the latest sequence number and hash from MongoDB to resume the chain."""
        db = db_module.get_database()
        last_record = await db[db_module.AUDIT_DECISIONS].find_one(
            sort=[("sequence_number", -1)]
        )
        if last_record:
            with self._lock:
                self._sequence = last_record.get("sequence_number", 0)
                self._previous_hash = last_record.get("record_hash", GENESIS_HASH)
        self._initialized = True

    async def append(self, audit: AuditDecision) -> AuditDecision:
        """Append an audit record with hash chain fields and persist to MongoDB.

        Returns the audit record with populated sequence_number, previous_hash,
        and record_hash fields.
        """
        if not self._initialized:
            await self.initialize()

        with self._lock:
            self._sequence += 1
            audit.sequence_number = self._sequence
            audit.previous_hash = self._previous_hash
            audit.record_hash = compute_record_hash(audit, self._previous_hash)
            self._previous_hash = audit.record_hash

        db = db_module.get_database()
        try:
            await db[db_module.AUDIT_DECISIONS].insert_one(
                audit.model_dump(mode="json")
            )
        except Exception:
            logger.exception("Failed to write audit record seq=%d", audit.sequence_number)

        return audit

    def reset(self) -> None:
        """Reset internal state (used in tests)."""
        with self._lock:
            self._sequence = 0
            self._previous_hash = GENESIS_HASH
            self._initialized = False


# Module-level singleton
audit_logger = AuditLogger()
