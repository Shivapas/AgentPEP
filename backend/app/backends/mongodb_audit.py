"""MongoDBauditBackend — MongoDB implementation of AuditBackend ABC.

Sprint 29 — APEP-230: Refactors the existing MongoDB audit logger as an
AuditBackend implementation with SHA-256 hash chain integrity.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from app.backends.audit import AuditBackend, IntegrityResult
from app.db import mongodb as db_module

logger = logging.getLogger(__name__)

GENESIS_HASH = hashlib.sha256(b"AGENTPEP_GENESIS").hexdigest()


class MongoDBauditBackend(AuditBackend):
    """MongoDB-backed audit backend with SHA-256 hash chain.

    Wraps the existing audit_decisions capped collection and provides
    integrity verification via the hash chain.
    """

    def __init__(self, collection: str = "audit_decisions") -> None:
        self._collection = collection

    async def write_decision(self, record: dict[str, Any]) -> bool:
        try:
            db = db_module.get_database()
            await db[self._collection].insert_one(record)
            return True
        except Exception:
            logger.exception("Failed to write audit decision to MongoDB")
            return False

    async def write_batch(self, records: list[dict[str, Any]]) -> int:
        if not records:
            return 0
        try:
            db = db_module.get_database()
            result = await db[self._collection].insert_many(records, ordered=False)
            return len(result.inserted_ids)
        except Exception:
            logger.exception("Failed to write audit batch (%d records)", len(records))
            return 0

    async def query(
        self,
        filter: dict[str, Any],
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        db = db_module.get_database()
        cursor = (
            db[self._collection]
            .find(filter)
            .sort("timestamp", -1)
            .skip(offset)
            .limit(limit)
        )
        docs = []
        async for doc in cursor:
            doc.pop("_id", None)
            docs.append(doc)
        return docs

    async def verify_integrity(
        self, *, start_sequence: int = 1, end_sequence: int | None = None
    ) -> IntegrityResult:
        db = db_module.get_database()

        query_filter: dict[str, Any] = {"sequence_number": {"$gte": start_sequence}}
        if end_sequence is not None:
            query_filter["sequence_number"]["$lte"] = end_sequence

        cursor = db[self._collection].find(query_filter).sort("sequence_number", 1)

        total = 0
        verified = 0
        previous_hash = GENESIS_HASH

        # If starting from a sequence > 1, get the previous record's hash
        if start_sequence > 1:
            prev_record = await db[self._collection].find_one(
                {"sequence_number": start_sequence - 1}
            )
            if prev_record:
                previous_hash = prev_record.get("record_hash", GENESIS_HASH)

        async for record in cursor:
            total += 1
            stored_hash = record.get("record_hash", "")
            stored_previous = record.get("previous_hash", "")

            # Verify chain linkage
            if stored_previous != previous_hash:
                return IntegrityResult(
                    valid=False,
                    total_records=total,
                    verified_records=verified,
                    first_tampered_sequence=record.get("sequence_number"),
                    first_tampered_decision_id=str(record.get("decision_id", "")),
                    detail=f"Hash chain broken at sequence {record.get('sequence_number')}: "
                    f"expected previous_hash={previous_hash!r}, "
                    f"got={stored_previous!r}",
                )

            # Verify record hash
            expected_hash = self._compute_record_hash(record, previous_hash)
            if stored_hash != expected_hash:
                return IntegrityResult(
                    valid=False,
                    total_records=total,
                    verified_records=verified,
                    first_tampered_sequence=record.get("sequence_number"),
                    first_tampered_decision_id=str(record.get("decision_id", "")),
                    detail=f"Record hash mismatch at sequence {record.get('sequence_number')}",
                )

            verified += 1
            previous_hash = stored_hash

        return IntegrityResult(
            valid=True,
            total_records=total,
            verified_records=verified,
            detail="All records verified successfully",
        )

    @staticmethod
    def _compute_record_hash(record: dict[str, Any], previous_hash: str) -> str:
        """Recompute SHA-256 hash for verification (mirrors audit_logger.compute_record_hash)."""
        payload = json.dumps(
            {
                "previous_hash": previous_hash,
                "sequence_number": record.get("sequence_number"),
                "decision_id": str(record.get("decision_id", "")),
                "session_id": record.get("session_id", ""),
                "agent_id": record.get("agent_id", ""),
                "agent_role": record.get("agent_role", ""),
                "tool_name": record.get("tool_name", ""),
                "tool_args_hash": record.get("tool_args_hash", ""),
                "decision": record.get("decision", ""),
                "risk_score": record.get("risk_score", 0.0),
                "matched_rule_id": (
                    str(record["matched_rule_id"]) if record.get("matched_rule_id") else None
                ),
                "taint_flags": record.get("taint_flags", []),
                "delegation_chain": record.get("delegation_chain", []),
                "latency_ms": record.get("latency_ms", 0),
                "timestamp": record.get("timestamp", ""),
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()
