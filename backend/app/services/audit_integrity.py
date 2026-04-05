"""Audit integrity verification — replays the SHA-256 hash chain to detect tampering.

Sprint 10 — APEP-088: Replay hash chain and detect any inconsistencies.
"""

import logging

from app.db import mongodb as db_module
from app.models.policy import AuditDecision, AuditIntegrityResult
from app.services.audit_logger import GENESIS_HASH, compute_record_hash

logger = logging.getLogger(__name__)


async def verify_audit_chain(
    start_sequence: int = 1,
    end_sequence: int | None = None,
) -> AuditIntegrityResult:
    """Replay the audit hash chain from start_sequence to end_sequence.

    Verifies that each record's hash matches the recomputed value and that
    the previous_hash field correctly links to the preceding record.

    Args:
        start_sequence: First sequence number to verify (default: 1).
        end_sequence: Last sequence number to verify (default: latest).

    Returns:
        AuditIntegrityResult with verification status.
    """
    db = db_module.get_database()
    collection = db[db_module.AUDIT_DECISIONS]

    query: dict = {"sequence_number": {"$gte": start_sequence}}
    if end_sequence is not None:
        query["sequence_number"]["$lte"] = end_sequence

    cursor = collection.find(query).sort("sequence_number", 1)

    total = 0
    verified = 0
    expected_previous_hash = GENESIS_HASH

    # If starting from a sequence > 1, fetch the preceding record's hash
    if start_sequence > 1:
        preceding = await collection.find_one(
            {"sequence_number": start_sequence - 1},
            sort=[("sequence_number", -1)],
        )
        if preceding:
            expected_previous_hash = preceding.get("record_hash", GENESIS_HASH)

    async for doc in cursor:
        total += 1
        try:
            audit = AuditDecision(**doc)
        except Exception:
            return AuditIntegrityResult(
                valid=False,
                total_records=total,
                verified_records=verified,
                first_tampered_sequence=doc.get("sequence_number"),
                first_tampered_decision_id=str(doc.get("decision_id", "")),
                detail=f"Failed to parse audit record at sequence {doc.get('sequence_number')}",
            )

        # Verify previous_hash linkage
        if audit.previous_hash != expected_previous_hash:
            return AuditIntegrityResult(
                valid=False,
                total_records=total,
                verified_records=verified,
                first_tampered_sequence=audit.sequence_number,
                first_tampered_decision_id=str(audit.decision_id),
                detail=(
                    f"Hash chain broken at sequence {audit.sequence_number}: "
                    f"expected previous_hash={expected_previous_hash[:16]}..., "
                    f"got={audit.previous_hash[:16]}..."
                ),
            )

        # Recompute and verify the record hash
        recomputed = compute_record_hash(audit, audit.previous_hash)
        if recomputed != audit.record_hash:
            return AuditIntegrityResult(
                valid=False,
                total_records=total,
                verified_records=verified,
                first_tampered_sequence=audit.sequence_number,
                first_tampered_decision_id=str(audit.decision_id),
                detail=(
                    f"Record hash mismatch at sequence {audit.sequence_number}: "
                    f"stored={audit.record_hash[:16]}..., "
                    f"recomputed={recomputed[:16]}..."
                ),
            )

        verified += 1
        expected_previous_hash = audit.record_hash

    return AuditIntegrityResult(
        valid=True,
        total_records=total,
        verified_records=verified,
        detail=f"All {verified} records verified successfully",
    )
"""Audit log integrity verification — APEP-191.

Implements a hash chain over audit decision records to detect tampering.
Each audit record's hash includes the previous record's hash, forming an
append-only chain.  A daily verification job walks the chain and validates
every link.

Hash chain scheme:
    hash_n = SHA-256(hash_{n-1} || decision_id || session_id || agent_id
                     || tool_name || decision || timestamp)

The ``AuditIntegrityVerifier`` class provides:
    - ``compute_record_hash()``: compute the chain hash for a single record
    - ``seal_record()``: called after each audit write to extend the chain
    - ``verify_chain()``: walk the full chain and report any broken links
    - ``run_daily_verification()``: entry point for the scheduled job
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Any

from app.db import mongodb as db_module

logger = logging.getLogger(__name__)

AUDIT_HASH_CHAIN = "audit_hash_chain"


class AuditIntegrityVerifier:
    """Manages hash chain integrity for the audit_decisions collection."""

    @staticmethod
    def compute_record_hash(
        previous_hash: str,
        decision_id: str,
        session_id: str,
        agent_id: str,
        tool_name: str,
        decision: str,
        timestamp: str,
    ) -> str:
        """Compute SHA-256 hash linking this record to the previous one."""
        payload = "|".join([
            previous_hash,
            decision_id,
            session_id,
            agent_id,
            tool_name,
            decision,
            timestamp,
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    async def seal_record(self, audit_record: dict[str, Any]) -> str:
        """Extend the hash chain with a new audit record.

        Fetches the latest chain entry, computes the new hash, and
        appends it to the audit_hash_chain collection.

        Returns the new chain hash.
        """
        db = db_module.get_database()

        # Get the latest chain entry
        latest = await db[AUDIT_HASH_CHAIN].find_one(
            sort=[("sequence", -1)]
        )
        previous_hash = latest["chain_hash"] if latest else "GENESIS"
        sequence = (latest["sequence"] + 1) if latest else 0

        timestamp_str = str(audit_record.get("timestamp", datetime.utcnow().isoformat()))

        chain_hash = self.compute_record_hash(
            previous_hash=previous_hash,
            decision_id=str(audit_record.get("decision_id", "")),
            session_id=str(audit_record.get("session_id", "")),
            agent_id=str(audit_record.get("agent_id", "")),
            tool_name=str(audit_record.get("tool_name", "")),
            decision=str(audit_record.get("decision", "")),
            timestamp=timestamp_str,
        )

        chain_entry = {
            "sequence": sequence,
            "decision_id": str(audit_record.get("decision_id", "")),
            "chain_hash": chain_hash,
            "previous_hash": previous_hash,
            "timestamp": datetime.utcnow(),
        }

        await db[AUDIT_HASH_CHAIN].insert_one(chain_entry)
        return chain_hash

    async def verify_chain(
        self,
        start_sequence: int = 0,
        end_sequence: int | None = None,
    ) -> AuditVerificationResult:
        """Walk the hash chain and verify every link.

        Returns a verification result with details of any broken links.
        """
        db = db_module.get_database()

        query: dict[str, Any] = {"sequence": {"$gte": start_sequence}}
        if end_sequence is not None:
            query["sequence"]["$lte"] = end_sequence

        cursor = db[AUDIT_HASH_CHAIN].find(query).sort("sequence", 1)
        entries = await cursor.to_list(length=None)

        if not entries:
            return AuditVerificationResult(
                verified=True,
                records_checked=0,
                broken_links=[],
                message="No audit chain entries to verify.",
            )

        broken_links: list[dict[str, Any]] = []
        records_checked = 0

        for i, entry in enumerate(entries):
            records_checked += 1

            if i == 0:
                expected_previous = "GENESIS" if entry["sequence"] == 0 else None
                if expected_previous and entry["previous_hash"] != expected_previous:
                    # First entry in range — check genesis only if seq 0
                    if entry["sequence"] == 0:
                        broken_links.append({
                            "sequence": entry["sequence"],
                            "decision_id": entry["decision_id"],
                            "expected_previous": "GENESIS",
                            "actual_previous": entry["previous_hash"],
                        })
                continue

            # Verify that this entry's previous_hash matches the prior entry's chain_hash
            prev_entry = entries[i - 1]
            if entry["previous_hash"] != prev_entry["chain_hash"]:
                broken_links.append({
                    "sequence": entry["sequence"],
                    "decision_id": entry["decision_id"],
                    "expected_previous": prev_entry["chain_hash"],
                    "actual_previous": entry["previous_hash"],
                })

        verified = len(broken_links) == 0
        message = (
            f"Chain verified: {records_checked} records checked, no broken links."
            if verified
            else f"INTEGRITY VIOLATION: {len(broken_links)} broken link(s) detected "
            f"out of {records_checked} records."
        )

        if not verified:
            logger.critical(
                "AUDIT_INTEGRITY_VIOLATION: %d broken links detected in hash chain",
                len(broken_links),
            )

        return AuditVerificationResult(
            verified=verified,
            records_checked=records_checked,
            broken_links=broken_links,
            message=message,
        )

    async def run_daily_verification(self) -> AuditVerificationResult:
        """Run the daily hash chain verification job.

        Verifies the entire chain and logs the result.
        """
        logger.info("Starting daily audit log integrity verification...")
        result = await self.verify_chain()

        if result.verified:
            logger.info(
                "Audit integrity verification PASSED: %d records checked.",
                result.records_checked,
            )
        else:
            logger.critical(
                "Audit integrity verification FAILED: %s",
                result.message,
            )

            # Store the verification result for dashboarding
            db = db_module.get_database()
            await db["audit_verification_results"].insert_one({
                "timestamp": datetime.utcnow(),
                "verified": result.verified,
                "records_checked": result.records_checked,
                "broken_links": result.broken_links,
                "message": result.message,
            })

        return result

    async def get_chain_length(self) -> int:
        """Return the current number of entries in the hash chain."""
        db = db_module.get_database()
        return await db[AUDIT_HASH_CHAIN].count_documents({})


class AuditVerificationResult:
    """Result of a hash chain verification run."""

    def __init__(
        self,
        verified: bool,
        records_checked: int,
        broken_links: list[dict[str, Any]],
        message: str,
    ) -> None:
        self.verified = verified
        self.records_checked = records_checked
        self.broken_links = broken_links
        self.message = message

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "records_checked": self.records_checked,
            "broken_links_count": len(self.broken_links),
            "broken_links": self.broken_links,
            "message": self.message,
        }


# Module-level singleton
audit_integrity_verifier = AuditIntegrityVerifier()
