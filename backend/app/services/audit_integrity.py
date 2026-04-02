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
