"""HashChainedContext — tamper-evident context chain with SHA-256 hashes.

Sprint 36 — APEP-285: Each context entry in a session is hash-chained to the
previous entry, creating a tamper-evident log. Any modification to a prior
entry invalidates all subsequent chain hashes, enabling tamper detection.

The chain uses SHA-256(previous_hash || content_hash) to link entries.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from app.db import mongodb as db_module
from app.models.sprint36 import HashChainedContextEntry, HashChainVerificationResult

logger = logging.getLogger(__name__)

# Genesis hash used as the previous_hash for the first entry in a chain
GENESIS_HASH = "0" * 64


class HashChainedContextManager:
    """Manage hash-chained context entries per session.

    Each session has an independent hash chain. Entries are appended
    sequentially and each entry's chain_hash links it to the previous
    entry's chain_hash.
    """

    @staticmethod
    def compute_content_hash(content: str) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def compute_chain_hash(previous_hash: str, content_hash: str) -> str:
        """Compute chain link hash: SHA-256(previous_hash || content_hash)."""
        combined = (previous_hash + content_hash).encode("utf-8")
        return hashlib.sha256(combined).hexdigest()

    async def append(
        self,
        session_id: str,
        content: str,
        source: str = "",
        agent_id: str | None = None,
        tenant_id: str = "default",
    ) -> HashChainedContextEntry:
        """Append a new entry to the session's hash chain.

        Args:
            session_id: Session identifier.
            content: Raw content string to hash and chain.
            source: Origin source label.
            agent_id: Agent that produced this entry.
            tenant_id: Tenant identifier for isolation.

        Returns:
            The newly created and persisted HashChainedContextEntry.
        """
        db = db_module.get_database()
        collection = db[db_module.HASH_CHAINED_CONTEXT]

        # Get the last entry in this session's chain
        last_doc = await collection.find_one(
            {"session_id": session_id},
            sort=[("sequence_number", -1)],
        )

        if last_doc:
            previous_hash = last_doc["chain_hash"]
            sequence_number = last_doc["sequence_number"] + 1
        else:
            previous_hash = GENESIS_HASH
            sequence_number = 0

        content_hash = self.compute_content_hash(content)
        chain_hash = self.compute_chain_hash(previous_hash, content_hash)

        entry = HashChainedContextEntry(
            session_id=session_id,
            sequence_number=sequence_number,
            content_hash=content_hash,
            previous_hash=previous_hash,
            chain_hash=chain_hash,
            source=source,
            agent_id=agent_id,
            tenant_id=tenant_id,
        )

        await collection.insert_one(entry.model_dump(mode="json"))

        # Emit Prometheus metric
        try:
            from app.core.observability import HASH_CHAIN_ENTRIES

            HASH_CHAIN_ENTRIES.inc()
        except Exception:
            pass

        logger.debug(
            "hash_chain_appended session_id=%s seq=%d",
            session_id,
            sequence_number,
        )
        return entry

    async def verify_chain(
        self,
        session_id: str,
        tenant_id: str | None = None,
    ) -> HashChainVerificationResult:
        """Verify the integrity of a session's hash chain.

        Walks the chain from genesis to the latest entry, recomputing
        each chain_hash and comparing it to the stored value.

        Args:
            session_id: Session to verify.
            tenant_id: Optional tenant filter.

        Returns:
            HashChainVerificationResult with verification outcome.
        """
        db = db_module.get_database()
        collection = db[db_module.HASH_CHAINED_CONTEXT]

        query: dict[str, Any] = {"session_id": session_id}
        if tenant_id:
            query["tenant_id"] = tenant_id

        cursor = collection.find(query).sort("sequence_number", 1)
        entries = await cursor.to_list(length=100000)

        if not entries:
            return HashChainVerificationResult(
                valid=True,
                total_entries=0,
                verified_entries=0,
                detail="No entries found for session",
            )

        verified = 0
        expected_previous = GENESIS_HASH

        for doc in entries:
            content_hash = doc["content_hash"]
            stored_chain_hash = doc["chain_hash"]
            stored_previous_hash = doc["previous_hash"]
            seq = doc["sequence_number"]

            # Verify previous_hash links correctly
            if stored_previous_hash != expected_previous:
                try:
                    from app.core.observability import HASH_CHAIN_VERIFICATIONS
                    HASH_CHAIN_VERIFICATIONS.labels(result="tampered").inc()
                except Exception:
                    pass
                return HashChainVerificationResult(
                    valid=False,
                    total_entries=len(entries),
                    verified_entries=verified,
                    first_tampered_sequence=seq,
                    first_tampered_entry_id=str(doc.get("entry_id", "")),
                    detail=f"previous_hash mismatch at sequence {seq}",
                )

            # Recompute chain_hash and verify
            recomputed = self.compute_chain_hash(expected_previous, content_hash)
            if recomputed != stored_chain_hash:
                try:
                    from app.core.observability import HASH_CHAIN_VERIFICATIONS
                    HASH_CHAIN_VERIFICATIONS.labels(result="tampered").inc()
                except Exception:
                    pass
                return HashChainVerificationResult(
                    valid=False,
                    total_entries=len(entries),
                    verified_entries=verified,
                    first_tampered_sequence=seq,
                    first_tampered_entry_id=str(doc.get("entry_id", "")),
                    detail=f"chain_hash mismatch at sequence {seq}",
                )

            expected_previous = stored_chain_hash
            verified += 1

        # Emit Prometheus metric
        try:
            from app.core.observability import HASH_CHAIN_VERIFICATIONS

            HASH_CHAIN_VERIFICATIONS.labels(result="valid").inc()
        except Exception:
            pass

        return HashChainVerificationResult(
            valid=True,
            total_entries=len(entries),
            verified_entries=verified,
            detail="All entries verified successfully",
        )

    async def get_chain(
        self,
        session_id: str,
        tenant_id: str | None = None,
    ) -> list[HashChainedContextEntry]:
        """Retrieve all entries in a session's hash chain, ordered by sequence."""
        db = db_module.get_database()
        collection = db[db_module.HASH_CHAINED_CONTEXT]

        query: dict[str, Any] = {"session_id": session_id}
        if tenant_id:
            query["tenant_id"] = tenant_id

        cursor = collection.find(query).sort("sequence_number", 1)
        docs = await cursor.to_list(length=100000)
        return [HashChainedContextEntry(**doc) for doc in docs]

    async def get_latest(
        self,
        session_id: str,
    ) -> HashChainedContextEntry | None:
        """Get the latest entry in a session's hash chain."""
        db = db_module.get_database()
        collection = db[db_module.HASH_CHAINED_CONTEXT]

        doc = await collection.find_one(
            {"session_id": session_id},
            sort=[("sequence_number", -1)],
        )
        if doc:
            return HashChainedContextEntry(**doc)
        return None


# Module-level singleton
hash_chained_context = HashChainedContextManager()
