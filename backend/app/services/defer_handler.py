"""DeferHandler — manages DEFER decision lifecycle.

Sprint 36 — APEP-287: When the policy evaluator issues a DEFER decision,
the request is parked in a pending queue. The DEFER decision tells the
caller to retry after a timeout or await resolution. If the timeout
expires without resolution, the decision auto-denies.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID

from app.db import mongodb as db_module
from app.models.sprint36 import DeferCondition, DeferDecisionRecord

logger = logging.getLogger(__name__)


class DeferHandler:
    """Manage DEFER decision records."""

    async def create_deferral(
        self,
        request_id: UUID,
        session_id: str,
        agent_id: str,
        tool_name: str,
        condition: DeferCondition = DeferCondition.PENDING_REVIEW,
        reason: str = "",
        timeout_s: int = 60,
        tenant_id: str = "default",
    ) -> DeferDecisionRecord:
        """Create a new DEFER decision record.

        Args:
            request_id: Original tool call request ID.
            session_id: Session identifier.
            agent_id: Agent that made the request.
            tool_name: Tool being deferred.
            condition: Why the decision was deferred.
            reason: Human-readable reason.
            timeout_s: Seconds before auto-deny.
            tenant_id: Tenant identifier.

        Returns:
            The created DeferDecisionRecord.
        """
        record = DeferDecisionRecord(
            request_id=request_id,
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            condition=condition,
            reason=reason,
            timeout_s=timeout_s,
            tenant_id=tenant_id,
        )

        db = db_module.get_database()
        await db[db_module.DEFER_DECISIONS].insert_one(
            record.model_dump(mode="json")
        )

        logger.info(
            "defer_created defer_id=%s session_id=%s tool=%s condition=%s timeout=%ds",
            record.defer_id,
            session_id,
            tool_name,
            condition.value,
            timeout_s,
        )
        return record

    async def resolve(
        self,
        defer_id: UUID,
        resolution: str,
    ) -> DeferDecisionRecord | None:
        """Resolve a pending DEFER decision.

        Args:
            defer_id: ID of the defer record to resolve.
            resolution: Resolution outcome (e.g., 'ALLOW', 'DENY').

        Returns:
            Updated record, or None if not found.
        """
        db = db_module.get_database()
        collection = db[db_module.DEFER_DECISIONS]

        result = await collection.find_one_and_update(
            {"defer_id": str(defer_id), "resolved": False},
            {
                "$set": {
                    "resolved": True,
                    "resolution": resolution,
                    "resolved_at": datetime.now(UTC).isoformat(),
                }
            },
            return_document=True,
        )

        if result:
            logger.info(
                "defer_resolved defer_id=%s resolution=%s",
                defer_id,
                resolution,
            )
            return DeferDecisionRecord(**result)

        logger.warning("defer_not_found defer_id=%s", defer_id)
        return None

    async def get_pending(
        self,
        session_id: str | None = None,
        tenant_id: str | None = None,
    ) -> list[DeferDecisionRecord]:
        """List pending (unresolved) DEFER decisions.

        Args:
            session_id: Filter by session (optional).
            tenant_id: Filter by tenant (optional).

        Returns:
            List of pending DeferDecisionRecords.
        """
        db = db_module.get_database()
        collection = db[db_module.DEFER_DECISIONS]

        query: dict = {"resolved": False}
        if session_id:
            query["session_id"] = session_id
        if tenant_id:
            query["tenant_id"] = tenant_id

        cursor = collection.find(query).sort("created_at", -1)
        docs = await cursor.to_list(length=1000)
        return [DeferDecisionRecord(**doc) for doc in docs]

    async def get_by_id(self, defer_id: UUID) -> DeferDecisionRecord | None:
        """Get a defer record by ID."""
        db = db_module.get_database()
        doc = await db[db_module.DEFER_DECISIONS].find_one(
            {"defer_id": str(defer_id)}
        )
        if doc:
            return DeferDecisionRecord(**doc)
        return None

    async def auto_deny_expired(self) -> int:
        """Auto-deny all expired, unresolved DEFER decisions.

        Returns the number of records auto-denied.
        """
        db = db_module.get_database()
        collection = db[db_module.DEFER_DECISIONS]
        now = datetime.now(UTC)

        # Find unresolved deferrals and check timeout
        cursor = collection.find({"resolved": False})
        docs = await cursor.to_list(length=10000)

        auto_denied = 0
        for doc in docs:
            created_at = doc.get("created_at")
            timeout_s = doc.get("timeout_s", 60)

            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at)

            if created_at and (now - created_at).total_seconds() > timeout_s:
                await collection.update_one(
                    {"defer_id": doc["defer_id"]},
                    {
                        "$set": {
                            "resolved": True,
                            "resolution": "AUTO_DENIED",
                            "resolved_at": now.isoformat(),
                        }
                    },
                )
                auto_denied += 1
                logger.info(
                    "defer_auto_denied defer_id=%s session_id=%s",
                    doc["defer_id"],
                    doc["session_id"],
                )

        return auto_denied


# Module-level singleton
defer_handler = DeferHandler()
