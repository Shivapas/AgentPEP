"""Sprint 41 — APEP-326: Plan-scoped checkpoint approval memory.

Provides a plan-scoped approval memory that remembers when a human
has already approved a checkpoint pattern for a given agent+tool
combination within a specific plan. This prevents re-escalation for
the same checkpoint within the same plan context.

Unlike the global approval memory (APEP-077), this memory is scoped
to a plan_id, so approvals in one plan do not leak to another.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID

from app.models.scope_pattern import PlanCheckpointApproval

logger = logging.getLogger(__name__)


class CheckpointApprovalMemory:
    """Plan-scoped checkpoint approval memory store.

    Checks whether a checkpoint-triggered escalation has already been
    approved for a given plan + agent + tool combination. Stores
    approvals in MongoDB with optional expiry.
    """

    async def check(
        self,
        *,
        plan_id: UUID,
        agent_id: str,
        tool_name: str,
        matched_pattern: str,
    ) -> bool:
        """Check if there is an existing approval for this checkpoint.

        Returns True if a valid (non-expired) approval exists, meaning
        the escalation can be skipped.
        """
        from app.db import mongodb as db_module
        from app.db.mongodb import PLAN_CHECKPOINT_APPROVALS

        try:
            db = db_module.get_database()
            now = datetime.now(UTC)
            query = {
                "plan_id": str(plan_id),
                "agent_id": agent_id,
                "tool_name": tool_name,
                "matched_pattern": matched_pattern,
            }

            doc = await db[PLAN_CHECKPOINT_APPROVALS].find_one(query)
            if doc is None:
                return False

            # Check expiry
            expires_at = doc.get("expires_at")
            if expires_at is not None:
                if isinstance(expires_at, str):
                    expires_at = datetime.fromisoformat(expires_at)
                if now >= expires_at:
                    return False

            return True

        except Exception:
            logger.warning(
                "Checkpoint approval memory check failed; treating as no approval",
                exc_info=True,
            )
            return False

    async def store(
        self,
        approval: PlanCheckpointApproval,
    ) -> None:
        """Store a checkpoint approval in plan-scoped memory."""
        from app.db import mongodb as db_module
        from app.db.mongodb import PLAN_CHECKPOINT_APPROVALS

        try:
            db = db_module.get_database()
            await db[PLAN_CHECKPOINT_APPROVALS].insert_one(
                approval.model_dump(mode="json")
            )
            logger.info(
                "checkpoint_approval_stored",
                extra={
                    "plan_id": str(approval.plan_id),
                    "agent_id": approval.agent_id,
                    "tool_name": approval.tool_name,
                    "pattern": approval.matched_pattern,
                },
            )
        except Exception:
            logger.exception("Failed to store checkpoint approval")

    async def revoke(
        self,
        *,
        plan_id: UUID,
        agent_id: str | None = None,
        tool_name: str | None = None,
    ) -> int:
        """Revoke checkpoint approvals for a plan (optionally filtered).

        Returns the number of approvals revoked.
        """
        from app.db import mongodb as db_module
        from app.db.mongodb import PLAN_CHECKPOINT_APPROVALS

        try:
            db = db_module.get_database()
            query: dict = {"plan_id": str(plan_id)}
            if agent_id is not None:
                query["agent_id"] = agent_id
            if tool_name is not None:
                query["tool_name"] = tool_name

            result = await db[PLAN_CHECKPOINT_APPROVALS].delete_many(query)
            return result.deleted_count
        except Exception:
            logger.exception("Failed to revoke checkpoint approvals")
            return 0

    async def list_approvals(
        self,
        plan_id: UUID,
    ) -> list[PlanCheckpointApproval]:
        """List all checkpoint approvals for a plan."""
        from app.db import mongodb as db_module
        from app.db.mongodb import PLAN_CHECKPOINT_APPROVALS

        try:
            db = db_module.get_database()
            approvals: list[PlanCheckpointApproval] = []
            cursor = db[PLAN_CHECKPOINT_APPROVALS].find(
                {"plan_id": str(plan_id)}
            )
            async for doc in cursor:
                approvals.append(
                    PlanCheckpointApproval(
                        **{k: v for k, v in doc.items() if k != "_id"}
                    )
                )
            return approvals
        except Exception:
            logger.exception("Failed to list checkpoint approvals")
            return []


# Module-level singleton
checkpoint_approval_memory = CheckpointApprovalMemory()
