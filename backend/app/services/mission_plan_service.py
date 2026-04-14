"""MissionPlanService -- CRUD, session binding, budget tracking, and TTL expiry.

Sprint 37:
  APEP-292: MissionPlan lifecycle management.
  APEP-294: Plan creation (with Ed25519 signing).
  APEP-295: Plan retrieval with budget status.
  APEP-296: Plan revocation.
  APEP-297: Plan-session binding.
  APEP-298: Plan TTL expiry background job.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.db import mongodb as db_module
from app.models.mission_plan import (
    BindPlanRequest,
    BindPlanResponse,
    CreatePlanRequest,
    CreatePlanResponse,
    MissionPlan,
    PlanBudget,
    PlanDetailResponse,
    PlanDenialReason,
    PlanSessionBinding,
    PlanStatus,
    RevokePlanResponse,
)

logger = logging.getLogger(__name__)


class MissionPlanService:
    """Core service for MissionPlan CRUD, session binding, and budget management."""

    # ------------------------------------------------------------------
    # APEP-294: Create plan
    # ------------------------------------------------------------------

    async def create_plan(self, request: CreatePlanRequest) -> MissionPlan:
        """Create a new MissionPlan, sign it, and persist to MongoDB."""
        from app.services.plan_signer import plan_signer

        now = datetime.now(UTC)
        expires_at: datetime | None = None
        if request.budget.ttl_seconds is not None:
            expires_at = now + timedelta(seconds=request.budget.ttl_seconds)

        plan = MissionPlan(
            action=request.action,
            issuer=request.issuer,
            scope=request.scope,
            requires_checkpoint=request.requires_checkpoint,
            delegates_to=request.delegates_to,
            budget=request.budget,
            status=PlanStatus.ACTIVE,
            issued_at=now,
            expires_at=expires_at,
        )

        # Sign the plan
        if plan_signer is not None:
            plan.signature = plan_signer.sign_plan(plan)

        # Persist to MongoDB
        db = db_module.get_database()
        await db[db_module.MISSION_PLANS].insert_one(
            plan.model_dump(mode="json")
        )

        logger.info(
            "plan_created",
            extra={
                "plan_id": str(plan.plan_id),
                "issuer": plan.issuer,
                "action": plan.action,
            },
        )
        return plan

    # ------------------------------------------------------------------
    # APEP-295: Retrieve plan
    # ------------------------------------------------------------------

    async def get_plan(self, plan_id: UUID) -> MissionPlan | None:
        """Retrieve a MissionPlan by ID, refreshing expiry status."""
        db = db_module.get_database()
        doc = await db[db_module.MISSION_PLANS].find_one(
            {"plan_id": str(plan_id)}
        )
        if doc is None:
            return None

        plan = MissionPlan(**doc)

        # Auto-expire if TTL has elapsed but status not yet updated
        if (
            plan.status == PlanStatus.ACTIVE
            and plan.expires_at is not None
            and datetime.now(UTC) >= plan.expires_at
        ):
            plan.status = PlanStatus.EXPIRED
            await db[db_module.MISSION_PLANS].update_one(
                {"plan_id": str(plan_id)},
                {"$set": {"status": PlanStatus.EXPIRED}},
            )

        return plan

    async def get_plan_detail(self, plan_id: UUID) -> PlanDetailResponse | None:
        """Retrieve plan with computed budget status fields."""
        plan = await self.get_plan(plan_id)
        if plan is None:
            return None
        return PlanDetailResponse(
            plan_id=plan.plan_id,
            action=plan.action,
            issuer=plan.issuer,
            scope=plan.scope,
            requires_checkpoint=plan.requires_checkpoint,
            delegates_to=plan.delegates_to,
            budget=plan.budget,
            status=plan.status,
            signature=plan.signature,
            issued_at=plan.issued_at,
            expires_at=plan.expires_at,
            delegation_count=plan.delegation_count,
            accumulated_risk=plan.accumulated_risk,
            is_active=plan.is_active,
            budget_exhausted=plan.budget_exhausted,
        )

    # ------------------------------------------------------------------
    # APEP-296: Revoke plan
    # ------------------------------------------------------------------

    async def revoke_plan(self, plan_id: UUID) -> RevokePlanResponse | None:
        """Revoke a MissionPlan (sets status to REVOKED)."""
        db = db_module.get_database()
        now = datetime.now(UTC)
        result = await db[db_module.MISSION_PLANS].update_one(
            {"plan_id": str(plan_id), "status": PlanStatus.ACTIVE},
            {"$set": {"status": PlanStatus.REVOKED}},
        )
        if result.modified_count == 0:
            # Check if plan exists at all
            exists = await db[db_module.MISSION_PLANS].find_one(
                {"plan_id": str(plan_id)}
            )
            if exists is None:
                return None
            # Plan exists but not ACTIVE -- still return revoked status
            return RevokePlanResponse(
                plan_id=plan_id,
                status=PlanStatus(exists["status"]),
                revoked_at=now,
            )

        logger.info(
            "plan_revoked",
            extra={"plan_id": str(plan_id)},
        )
        return RevokePlanResponse(
            plan_id=plan_id,
            status=PlanStatus.REVOKED,
            revoked_at=now,
        )

    # ------------------------------------------------------------------
    # APEP-297: Plan-session binding
    # ------------------------------------------------------------------

    async def bind_session(
        self, plan_id: UUID, request: BindPlanRequest
    ) -> BindPlanResponse | None:
        """Bind a session to a MissionPlan.

        Returns None if the plan doesn't exist or is not active.
        """
        plan = await self.get_plan(plan_id)
        if plan is None or not plan.is_active:
            return None

        binding = PlanSessionBinding(
            plan_id=plan_id,
            session_id=request.session_id,
            agent_id=request.agent_id,
        )

        db = db_module.get_database()
        await db[db_module.PLAN_SESSION_BINDINGS].insert_one(
            binding.model_dump(mode="json")
        )

        logger.info(
            "plan_session_bound",
            extra={
                "plan_id": str(plan_id),
                "session_id": request.session_id,
                "agent_id": request.agent_id,
            },
        )
        return BindPlanResponse(
            binding_id=binding.binding_id,
            plan_id=plan_id,
            session_id=request.session_id,
            agent_id=request.agent_id,
            bound_at=binding.bound_at,
        )

    async def get_plan_for_session(self, session_id: str) -> MissionPlan | None:
        """Look up the active plan bound to a session."""
        db = db_module.get_database()
        binding = await db[db_module.PLAN_SESSION_BINDINGS].find_one(
            {"session_id": session_id, "active": True}
        )
        if binding is None:
            return None
        return await self.get_plan(UUID(binding["plan_id"]))

    async def unbind_session(self, session_id: str) -> bool:
        """Unbind a session from its plan."""
        db = db_module.get_database()
        result = await db[db_module.PLAN_SESSION_BINDINGS].update_many(
            {"session_id": session_id, "active": True},
            {
                "$set": {
                    "active": False,
                    "unbound_at": datetime.now(UTC).isoformat(),
                }
            },
        )
        return result.modified_count > 0

    # ------------------------------------------------------------------
    # Budget tracking (used by pipeline filters)
    # ------------------------------------------------------------------

    async def record_delegation(
        self, plan_id: UUID, risk_score: float
    ) -> None:
        """Increment delegation count and accumulated risk for a plan."""
        db = db_module.get_database()
        await db[db_module.MISSION_PLANS].update_one(
            {"plan_id": str(plan_id)},
            {
                "$inc": {
                    "delegation_count": 1,
                    "accumulated_risk": risk_score,
                }
            },
        )

    async def check_plan_budget(self, plan: MissionPlan) -> PlanDenialReason | None:
        """Check if a plan's budget constraints are satisfied.

        Returns a denial reason if budget is exhausted, None if OK.
        """
        if plan.status == PlanStatus.REVOKED:
            return PlanDenialReason.PLAN_REVOKED

        if plan.status == PlanStatus.EXPIRED:
            return PlanDenialReason.PLAN_EXPIRED

        if plan.expires_at is not None and datetime.now(UTC) >= plan.expires_at:
            return PlanDenialReason.PLAN_EXPIRED

        if plan.budget_exhausted:
            return PlanDenialReason.PLAN_BUDGET_EXHAUSTED

        return None

    def check_agent_authorized(
        self, plan: MissionPlan, agent_id: str
    ) -> bool:
        """Check if an agent is in the plan's delegates_to list.

        Empty delegates_to means no sub-delegation is allowed but the
        original session agent (bound via binding) is permitted.
        """
        if not plan.delegates_to:
            # No sub-delegation restriction -- any bound agent is allowed
            return True
        return agent_id in plan.delegates_to

    def check_requires_checkpoint(
        self, plan: MissionPlan, tool_name: str
    ) -> bool:
        """Check if a tool call matches any requires_checkpoint pattern.

        Uses fnmatch-style glob matching.
        """
        import fnmatch

        for pattern in plan.requires_checkpoint:
            if fnmatch.fnmatch(tool_name, pattern):
                return True
        return False


# Module-level singleton
mission_plan_service = MissionPlanService()


# ---------------------------------------------------------------------------
# APEP-298: Plan TTL Expiry Background Job
# ---------------------------------------------------------------------------


class PlanExpiryJob:
    """Background job that periodically expires plans whose TTL has elapsed."""

    def __init__(self, interval_s: float = 60.0) -> None:
        self._interval_s = interval_s
        self._running = False
        self._task: asyncio.Task | None = None  # type: ignore[type-arg]

    def start(self) -> None:
        """Start the background expiry loop (idempotent)."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.ensure_future(self._run_loop())

    def stop(self) -> None:
        """Signal the expiry loop to stop."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

    async def _run_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(self._interval_s)
                await self.expire_plans()
            except asyncio.CancelledError:
                return
            except Exception:
                logger.exception("Plan expiry job error")

    async def expire_plans(self) -> int:
        """Expire all active plans whose expires_at has passed.

        Returns the number of plans expired.
        """
        db = db_module.get_database()
        now = datetime.now(UTC)
        result = await db[db_module.MISSION_PLANS].update_many(
            {
                "status": PlanStatus.ACTIVE,
                "expires_at": {"$ne": None, "$lte": now.isoformat()},
            },
            {"$set": {"status": PlanStatus.EXPIRED}},
        )
        if result.modified_count > 0:
            logger.info(
                "plans_expired",
                extra={"count": result.modified_count},
            )
        return result.modified_count


# Module-level singleton
plan_expiry_job = PlanExpiryJob()
