"""Sprint 40 — PlanBudgetGate: pre-evaluation budget enforcement.

APEP-318: PlanBudgetGate with Redis-backed budget state tracking.
APEP-319: Budget exhaustion enforcement — deny when TTL, delegation
          count, or risk budget is exceeded.
APEP-320: Budget status API logic.
APEP-321: Budget alert event emission.
APEP-322: Plan budget reset logic.

The PlanBudgetGate runs as a pre-evaluation stage in the PolicyEvaluator
pipeline.  It checks:
  1. Plan TTL expiry
  2. Delegation count limit (max_delegations)
  3. Accumulated risk budget (max_risk_total)

Budget state is tracked in Redis for low-latency reads/writes, with
MongoDB as the durable fallback.  Alert events are emitted when budget
utilization crosses configurable thresholds (80% = WARNING, 95% = CRITICAL,
100% = EXHAUSTED).
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.config import settings
from app.db import mongodb as db_module
from app.models.mission_plan import (
    MissionPlan,
    PlanBudget,
    PlanDenialReason,
    PlanStatus,
)
from app.models.plan_budget_gate import (
    BudgetAlertEvent,
    BudgetAlertLevel,
    BudgetCheckResult,
    BudgetDimension,
    BudgetResetRequest,
    BudgetResetResponse,
    BudgetStatusResponse,
    BudgetUtilization,
    PlanBudgetState,
)

logger = logging.getLogger(__name__)

# Alert thresholds (percentage utilization)
_WARNING_THRESHOLD = 0.80
_CRITICAL_THRESHOLD = 0.95

# Redis key prefix for budget state
_REDIS_KEY_PREFIX = "agentpep:plan_budget"


class PlanBudgetGate:
    """Pre-evaluation budget gate for MissionPlans.

    Enforces TTL, delegation count, and risk budget constraints.
    Budget state is tracked in Redis (when available) for sub-millisecond
    checks, with MongoDB as the authoritative fallback.
    """

    def __init__(self) -> None:
        self._redis = None
        self._alert_handlers: list = []

    # ------------------------------------------------------------------
    # Redis connection management
    # ------------------------------------------------------------------

    async def _get_redis(self):
        """Lazily connect to Redis for budget state caching."""
        if self._redis is not None:
            return self._redis
        try:
            import redis.asyncio as aioredis

            self._redis = aioredis.from_url(
                settings.redis_url,
                decode_responses=True,
            )
            await self._redis.ping()
            logger.info("plan_budget_gate_redis_connected")
            return self._redis
        except Exception:
            logger.debug(
                "Redis unavailable for PlanBudgetGate; using MongoDB fallback"
            )
            self._redis = None
            return None

    def _budget_key(self, plan_id: UUID) -> str:
        """Redis key for a plan's budget state."""
        return f"{_REDIS_KEY_PREFIX}:{plan_id}"

    # ------------------------------------------------------------------
    # APEP-318/319: Budget check (core gate logic)
    # ------------------------------------------------------------------

    async def check(self, plan: MissionPlan) -> BudgetCheckResult:
        """Check if a plan's budget permits another delegation.

        Returns a :class:`BudgetCheckResult` indicating whether the
        operation is allowed and which dimensions (if any) are exhausted.
        """
        exhausted: list[BudgetDimension] = []
        now = datetime.now(UTC)

        # 1. Plan status check
        if plan.status == PlanStatus.REVOKED:
            return BudgetCheckResult(
                allowed=False,
                plan_id=plan.plan_id,
                exhausted_dimensions=[],
                reason=PlanDenialReason.PLAN_REVOKED,
                delegation_count=plan.delegation_count,
                accumulated_risk=plan.accumulated_risk,
            )

        if plan.status == PlanStatus.EXPIRED:
            return BudgetCheckResult(
                allowed=False,
                plan_id=plan.plan_id,
                exhausted_dimensions=[BudgetDimension.TTL],
                reason=PlanDenialReason.PLAN_EXPIRED,
                delegation_count=plan.delegation_count,
                accumulated_risk=plan.accumulated_risk,
            )

        # 2. TTL expiry check
        ttl_remaining: int | None = None
        if plan.expires_at is not None:
            if now >= plan.expires_at:
                exhausted.append(BudgetDimension.TTL)
            else:
                ttl_remaining = int((plan.expires_at - now).total_seconds())

        # 3. Get current budget state (Redis or MongoDB fallback)
        state = await self._get_budget_state(plan)

        # 4. Delegation count check
        remaining_delegations: int | None = None
        if plan.budget.max_delegations is not None:
            remaining_delegations = max(
                0, plan.budget.max_delegations - state.delegation_count
            )
            if state.delegation_count >= plan.budget.max_delegations:
                exhausted.append(BudgetDimension.DELEGATION_COUNT)

        # 5. Risk budget check
        remaining_risk: float | None = None
        if plan.budget.max_risk_total is not None:
            remaining_risk = max(
                0.0, plan.budget.max_risk_total - state.accumulated_risk
            )
            if state.accumulated_risk >= plan.budget.max_risk_total:
                exhausted.append(BudgetDimension.RISK_TOTAL)

        if exhausted:
            reason = (
                f"{PlanDenialReason.PLAN_BUDGET_EXHAUSTED}: "
                f"exhausted dimensions: {[d.value for d in exhausted]}"
            )
            return BudgetCheckResult(
                allowed=False,
                plan_id=plan.plan_id,
                exhausted_dimensions=exhausted,
                reason=reason,
                delegation_count=state.delegation_count,
                accumulated_risk=state.accumulated_risk,
                remaining_delegations=remaining_delegations,
                remaining_risk_budget=remaining_risk,
                ttl_remaining_seconds=ttl_remaining,
            )

        return BudgetCheckResult(
            allowed=True,
            plan_id=plan.plan_id,
            exhausted_dimensions=[],
            reason="Budget OK",
            delegation_count=state.delegation_count,
            accumulated_risk=state.accumulated_risk,
            remaining_delegations=remaining_delegations,
            remaining_risk_budget=remaining_risk,
            ttl_remaining_seconds=ttl_remaining,
        )

    # ------------------------------------------------------------------
    # APEP-319: Record delegation (increment counters)
    # ------------------------------------------------------------------

    async def record_delegation(
        self, plan: MissionPlan, risk_score: float
    ) -> PlanBudgetState:
        """Increment delegation count and accumulated risk for a plan.

        Updates both Redis (if available) and MongoDB. Emits alert events
        when budget thresholds are crossed.
        """
        # Update MongoDB (authoritative)
        db = db_module.get_database()
        await db[db_module.MISSION_PLANS].update_one(
            {"plan_id": str(plan.plan_id)},
            {
                "$inc": {
                    "delegation_count": 1,
                    "accumulated_risk": risk_score,
                }
            },
        )

        # Update Redis cache
        redis = await self._get_redis()
        new_count = plan.delegation_count + 1
        new_risk = plan.accumulated_risk + risk_score

        if redis is not None:
            try:
                key = self._budget_key(plan.plan_id)
                pipe = redis.pipeline()
                pipe.hset(key, "delegation_count", str(new_count))
                pipe.hset(key, "accumulated_risk", str(new_risk))
                pipe.hset(
                    key,
                    "last_updated",
                    datetime.now(UTC).isoformat(),
                )
                # Set TTL on the Redis key to match plan TTL + buffer
                if plan.expires_at is not None:
                    ttl = int(
                        (plan.expires_at - datetime.now(UTC)).total_seconds()
                    ) + 300  # 5 min buffer
                    if ttl > 0:
                        pipe.expire(key, ttl)
                await pipe.execute()
            except Exception:
                logger.debug(
                    "Redis budget state update failed; MongoDB is authoritative",
                    exc_info=True,
                )

        state = PlanBudgetState(
            plan_id=plan.plan_id,
            delegation_count=new_count,
            accumulated_risk=new_risk,
        )

        # Emit alert events at thresholds
        await self._check_and_emit_alerts(plan, state)

        return state

    # ------------------------------------------------------------------
    # Internal: Get budget state (Redis → MongoDB fallback)
    # ------------------------------------------------------------------

    async def _get_budget_state(self, plan: MissionPlan) -> PlanBudgetState:
        """Read current budget state from Redis, falling back to MongoDB."""
        redis = await self._get_redis()
        if redis is not None:
            try:
                key = self._budget_key(plan.plan_id)
                data = await redis.hgetall(key)
                if data and "delegation_count" in data:
                    return PlanBudgetState(
                        plan_id=plan.plan_id,
                        delegation_count=int(data["delegation_count"]),
                        accumulated_risk=float(data["accumulated_risk"]),
                    )
            except Exception:
                logger.debug(
                    "Redis budget state read failed; using MongoDB",
                    exc_info=True,
                )

        # MongoDB fallback — use the values already on the plan object
        return PlanBudgetState(
            plan_id=plan.plan_id,
            delegation_count=plan.delegation_count,
            accumulated_risk=plan.accumulated_risk,
        )

    # ------------------------------------------------------------------
    # APEP-320: Budget Status
    # ------------------------------------------------------------------

    async def get_budget_status(
        self, plan: MissionPlan
    ) -> BudgetStatusResponse:
        """Return the current budget status for a plan."""
        state = await self._get_budget_state(plan)
        now = datetime.now(UTC)

        exhausted: list[BudgetDimension] = []
        ttl_remaining: int | None = None

        # TTL
        if plan.expires_at is not None:
            if now >= plan.expires_at:
                exhausted.append(BudgetDimension.TTL)
            else:
                ttl_remaining = int(
                    (plan.expires_at - now).total_seconds()
                )

        # Delegations
        if (
            plan.budget.max_delegations is not None
            and state.delegation_count >= plan.budget.max_delegations
        ):
            exhausted.append(BudgetDimension.DELEGATION_COUNT)

        # Risk
        if (
            plan.budget.max_risk_total is not None
            and state.accumulated_risk >= plan.budget.max_risk_total
        ):
            exhausted.append(BudgetDimension.RISK_TOTAL)

        # Determine status label
        if plan.status == PlanStatus.REVOKED:
            status_label = "REVOKED"
        elif plan.status == PlanStatus.EXPIRED or BudgetDimension.TTL in exhausted:
            status_label = "EXPIRED"
        elif exhausted:
            status_label = "BUDGET_EXHAUSTED"
        else:
            status_label = "ACTIVE"

        # Utilization percentages
        utilization = self._compute_utilization(plan, state, now)

        return BudgetStatusResponse(
            plan_id=plan.plan_id,
            status=status_label,
            delegation_count=state.delegation_count,
            max_delegations=plan.budget.max_delegations,
            accumulated_risk=state.accumulated_risk,
            max_risk_total=plan.budget.max_risk_total,
            ttl_seconds=plan.budget.ttl_seconds,
            ttl_remaining_seconds=ttl_remaining,
            issued_at=plan.issued_at,
            expires_at=plan.expires_at,
            exhausted_dimensions=exhausted,
            budget_utilization=utilization,
        )

    @staticmethod
    def _compute_utilization(
        plan: MissionPlan, state: PlanBudgetState, now: datetime
    ) -> BudgetUtilization:
        """Compute percentage utilization for each budget dimension."""
        delegation_pct: float | None = None
        risk_pct: float | None = None
        ttl_pct: float | None = None

        if (
            plan.budget.max_delegations is not None
            and plan.budget.max_delegations > 0
        ):
            delegation_pct = min(
                100.0,
                (state.delegation_count / plan.budget.max_delegations) * 100,
            )

        if (
            plan.budget.max_risk_total is not None
            and plan.budget.max_risk_total > 0
        ):
            risk_pct = min(
                100.0,
                (state.accumulated_risk / plan.budget.max_risk_total) * 100,
            )

        if plan.budget.ttl_seconds is not None and plan.budget.ttl_seconds > 0:
            elapsed = (now - plan.issued_at).total_seconds()
            ttl_pct = min(
                100.0, (elapsed / plan.budget.ttl_seconds) * 100
            )

        return BudgetUtilization(
            delegation_pct=delegation_pct,
            risk_pct=risk_pct,
            ttl_pct=ttl_pct,
        )

    # ------------------------------------------------------------------
    # APEP-321: Budget alert events
    # ------------------------------------------------------------------

    def register_alert_handler(self, handler) -> None:
        """Register a callback for budget alert events.

        Handler signature: ``async def handler(event: BudgetAlertEvent) -> None``
        """
        self._alert_handlers.append(handler)

    async def _check_and_emit_alerts(
        self, plan: MissionPlan, state: PlanBudgetState
    ) -> list[BudgetAlertEvent]:
        """Check budget thresholds and emit alert events."""
        alerts: list[BudgetAlertEvent] = []

        # Delegation count alerts
        if (
            plan.budget.max_delegations is not None
            and plan.budget.max_delegations > 0
        ):
            utilization = state.delegation_count / plan.budget.max_delegations
            alert = self._maybe_create_alert(
                plan_id=plan.plan_id,
                dimension=BudgetDimension.DELEGATION_COUNT,
                current=float(state.delegation_count),
                maximum=float(plan.budget.max_delegations),
                utilization=utilization,
            )
            if alert is not None:
                alerts.append(alert)

        # Risk total alerts
        if (
            plan.budget.max_risk_total is not None
            and plan.budget.max_risk_total > 0
        ):
            utilization = state.accumulated_risk / plan.budget.max_risk_total
            alert = self._maybe_create_alert(
                plan_id=plan.plan_id,
                dimension=BudgetDimension.RISK_TOTAL,
                current=state.accumulated_risk,
                maximum=plan.budget.max_risk_total,
                utilization=utilization,
            )
            if alert is not None:
                alerts.append(alert)

        # Publish alerts
        for alert in alerts:
            logger.info(
                "plan_budget_alert",
                extra={
                    "plan_id": str(alert.plan_id),
                    "alert_level": alert.alert_level,
                    "dimension": alert.dimension,
                    "utilization_pct": alert.utilization_pct,
                },
            )
            for handler in self._alert_handlers:
                try:
                    await handler(alert)
                except Exception:
                    logger.warning(
                        "Budget alert handler failed",
                        exc_info=True,
                    )

            # Publish to Kafka if available
            await self._publish_alert_kafka(alert)

        return alerts

    @staticmethod
    def _maybe_create_alert(
        *,
        plan_id: UUID,
        dimension: BudgetDimension,
        current: float,
        maximum: float,
        utilization: float,
    ) -> BudgetAlertEvent | None:
        """Create an alert event if utilization crosses a threshold."""
        if utilization >= 1.0:
            level = BudgetAlertLevel.EXHAUSTED
            threshold = maximum
        elif utilization >= _CRITICAL_THRESHOLD:
            level = BudgetAlertLevel.CRITICAL
            threshold = maximum * _CRITICAL_THRESHOLD
        elif utilization >= _WARNING_THRESHOLD:
            level = BudgetAlertLevel.WARNING
            threshold = maximum * _WARNING_THRESHOLD
        else:
            return None

        return BudgetAlertEvent(
            plan_id=plan_id,
            alert_level=level,
            dimension=dimension,
            current_value=current,
            threshold_value=threshold,
            max_value=maximum,
            utilization_pct=round(utilization * 100, 2),
            message=(
                f"Plan {plan_id} budget {dimension.value}: "
                f"{level.value} at {round(utilization * 100, 1)}% "
                f"({current}/{maximum})"
            ),
        )

    @staticmethod
    async def _publish_alert_kafka(alert: BudgetAlertEvent) -> None:
        """Publish budget alert event to Kafka topic."""
        if not settings.kafka_enabled:
            return
        try:
            from app.services.kafka_producer import kafka_producer

            if kafka_producer._started:
                await kafka_producer._producer.send(
                    "agentpep.plan_budget_alerts",
                    value=alert.model_dump(mode="json"),
                    key=str(alert.plan_id),
                )
        except Exception:
            logger.debug(
                "Failed to publish budget alert to Kafka",
                exc_info=True,
            )

    # ------------------------------------------------------------------
    # APEP-322: Plan Budget Reset
    # ------------------------------------------------------------------

    async def reset_budget(
        self, plan: MissionPlan, request: BudgetResetRequest
    ) -> BudgetResetResponse:
        """Reset a plan's budget counters and optionally update limits.

        Can reactivate an EXPIRED plan if budget limits are reset.
        """
        prev_count = plan.delegation_count
        prev_risk = plan.accumulated_risk
        now = datetime.now(UTC)

        update_fields: dict = {}
        budget_updated = False
        plan_reactivated = False

        # Reset counters
        new_count = 0 if request.reset_delegations else plan.delegation_count
        new_risk = 0.0 if request.reset_risk else plan.accumulated_risk

        update_fields["delegation_count"] = new_count
        update_fields["accumulated_risk"] = new_risk

        # Update budget limits if specified
        budget_dict = plan.budget.model_dump()
        if request.new_max_delegations is not None:
            budget_dict["max_delegations"] = request.new_max_delegations
            budget_updated = True
        if request.new_max_risk_total is not None:
            budget_dict["max_risk_total"] = request.new_max_risk_total
            budget_updated = True
        if request.new_ttl_seconds is not None:
            budget_dict["ttl_seconds"] = request.new_ttl_seconds
            update_fields["expires_at"] = (
                now + timedelta(seconds=request.new_ttl_seconds)
            ).isoformat()
            budget_updated = True

        if budget_updated:
            update_fields["budget"] = budget_dict

        # Reactivate plan if it was budget-exhausted (EXPIRED)
        if plan.status == PlanStatus.EXPIRED:
            update_fields["status"] = PlanStatus.ACTIVE
            plan_reactivated = True

        # Update MongoDB
        db = db_module.get_database()
        await db[db_module.MISSION_PLANS].update_one(
            {"plan_id": str(plan.plan_id)},
            {"$set": update_fields},
        )

        # Update Redis cache
        redis = await self._get_redis()
        if redis is not None:
            try:
                key = self._budget_key(plan.plan_id)
                await redis.hset(key, "delegation_count", str(new_count))
                await redis.hset(key, "accumulated_risk", str(new_risk))
                await redis.hset(
                    key, "last_updated", now.isoformat()
                )
            except Exception:
                logger.debug(
                    "Redis budget reset update failed",
                    exc_info=True,
                )

        logger.info(
            "plan_budget_reset",
            extra={
                "plan_id": str(plan.plan_id),
                "previous_delegation_count": prev_count,
                "previous_accumulated_risk": prev_risk,
                "new_delegation_count": new_count,
                "new_accumulated_risk": new_risk,
                "budget_updated": budget_updated,
                "plan_reactivated": plan_reactivated,
                "reason": request.reason,
            },
        )

        return BudgetResetResponse(
            plan_id=plan.plan_id,
            reset_at=now,
            previous_delegation_count=prev_count,
            previous_accumulated_risk=prev_risk,
            new_delegation_count=new_count,
            new_accumulated_risk=new_risk,
            budget_updated=budget_updated,
            plan_reactivated=plan_reactivated,
        )


# Module-level singleton
plan_budget_gate = PlanBudgetGate()
