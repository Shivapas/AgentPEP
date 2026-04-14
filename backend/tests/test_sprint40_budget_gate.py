"""Tests for Sprint 40 — PlanBudgetGate (APEP-318/319/320/321/322).

APEP-318.f: Unit tests for PlanBudgetGate.
APEP-319.e: Unit tests for budget exhaustion enforcement.
APEP-320.c: Unit tests for budget status API.
APEP-321.c: Unit tests for budget alert events.
APEP-322.c: Unit tests for plan budget reset.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from app.models.mission_plan import MissionPlan, PlanBudget, PlanDenialReason, PlanStatus
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
from app.services.plan_budget_gate import PlanBudgetGate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plan(**overrides) -> MissionPlan:
    defaults = {
        "action": "Analyze Q3 reports",
        "issuer": "admin@example.com",
        "scope": ["read:public:*"],
        "delegates_to": ["agent-alpha"],
        "budget": PlanBudget(
            max_delegations=10,
            max_risk_total=5.0,
            ttl_seconds=3600,
        ),
        "issued_at": datetime.now(UTC),
    }
    # Compute expires_at from ttl_seconds
    defaults.update(overrides)
    if "expires_at" not in overrides and defaults.get("budget"):
        budget = defaults["budget"]
        if isinstance(budget, PlanBudget) and budget.ttl_seconds is not None:
            defaults["expires_at"] = defaults["issued_at"] + timedelta(
                seconds=budget.ttl_seconds
            )
        elif isinstance(budget, dict) and budget.get("ttl_seconds") is not None:
            defaults["expires_at"] = defaults["issued_at"] + timedelta(
                seconds=budget["ttl_seconds"]
            )
    return MissionPlan(**defaults)


def _make_gate() -> PlanBudgetGate:
    """Create a fresh PlanBudgetGate with no Redis connection."""
    gate = PlanBudgetGate()
    gate._redis = None
    return gate


# ---------------------------------------------------------------------------
# APEP-318.f: PlanBudgetGate unit tests
# ---------------------------------------------------------------------------


class TestPlanBudgetGateCheck:
    """Budget gate check logic."""

    @pytest.mark.asyncio
    async def test_active_plan_within_budget_allowed(self):
        gate = _make_gate()
        plan = _make_plan(delegation_count=3, accumulated_risk=1.5)

        result = await gate.check(plan)

        assert result.allowed is True
        assert result.plan_id == plan.plan_id
        assert result.exhausted_dimensions == []
        assert result.delegation_count == 3
        assert result.accumulated_risk == 1.5

    @pytest.mark.asyncio
    async def test_revoked_plan_denied(self):
        gate = _make_gate()
        plan = _make_plan(status=PlanStatus.REVOKED)

        result = await gate.check(plan)

        assert result.allowed is False
        assert PlanDenialReason.PLAN_REVOKED in result.reason

    @pytest.mark.asyncio
    async def test_expired_plan_denied(self):
        gate = _make_gate()
        plan = _make_plan(status=PlanStatus.EXPIRED)

        result = await gate.check(plan)

        assert result.allowed is False
        assert PlanDenialReason.PLAN_EXPIRED in result.reason
        assert BudgetDimension.TTL in result.exhausted_dimensions

    @pytest.mark.asyncio
    async def test_ttl_expired_denied(self):
        gate = _make_gate()
        plan = _make_plan(
            issued_at=datetime.now(UTC) - timedelta(hours=2),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
            budget=PlanBudget(ttl_seconds=3600),
        )

        result = await gate.check(plan)

        assert result.allowed is False
        assert BudgetDimension.TTL in result.exhausted_dimensions

    @pytest.mark.asyncio
    async def test_ttl_remaining_computed(self):
        gate = _make_gate()
        plan = _make_plan(
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )

        result = await gate.check(plan)

        assert result.allowed is True
        assert result.ttl_remaining_seconds is not None
        assert result.ttl_remaining_seconds > 0
        assert result.ttl_remaining_seconds <= 1800

    @pytest.mark.asyncio
    async def test_no_ttl_means_no_remaining(self):
        gate = _make_gate()
        plan = _make_plan(
            budget=PlanBudget(max_delegations=10),
            expires_at=None,
        )

        result = await gate.check(plan)

        assert result.allowed is True
        assert result.ttl_remaining_seconds is None


# ---------------------------------------------------------------------------
# APEP-319.e: Budget exhaustion enforcement tests
# ---------------------------------------------------------------------------


class TestBudgetExhaustionEnforcement:
    """Test denial when budget dimensions are exceeded."""

    @pytest.mark.asyncio
    async def test_delegation_count_exhausted(self):
        gate = _make_gate()
        plan = _make_plan(
            delegation_count=10,
            budget=PlanBudget(max_delegations=10),
        )

        result = await gate.check(plan)

        assert result.allowed is False
        assert BudgetDimension.DELEGATION_COUNT in result.exhausted_dimensions
        assert "PLAN_BUDGET_EXHAUSTED" in result.reason

    @pytest.mark.asyncio
    async def test_delegation_count_over_limit(self):
        gate = _make_gate()
        plan = _make_plan(
            delegation_count=15,
            budget=PlanBudget(max_delegations=10),
        )

        result = await gate.check(plan)

        assert result.allowed is False
        assert BudgetDimension.DELEGATION_COUNT in result.exhausted_dimensions

    @pytest.mark.asyncio
    async def test_risk_total_exhausted(self):
        gate = _make_gate()
        plan = _make_plan(
            accumulated_risk=5.0,
            budget=PlanBudget(max_risk_total=5.0),
        )

        result = await gate.check(plan)

        assert result.allowed is False
        assert BudgetDimension.RISK_TOTAL in result.exhausted_dimensions

    @pytest.mark.asyncio
    async def test_risk_total_over_limit(self):
        gate = _make_gate()
        plan = _make_plan(
            accumulated_risk=7.5,
            budget=PlanBudget(max_risk_total=5.0),
        )

        result = await gate.check(plan)

        assert result.allowed is False
        assert BudgetDimension.RISK_TOTAL in result.exhausted_dimensions

    @pytest.mark.asyncio
    async def test_multiple_dimensions_exhausted(self):
        gate = _make_gate()
        plan = _make_plan(
            delegation_count=10,
            accumulated_risk=6.0,
            budget=PlanBudget(max_delegations=10, max_risk_total=5.0),
            issued_at=datetime.now(UTC) - timedelta(hours=2),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )

        result = await gate.check(plan)

        assert result.allowed is False
        assert len(result.exhausted_dimensions) >= 2

    @pytest.mark.asyncio
    async def test_unlimited_delegations_allowed(self):
        gate = _make_gate()
        plan = _make_plan(
            delegation_count=10000,
            budget=PlanBudget(max_delegations=None),
        )

        result = await gate.check(plan)

        assert result.allowed is True
        assert result.remaining_delegations is None

    @pytest.mark.asyncio
    async def test_unlimited_risk_allowed(self):
        gate = _make_gate()
        plan = _make_plan(
            accumulated_risk=999.0,
            budget=PlanBudget(max_risk_total=None),
        )

        result = await gate.check(plan)

        assert result.allowed is True
        assert result.remaining_risk_budget is None

    @pytest.mark.asyncio
    async def test_remaining_delegations_computed(self):
        gate = _make_gate()
        plan = _make_plan(
            delegation_count=7,
            budget=PlanBudget(max_delegations=10),
        )

        result = await gate.check(plan)

        assert result.allowed is True
        assert result.remaining_delegations == 3

    @pytest.mark.asyncio
    async def test_remaining_risk_computed(self):
        gate = _make_gate()
        plan = _make_plan(
            accumulated_risk=2.5,
            budget=PlanBudget(max_risk_total=5.0),
        )

        result = await gate.check(plan)

        assert result.allowed is True
        assert result.remaining_risk_budget == pytest.approx(2.5)


# ---------------------------------------------------------------------------
# APEP-319: Record delegation tests
# ---------------------------------------------------------------------------


class TestRecordDelegation:
    """Test budget state updates on delegation recording."""

    @pytest.mark.asyncio
    async def test_record_delegation_increments_counters(self, mock_mongodb):
        gate = _make_gate()
        plan = _make_plan(delegation_count=3, accumulated_risk=1.0)

        # Seed the plan in mock MongoDB
        await mock_mongodb["mission_plans"].insert_one(
            plan.model_dump(mode="json")
        )

        state = await gate.record_delegation(plan, risk_score=0.5)

        assert state.delegation_count == 4
        assert state.accumulated_risk == pytest.approx(1.5)

    @pytest.mark.asyncio
    async def test_record_delegation_zero_risk(self, mock_mongodb):
        gate = _make_gate()
        plan = _make_plan(delegation_count=0, accumulated_risk=0.0)

        await mock_mongodb["mission_plans"].insert_one(
            plan.model_dump(mode="json")
        )

        state = await gate.record_delegation(plan, risk_score=0.0)

        assert state.delegation_count == 1
        assert state.accumulated_risk == 0.0


# ---------------------------------------------------------------------------
# APEP-320.c: Budget status API tests
# ---------------------------------------------------------------------------


class TestBudgetStatus:
    """Budget status response construction."""

    @pytest.mark.asyncio
    async def test_active_plan_status(self):
        gate = _make_gate()
        plan = _make_plan(delegation_count=3, accumulated_risk=1.5)

        status = await gate.get_budget_status(plan)

        assert status.plan_id == plan.plan_id
        assert status.status == "ACTIVE"
        assert status.delegation_count == 3
        assert status.accumulated_risk == 1.5
        assert status.max_delegations == 10
        assert status.max_risk_total == 5.0

    @pytest.mark.asyncio
    async def test_expired_plan_status(self):
        gate = _make_gate()
        plan = _make_plan(
            status=PlanStatus.EXPIRED,
            issued_at=datetime.now(UTC) - timedelta(hours=2),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )

        status = await gate.get_budget_status(plan)

        assert status.status == "EXPIRED"

    @pytest.mark.asyncio
    async def test_revoked_plan_status(self):
        gate = _make_gate()
        plan = _make_plan(status=PlanStatus.REVOKED)

        status = await gate.get_budget_status(plan)

        assert status.status == "REVOKED"

    @pytest.mark.asyncio
    async def test_budget_exhausted_status(self):
        gate = _make_gate()
        plan = _make_plan(
            delegation_count=10,
            budget=PlanBudget(max_delegations=10),
        )

        status = await gate.get_budget_status(plan)

        assert status.status == "BUDGET_EXHAUSTED"
        assert BudgetDimension.DELEGATION_COUNT in status.exhausted_dimensions

    @pytest.mark.asyncio
    async def test_utilization_percentages(self):
        gate = _make_gate()
        plan = _make_plan(
            delegation_count=5,
            accumulated_risk=2.5,
            budget=PlanBudget(
                max_delegations=10,
                max_risk_total=5.0,
                ttl_seconds=3600,
            ),
        )

        status = await gate.get_budget_status(plan)

        assert status.budget_utilization is not None
        assert status.budget_utilization.delegation_pct == pytest.approx(50.0)
        assert status.budget_utilization.risk_pct == pytest.approx(50.0)
        assert status.budget_utilization.ttl_pct is not None

    @pytest.mark.asyncio
    async def test_utilization_unlimited_dimensions_are_none(self):
        gate = _make_gate()
        plan = _make_plan(
            budget=PlanBudget(
                max_delegations=None,
                max_risk_total=None,
                ttl_seconds=None,
            ),
            expires_at=None,
        )

        status = await gate.get_budget_status(plan)

        assert status.budget_utilization is not None
        assert status.budget_utilization.delegation_pct is None
        assert status.budget_utilization.risk_pct is None
        assert status.budget_utilization.ttl_pct is None

    @pytest.mark.asyncio
    async def test_ttl_remaining_in_status(self):
        gate = _make_gate()
        plan = _make_plan(
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )

        status = await gate.get_budget_status(plan)

        assert status.ttl_remaining_seconds is not None
        assert 0 < status.ttl_remaining_seconds <= 1800


# ---------------------------------------------------------------------------
# APEP-321.c: Budget alert event tests
# ---------------------------------------------------------------------------


class TestBudgetAlertEvents:
    """Budget alert threshold detection and event emission."""

    def test_warning_alert_at_80_pct(self):
        gate = _make_gate()
        alert = gate._maybe_create_alert(
            plan_id=uuid4(),
            dimension=BudgetDimension.DELEGATION_COUNT,
            current=8.0,
            maximum=10.0,
            utilization=0.8,
        )

        assert alert is not None
        assert alert.alert_level == BudgetAlertLevel.WARNING
        assert alert.utilization_pct == 80.0

    def test_critical_alert_at_95_pct(self):
        gate = _make_gate()
        alert = gate._maybe_create_alert(
            plan_id=uuid4(),
            dimension=BudgetDimension.DELEGATION_COUNT,
            current=9.5,
            maximum=10.0,
            utilization=0.95,
        )

        assert alert is not None
        assert alert.alert_level == BudgetAlertLevel.CRITICAL
        assert alert.utilization_pct == 95.0

    def test_exhausted_alert_at_100_pct(self):
        gate = _make_gate()
        alert = gate._maybe_create_alert(
            plan_id=uuid4(),
            dimension=BudgetDimension.DELEGATION_COUNT,
            current=10.0,
            maximum=10.0,
            utilization=1.0,
        )

        assert alert is not None
        assert alert.alert_level == BudgetAlertLevel.EXHAUSTED

    def test_no_alert_below_80_pct(self):
        gate = _make_gate()
        alert = gate._maybe_create_alert(
            plan_id=uuid4(),
            dimension=BudgetDimension.DELEGATION_COUNT,
            current=7.0,
            maximum=10.0,
            utilization=0.7,
        )

        assert alert is None

    def test_risk_dimension_alert(self):
        gate = _make_gate()
        alert = gate._maybe_create_alert(
            plan_id=uuid4(),
            dimension=BudgetDimension.RISK_TOTAL,
            current=4.5,
            maximum=5.0,
            utilization=0.9,
        )

        assert alert is not None
        assert alert.dimension == BudgetDimension.RISK_TOTAL
        assert alert.alert_level == BudgetAlertLevel.WARNING

    def test_alert_event_contains_message(self):
        gate = _make_gate()
        plan_id = uuid4()
        alert = gate._maybe_create_alert(
            plan_id=plan_id,
            dimension=BudgetDimension.DELEGATION_COUNT,
            current=10.0,
            maximum=10.0,
            utilization=1.0,
        )

        assert alert is not None
        assert str(plan_id) in alert.message
        assert "EXHAUSTED" in alert.message

    @pytest.mark.asyncio
    async def test_alert_handler_called(self, mock_mongodb):
        gate = _make_gate()
        handler = AsyncMock()
        gate.register_alert_handler(handler)

        plan = _make_plan(
            delegation_count=9,
            budget=PlanBudget(max_delegations=10),
        )
        await mock_mongodb["mission_plans"].insert_one(
            plan.model_dump(mode="json")
        )

        await gate.record_delegation(plan, risk_score=0.1)

        # After incrementing from 9 to 10, should trigger EXHAUSTED alert
        assert handler.called

    @pytest.mark.asyncio
    async def test_emit_alerts_for_delegation_threshold(self):
        gate = _make_gate()
        plan = _make_plan(
            delegation_count=8,
            budget=PlanBudget(max_delegations=10),
        )
        state = PlanBudgetState(
            plan_id=plan.plan_id,
            delegation_count=9,
            accumulated_risk=0.0,
        )

        alerts = await gate._check_and_emit_alerts(plan, state)

        assert len(alerts) >= 1
        assert any(a.dimension == BudgetDimension.DELEGATION_COUNT for a in alerts)


# ---------------------------------------------------------------------------
# APEP-322.c: Plan budget reset tests
# ---------------------------------------------------------------------------


class TestPlanBudgetReset:
    """Plan budget reset logic."""

    @pytest.mark.asyncio
    async def test_reset_counters(self, mock_mongodb):
        gate = _make_gate()
        plan = _make_plan(delegation_count=8, accumulated_risk=3.5)
        await mock_mongodb["mission_plans"].insert_one(
            plan.model_dump(mode="json")
        )

        request = BudgetResetRequest(reset_delegations=True, reset_risk=True)
        result = await gate.reset_budget(plan, request)

        assert result.previous_delegation_count == 8
        assert result.previous_accumulated_risk == 3.5
        assert result.new_delegation_count == 0
        assert result.new_accumulated_risk == 0.0
        assert result.plan_reactivated is False

    @pytest.mark.asyncio
    async def test_reset_only_delegations(self, mock_mongodb):
        gate = _make_gate()
        plan = _make_plan(delegation_count=8, accumulated_risk=3.5)
        await mock_mongodb["mission_plans"].insert_one(
            plan.model_dump(mode="json")
        )

        request = BudgetResetRequest(reset_delegations=True, reset_risk=False)
        result = await gate.reset_budget(plan, request)

        assert result.new_delegation_count == 0
        assert result.new_accumulated_risk == 3.5

    @pytest.mark.asyncio
    async def test_reset_only_risk(self, mock_mongodb):
        gate = _make_gate()
        plan = _make_plan(delegation_count=8, accumulated_risk=3.5)
        await mock_mongodb["mission_plans"].insert_one(
            plan.model_dump(mode="json")
        )

        request = BudgetResetRequest(reset_delegations=False, reset_risk=True)
        result = await gate.reset_budget(plan, request)

        assert result.new_delegation_count == 8
        assert result.new_accumulated_risk == 0.0

    @pytest.mark.asyncio
    async def test_reset_with_new_limits(self, mock_mongodb):
        gate = _make_gate()
        plan = _make_plan(delegation_count=10, accumulated_risk=5.0)
        await mock_mongodb["mission_plans"].insert_one(
            plan.model_dump(mode="json")
        )

        request = BudgetResetRequest(
            reset_delegations=True,
            reset_risk=True,
            new_max_delegations=20,
            new_max_risk_total=10.0,
        )
        result = await gate.reset_budget(plan, request)

        assert result.budget_updated is True
        assert result.new_delegation_count == 0
        assert result.new_accumulated_risk == 0.0

    @pytest.mark.asyncio
    async def test_reset_reactivates_expired_plan(self, mock_mongodb):
        gate = _make_gate()
        plan = _make_plan(
            status=PlanStatus.EXPIRED,
            delegation_count=10,
            budget=PlanBudget(max_delegations=10),
        )
        await mock_mongodb["mission_plans"].insert_one(
            plan.model_dump(mode="json")
        )

        request = BudgetResetRequest(reset_delegations=True)
        result = await gate.reset_budget(plan, request)

        assert result.plan_reactivated is True

    @pytest.mark.asyncio
    async def test_reset_with_new_ttl(self, mock_mongodb):
        gate = _make_gate()
        plan = _make_plan(
            status=PlanStatus.EXPIRED,
            issued_at=datetime.now(UTC) - timedelta(hours=2),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        await mock_mongodb["mission_plans"].insert_one(
            plan.model_dump(mode="json")
        )

        request = BudgetResetRequest(
            reset_delegations=True,
            new_ttl_seconds=7200,
        )
        result = await gate.reset_budget(plan, request)

        assert result.budget_updated is True
        assert result.plan_reactivated is True


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestBudgetModels:
    """Pydantic model serialization tests."""

    def test_budget_check_result_serialization(self):
        result = BudgetCheckResult(
            allowed=True,
            plan_id=uuid4(),
            reason="Budget OK",
        )
        data = result.model_dump()
        assert data["allowed"] is True
        assert "plan_id" in data

    def test_budget_state_defaults(self):
        state = PlanBudgetState(plan_id=uuid4())
        assert state.delegation_count == 0
        assert state.accumulated_risk == 0.0

    def test_budget_alert_event_serialization(self):
        event = BudgetAlertEvent(
            plan_id=uuid4(),
            alert_level=BudgetAlertLevel.WARNING,
            dimension=BudgetDimension.DELEGATION_COUNT,
            current_value=8.0,
            threshold_value=8.0,
            max_value=10.0,
            utilization_pct=80.0,
            message="test alert",
        )
        data = event.model_dump(mode="json")
        assert data["alert_level"] == "WARNING"
        assert data["dimension"] == "DELEGATION_COUNT"

    def test_budget_utilization_model(self):
        util = BudgetUtilization(
            delegation_pct=50.0, risk_pct=25.0, ttl_pct=10.0
        )
        assert util.delegation_pct == 50.0
        assert util.risk_pct == 25.0

    def test_budget_reset_request_defaults(self):
        req = BudgetResetRequest()
        assert req.reset_delegations is True
        assert req.reset_risk is True
        assert req.new_max_delegations is None

    def test_budget_dimension_enum_values(self):
        assert BudgetDimension.DELEGATION_COUNT == "DELEGATION_COUNT"
        assert BudgetDimension.RISK_TOTAL == "RISK_TOTAL"
        assert BudgetDimension.TTL == "TTL"
