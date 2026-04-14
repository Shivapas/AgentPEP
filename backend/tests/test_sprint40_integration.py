"""Sprint 40 integration tests — Declarative Delegates-To & Plan Budget Gate.

APEP-318.g: Integration tests for PlanBudgetGate.
APEP-323.a/b: Integration and adversarial tests.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.models.mission_plan import (
    CreatePlanRequest,
    MissionPlan,
    PlanBudget,
    PlanDenialReason,
    PlanStatus,
)
from app.models.plan_budget_gate import (
    BudgetAlertLevel,
    BudgetDimension,
    BudgetResetRequest,
)
from app.services.mission_plan_service import mission_plan_service
from app.services.plan_budget_gate import PlanBudgetGate, plan_budget_gate
from app.services.plan_delegates_filter import plan_delegates_filter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plan(**overrides) -> MissionPlan:
    defaults = {
        "action": "Integration test plan",
        "issuer": "admin@test.com",
        "scope": ["read:public:*"],
        "delegates_to": ["agent-alpha", "agent-beta"],
        "budget": PlanBudget(
            max_delegations=5,
            max_risk_total=3.0,
            ttl_seconds=3600,
        ),
        "issued_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    if "expires_at" not in overrides and defaults.get("budget"):
        budget = defaults["budget"]
        if isinstance(budget, PlanBudget) and budget.ttl_seconds is not None:
            defaults["expires_at"] = defaults["issued_at"] + timedelta(
                seconds=budget.ttl_seconds
            )
    return MissionPlan(**defaults)


async def _seed_plan(mock_mongodb, plan: MissionPlan) -> None:
    """Insert a plan into mock MongoDB."""
    await mock_mongodb["mission_plans"].insert_one(
        plan.model_dump(mode="json")
    )


# ---------------------------------------------------------------------------
# APEP-318.g: PlanBudgetGate integration tests
# ---------------------------------------------------------------------------


class TestBudgetGateIntegration:
    """End-to-end PlanBudgetGate tests with MongoDB."""

    @pytest.mark.asyncio
    async def test_full_budget_lifecycle(self, mock_mongodb):
        """Test plan from creation through budget exhaustion."""
        gate = PlanBudgetGate()
        gate._redis = None

        plan = _make_plan(
            delegation_count=0,
            accumulated_risk=0.0,
            budget=PlanBudget(max_delegations=3, max_risk_total=2.0),
        )
        await _seed_plan(mock_mongodb, plan)

        # First 3 delegations should succeed
        for i in range(3):
            check = await gate.check(plan)
            assert check.allowed is True, f"Delegation {i+1} should be allowed"

            state = await gate.record_delegation(plan, risk_score=0.5)
            # Update the local plan object to reflect new state
            plan.delegation_count = state.delegation_count
            plan.accumulated_risk = state.accumulated_risk

        # 4th delegation should be denied (max_delegations=3)
        check = await gate.check(plan)
        assert check.allowed is False
        assert BudgetDimension.DELEGATION_COUNT in check.exhausted_dimensions

    @pytest.mark.asyncio
    async def test_risk_budget_exhaustion_lifecycle(self, mock_mongodb):
        """Test risk budget exhaustion across multiple delegations."""
        gate = PlanBudgetGate()
        gate._redis = None

        plan = _make_plan(
            delegation_count=0,
            accumulated_risk=0.0,
            budget=PlanBudget(max_delegations=100, max_risk_total=1.0),
        )
        await _seed_plan(mock_mongodb, plan)

        # Record delegations with high risk scores
        state = await gate.record_delegation(plan, risk_score=0.4)
        plan.delegation_count = state.delegation_count
        plan.accumulated_risk = state.accumulated_risk

        state = await gate.record_delegation(plan, risk_score=0.4)
        plan.delegation_count = state.delegation_count
        plan.accumulated_risk = state.accumulated_risk

        # Should still be OK (0.8 < 1.0)
        check = await gate.check(plan)
        assert check.allowed is True

        # One more pushes over the limit
        state = await gate.record_delegation(plan, risk_score=0.3)
        plan.delegation_count = state.delegation_count
        plan.accumulated_risk = state.accumulated_risk

        check = await gate.check(plan)
        assert check.allowed is False
        assert BudgetDimension.RISK_TOTAL in check.exhausted_dimensions

    @pytest.mark.asyncio
    async def test_budget_reset_and_continue(self, mock_mongodb):
        """Test resetting an exhausted budget and continuing."""
        gate = PlanBudgetGate()
        gate._redis = None

        plan = _make_plan(
            delegation_count=5,
            accumulated_risk=3.0,
            budget=PlanBudget(max_delegations=5, max_risk_total=3.0),
            status=PlanStatus.EXPIRED,
        )
        await _seed_plan(mock_mongodb, plan)

        # Verify denied before reset
        check = await gate.check(plan)
        assert check.allowed is False

        # Reset budget
        reset_req = BudgetResetRequest(
            reset_delegations=True,
            reset_risk=True,
            new_max_delegations=10,
        )
        result = await gate.reset_budget(plan, reset_req)
        assert result.plan_reactivated is True
        assert result.new_delegation_count == 0

    @pytest.mark.asyncio
    async def test_budget_status_reflects_state(self, mock_mongodb):
        """Test that budget status accurately reflects current state."""
        gate = PlanBudgetGate()
        gate._redis = None

        plan = _make_plan(
            delegation_count=3,
            accumulated_risk=1.5,
            budget=PlanBudget(max_delegations=10, max_risk_total=5.0),
        )
        await _seed_plan(mock_mongodb, plan)

        status = await gate.get_budget_status(plan)

        assert status.status == "ACTIVE"
        assert status.delegation_count == 3
        assert status.accumulated_risk == 1.5
        assert status.budget_utilization.delegation_pct == pytest.approx(30.0)
        assert status.budget_utilization.risk_pct == pytest.approx(30.0)


# ---------------------------------------------------------------------------
# APEP-323: Combined delegates-to + budget gate integration
# ---------------------------------------------------------------------------


class TestDelegatesToBudgetIntegration:
    """Integration tests combining PlanDelegatesToFilter and PlanBudgetGate."""

    @pytest.mark.asyncio
    async def test_authorized_agent_within_budget_passes(self, mock_mongodb):
        """An authorized agent within budget should pass both gates."""
        gate = PlanBudgetGate()
        gate._redis = None

        plan = _make_plan(
            delegates_to=["agent-alpha", "agent-beta"],
            delegation_count=2,
            budget=PlanBudget(max_delegations=10),
        )
        await _seed_plan(mock_mongodb, plan)

        # Delegation check
        delegation_result = plan_delegates_filter.check(plan, "agent-alpha")
        assert delegation_result.authorized is True

        # Budget check
        budget_result = await gate.check(plan)
        assert budget_result.allowed is True

    @pytest.mark.asyncio
    async def test_unauthorized_agent_blocked_before_budget(self):
        """An unauthorized agent should be blocked by delegates_to filter."""
        gate = PlanBudgetGate()
        gate._redis = None

        plan = _make_plan(
            delegates_to=["agent-alpha"],
            delegation_count=0,
        )

        # Delegation check should fail first
        delegation_result = plan_delegates_filter.check(plan, "attacker-agent")
        assert delegation_result.authorized is False

    @pytest.mark.asyncio
    async def test_authorized_agent_budget_exhausted(self, mock_mongodb):
        """An authorized agent should still be blocked if budget is exhausted."""
        gate = PlanBudgetGate()
        gate._redis = None

        plan = _make_plan(
            delegates_to=["agent-alpha"],
            delegation_count=10,
            budget=PlanBudget(max_delegations=10),
        )
        await _seed_plan(mock_mongodb, plan)

        # Delegation check passes
        delegation_result = plan_delegates_filter.check(plan, "agent-alpha")
        assert delegation_result.authorized is True

        # Budget check fails
        budget_result = await gate.check(plan)
        assert budget_result.allowed is False


# ---------------------------------------------------------------------------
# Adversarial / Edge Case Tests (APEP-323.b)
# ---------------------------------------------------------------------------


class TestAdversarialScenarios:
    """Adversarial and edge case tests for Sprint 40."""

    def test_empty_agent_id_denied(self):
        plan = _make_plan(delegates_to=["agent-alpha"])
        result = plan_delegates_filter.check(plan, "")
        assert result.authorized is False

    def test_wildcard_injection_in_agent_id(self):
        """Agent ID containing glob characters shouldn't bypass the filter."""
        plan = _make_plan(delegates_to=["agent-alpha"])
        result = plan_delegates_filter.check(plan, "*")
        assert result.authorized is False

    def test_very_long_agent_id(self):
        plan = _make_plan(delegates_to=["agent-alpha"])
        result = plan_delegates_filter.check(plan, "a" * 10000)
        assert result.authorized is False

    @pytest.mark.asyncio
    async def test_negative_delegation_count_rejected(self):
        """PlanBudgetState should reject negative delegation counts."""
        with pytest.raises(Exception):
            from app.models.plan_budget_gate import PlanBudgetState
            PlanBudgetState(
                plan_id=uuid4(),
                delegation_count=-1,
            )

    @pytest.mark.asyncio
    async def test_negative_risk_score_rejected(self):
        """PlanBudgetState should reject negative risk scores."""
        with pytest.raises(Exception):
            from app.models.plan_budget_gate import PlanBudgetState
            PlanBudgetState(
                plan_id=uuid4(),
                accumulated_risk=-1.0,
            )

    @pytest.mark.asyncio
    async def test_concurrent_budget_checks(self, mock_mongodb):
        """Multiple concurrent budget checks should not produce race conditions."""
        gate = PlanBudgetGate()
        gate._redis = None

        plan = _make_plan(
            delegation_count=4,
            budget=PlanBudget(max_delegations=5),
        )
        await _seed_plan(mock_mongodb, plan)

        # Run 10 concurrent checks
        results = await asyncio.gather(
            *[gate.check(plan) for _ in range(10)]
        )

        # All should return the same result (allowed=True since count is 4 < 5)
        for r in results:
            assert r.allowed is True

    @pytest.mark.asyncio
    async def test_budget_check_with_zero_limits(self):
        """Zero budget limits should immediately exhaust."""
        gate = PlanBudgetGate()
        gate._redis = None

        plan = _make_plan(
            delegation_count=0,
            budget=PlanBudget(max_delegations=0),
        )

        result = await gate.check(plan)
        assert result.allowed is False
        assert BudgetDimension.DELEGATION_COUNT in result.exhausted_dimensions


# ---------------------------------------------------------------------------
# API endpoint integration tests
# ---------------------------------------------------------------------------


class TestPlanBudgetAPIEndpoints:
    """Test Sprint 40 API endpoints via ASGI transport."""

    @pytest.fixture
    async def client(self, mock_mongodb):
        from tests.conftest import _get_auth_headers

        from app.main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers=_get_auth_headers(),
        ) as c:
            yield c

    @pytest.mark.asyncio
    async def test_get_budget_status_endpoint(self, client, mock_mongodb):
        plan = _make_plan(delegation_count=3, accumulated_risk=1.5)
        await _seed_plan(mock_mongodb, plan)

        resp = await client.get(f"/v1/plans/{plan.plan_id}/budget")

        assert resp.status_code == 200
        data = resp.json()
        assert data["plan_id"] == str(plan.plan_id)
        assert data["delegation_count"] == 3

    @pytest.mark.asyncio
    async def test_get_budget_status_not_found(self, client, mock_mongodb):
        fake_id = uuid4()
        resp = await client.get(f"/v1/plans/{fake_id}/budget")

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_check_delegation_endpoint(self, client, mock_mongodb):
        plan = _make_plan(delegates_to=["agent-alpha", "agent-beta"])
        await _seed_plan(mock_mongodb, plan)

        resp = await client.get(
            f"/v1/plans/{plan.plan_id}/delegates/agent-alpha"
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["authorized"] is True

    @pytest.mark.asyncio
    async def test_check_delegation_unauthorized(self, client, mock_mongodb):
        plan = _make_plan(delegates_to=["agent-alpha"])
        await _seed_plan(mock_mongodb, plan)

        resp = await client.get(
            f"/v1/plans/{plan.plan_id}/delegates/agent-gamma"
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["authorized"] is False

    @pytest.mark.asyncio
    async def test_reset_budget_endpoint(self, client, mock_mongodb):
        plan = _make_plan(delegation_count=5, accumulated_risk=2.5)
        await _seed_plan(mock_mongodb, plan)

        resp = await client.post(
            f"/v1/plans/{plan.plan_id}/budget/reset",
            json={
                "reset_delegations": True,
                "reset_risk": True,
                "reason": "Integration test reset",
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["previous_delegation_count"] == 5
        assert data["new_delegation_count"] == 0

    @pytest.mark.asyncio
    async def test_reset_budget_revoked_plan_rejected(self, client, mock_mongodb):
        plan = _make_plan(status=PlanStatus.REVOKED)
        await _seed_plan(mock_mongodb, plan)

        resp = await client.post(
            f"/v1/plans/{plan.plan_id}/budget/reset",
            json={"reset_delegations": True},
        )

        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_reset_budget_not_found(self, client, mock_mongodb):
        fake_id = uuid4()
        resp = await client.post(
            f"/v1/plans/{fake_id}/budget/reset",
            json={"reset_delegations": True},
        )

        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Pipeline integration tests (APEP-318.e)
# ---------------------------------------------------------------------------


class TestPolicyEvaluatorPipelineIntegration:
    """Test Sprint 40 filters integrated into PolicyEvaluator pipeline."""

    @pytest.mark.asyncio
    async def test_delegates_filter_blocks_in_pipeline(self, mock_mongodb):
        """Agent not in delegates_to should be DENY'd by the pipeline."""
        from app.core.config import settings
        from app.models.policy import ToolCallRequest
        from app.services.policy_evaluator import PolicyEvaluator

        # Create plan with restricted delegates
        plan = _make_plan(delegates_to=["agent-alpha"])
        await _seed_plan(mock_mongodb, plan)

        # Bind a session to the plan
        await mock_mongodb["plan_session_bindings"].insert_one({
            "binding_id": str(uuid4()),
            "plan_id": str(plan.plan_id),
            "session_id": "test-session-1",
            "agent_id": "agent-alpha",
            "bound_at": datetime.now(UTC).isoformat(),
            "unbound_at": None,
            "active": True,
        })

        # Enable mission plan evaluation
        original = settings.mission_plan_enabled
        settings.mission_plan_enabled = True

        try:
            evaluator = PolicyEvaluator()
            request = ToolCallRequest(
                session_id="test-session-1",
                agent_id="agent-gamma",  # NOT in delegates_to
                tool_name="read_file",
                tool_args={},
            )
            response = await evaluator.evaluate(request)

            assert response.decision.value == "DENY"
            assert "PLAN_AGENT_NOT_AUTHORIZED" in response.reason
        finally:
            settings.mission_plan_enabled = original

    @pytest.mark.asyncio
    async def test_budget_gate_blocks_in_pipeline(self, mock_mongodb):
        """Exhausted budget should produce a DENY in the pipeline."""
        from app.core.config import settings
        from app.models.policy import ToolCallRequest
        from app.services.policy_evaluator import PolicyEvaluator

        plan = _make_plan(
            delegates_to=["agent-alpha"],
            delegation_count=10,
            budget=PlanBudget(max_delegations=10),
        )
        await _seed_plan(mock_mongodb, plan)

        await mock_mongodb["plan_session_bindings"].insert_one({
            "binding_id": str(uuid4()),
            "plan_id": str(plan.plan_id),
            "session_id": "test-session-2",
            "agent_id": "agent-alpha",
            "bound_at": datetime.now(UTC).isoformat(),
            "unbound_at": None,
            "active": True,
        })

        original = settings.mission_plan_enabled
        settings.mission_plan_enabled = True

        try:
            evaluator = PolicyEvaluator()
            request = ToolCallRequest(
                session_id="test-session-2",
                agent_id="agent-alpha",
                tool_name="read_file",
                tool_args={},
            )
            response = await evaluator.evaluate(request)

            assert response.decision.value == "DENY"
            assert "PLAN_BUDGET_EXHAUSTED" in response.reason
        finally:
            settings.mission_plan_enabled = original

    @pytest.mark.asyncio
    async def test_authorized_agent_within_budget_proceeds(self, mock_mongodb):
        """Authorized agent within budget should proceed to normal RBAC."""
        from app.core.config import settings
        from app.models.policy import ToolCallRequest
        from app.services.policy_evaluator import PolicyEvaluator

        plan = _make_plan(
            delegates_to=["agent-alpha"],
            delegation_count=0,
            budget=PlanBudget(max_delegations=10),
        )
        await _seed_plan(mock_mongodb, plan)

        await mock_mongodb["plan_session_bindings"].insert_one({
            "binding_id": str(uuid4()),
            "plan_id": str(plan.plan_id),
            "session_id": "test-session-3",
            "agent_id": "agent-alpha",
            "bound_at": datetime.now(UTC).isoformat(),
            "unbound_at": None,
            "active": True,
        })

        original = settings.mission_plan_enabled
        settings.mission_plan_enabled = True

        try:
            evaluator = PolicyEvaluator()
            request = ToolCallRequest(
                session_id="test-session-3",
                agent_id="agent-alpha",
                tool_name="read_file",
                tool_args={},
            )
            response = await evaluator.evaluate(request)

            # Should not be a plan-level DENY — either ALLOW or DENY-by-RBAC
            assert "PLAN_AGENT_NOT_AUTHORIZED" not in (response.reason or "")
            assert "PLAN_BUDGET_EXHAUSTED" not in (response.reason or "")
        finally:
            settings.mission_plan_enabled = original

    @pytest.mark.asyncio
    async def test_no_plan_bound_proceeds_normally(self, mock_mongodb):
        """Session with no plan binding should proceed to normal RBAC."""
        from app.core.config import settings
        from app.models.policy import ToolCallRequest
        from app.services.policy_evaluator import PolicyEvaluator

        original = settings.mission_plan_enabled
        settings.mission_plan_enabled = True

        try:
            evaluator = PolicyEvaluator()
            request = ToolCallRequest(
                session_id="unbound-session",
                agent_id="any-agent",
                tool_name="read_file",
                tool_args={},
            )
            response = await evaluator.evaluate(request)

            # Should not contain plan-level denial reasons
            assert "PLAN_AGENT_NOT_AUTHORIZED" not in (response.reason or "")
            assert "PLAN_BUDGET_EXHAUSTED" not in (response.reason or "")
        finally:
            settings.mission_plan_enabled = original
