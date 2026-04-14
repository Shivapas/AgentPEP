"""Tests for Sprint 40 — PlanDelegatesToFilter (APEP-316/317).

APEP-316.e: Unit tests for PlanDelegatesToFilter.
APEP-317.c: Unit tests for delegates_to enforcement.
"""

from uuid import uuid4

import pytest

from app.models.mission_plan import MissionPlan, PlanBudget, PlanDenialReason, PlanStatus
from app.models.plan_budget_gate import DelegationCheckResult
from app.services.plan_delegates_filter import PlanDelegatesToFilter, plan_delegates_filter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plan(**overrides) -> MissionPlan:
    defaults = {
        "action": "Analyze Q3 reports",
        "issuer": "admin@example.com",
        "scope": ["read:public:*"],
        "delegates_to": ["agent-alpha", "agent-beta"],
        "budget": PlanBudget(max_delegations=10, ttl_seconds=3600),
    }
    defaults.update(overrides)
    return MissionPlan(**defaults)


# ---------------------------------------------------------------------------
# APEP-316.e: PlanDelegatesToFilter unit tests
# ---------------------------------------------------------------------------


class TestPlanDelegatesToFilterBasic:
    """Basic authorization checks for PlanDelegatesToFilter."""

    def test_authorized_agent_in_whitelist(self):
        plan = _make_plan(delegates_to=["agent-alpha", "agent-beta"])
        result = plan_delegates_filter.check(plan, "agent-alpha")

        assert result.authorized is True
        assert result.agent_id == "agent-alpha"
        assert result.plan_id == plan.plan_id
        assert "whitelist" in result.reason

    def test_unauthorized_agent_not_in_whitelist(self):
        plan = _make_plan(delegates_to=["agent-alpha", "agent-beta"])
        result = plan_delegates_filter.check(plan, "agent-gamma")

        assert result.authorized is False
        assert result.agent_id == "agent-gamma"
        assert PlanDenialReason.PLAN_AGENT_NOT_AUTHORIZED in result.reason

    def test_empty_delegates_to_allows_all(self):
        plan = _make_plan(delegates_to=[])
        result = plan_delegates_filter.check(plan, "any-agent")

        assert result.authorized is True
        assert "empty" in result.reason.lower()

    def test_result_contains_plan_id(self):
        plan = _make_plan()
        result = plan_delegates_filter.check(plan, "agent-alpha")

        assert result.plan_id == plan.plan_id


class TestPlanDelegatesToFilterGlob:
    """Glob pattern matching for delegates_to."""

    def test_glob_wildcard_match(self):
        plan = _make_plan(delegates_to=["agent-*"])
        result = plan_delegates_filter.check(plan, "agent-gamma")

        assert result.authorized is True
        assert "pattern" in result.reason

    def test_glob_prefix_match(self):
        plan = _make_plan(delegates_to=["team-alpha-*"])
        result = plan_delegates_filter.check(plan, "team-alpha-worker-1")

        assert result.authorized is True

    def test_glob_no_match(self):
        plan = _make_plan(delegates_to=["team-alpha-*"])
        result = plan_delegates_filter.check(plan, "team-beta-worker-1")

        assert result.authorized is False

    def test_glob_question_mark(self):
        plan = _make_plan(delegates_to=["agent-?"])
        result = plan_delegates_filter.check(plan, "agent-1")

        assert result.authorized is True

    def test_glob_question_mark_no_match(self):
        plan = _make_plan(delegates_to=["agent-?"])
        result = plan_delegates_filter.check(plan, "agent-12")

        assert result.authorized is False

    def test_mixed_exact_and_glob(self):
        plan = _make_plan(delegates_to=["agent-alpha", "team-*"])

        assert plan_delegates_filter.check(plan, "agent-alpha").authorized is True
        assert plan_delegates_filter.check(plan, "team-beta").authorized is True
        assert plan_delegates_filter.check(plan, "other-agent").authorized is False

    def test_multiple_glob_patterns(self):
        plan = _make_plan(delegates_to=["reader-*", "writer-*"])

        assert plan_delegates_filter.check(plan, "reader-1").authorized is True
        assert plan_delegates_filter.check(plan, "writer-2").authorized is True
        assert plan_delegates_filter.check(plan, "admin-1").authorized is False


class TestPlanDelegatesToFilterEdgeCases:
    """Edge cases for PlanDelegatesToFilter."""

    def test_exact_match_takes_priority_over_glob(self):
        plan = _make_plan(delegates_to=["agent-alpha", "agent-*"])
        result = plan_delegates_filter.check(plan, "agent-alpha")

        assert result.authorized is True
        assert "whitelist" in result.reason  # exact match, not glob

    def test_case_sensitive_matching(self):
        plan = _make_plan(delegates_to=["Agent-Alpha"])
        result = plan_delegates_filter.check(plan, "agent-alpha")

        assert result.authorized is False

    def test_empty_agent_id(self):
        plan = _make_plan(delegates_to=["agent-alpha"])
        result = plan_delegates_filter.check(plan, "")

        assert result.authorized is False

    def test_single_delegate(self):
        plan = _make_plan(delegates_to=["sole-agent"])
        assert plan_delegates_filter.check(plan, "sole-agent").authorized is True
        assert plan_delegates_filter.check(plan, "other").authorized is False

    def test_denial_reason_code(self):
        assert plan_delegates_filter.get_denial_reason() == PlanDenialReason.PLAN_AGENT_NOT_AUTHORIZED

    def test_singleton_instance(self):
        assert isinstance(plan_delegates_filter, PlanDelegatesToFilter)


# ---------------------------------------------------------------------------
# APEP-317.c: delegates_to enforcement unit tests
# ---------------------------------------------------------------------------


class TestDelegatesToEnforcement:
    """Tests that delegates_to enforcement produces correct denial reasons."""

    def test_denial_contains_agent_id(self):
        plan = _make_plan(delegates_to=["agent-alpha"])
        result = plan_delegates_filter.check(plan, "attacker-agent")

        assert result.authorized is False
        assert "attacker-agent" in result.reason

    def test_denial_contains_delegates_list(self):
        plan = _make_plan(delegates_to=["agent-alpha", "agent-beta"])
        result = plan_delegates_filter.check(plan, "agent-gamma")

        assert "agent-alpha" in result.reason
        assert "agent-beta" in result.reason

    def test_authorization_with_special_chars_in_agent_id(self):
        plan = _make_plan(delegates_to=["agent:alpha@domain.com"])
        result = plan_delegates_filter.check(plan, "agent:alpha@domain.com")

        assert result.authorized is True

    def test_glob_star_matches_everything(self):
        plan = _make_plan(delegates_to=["*"])
        result = plan_delegates_filter.check(plan, "literally-anything")

        assert result.authorized is True

    def test_result_model_serialization(self):
        plan = _make_plan(delegates_to=["agent-alpha"])
        result = plan_delegates_filter.check(plan, "agent-alpha")

        data = result.model_dump()
        assert data["authorized"] is True
        assert data["agent_id"] == "agent-alpha"
        assert "plan_id" in data
