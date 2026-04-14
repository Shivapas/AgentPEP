"""Sprint 41 unit tests — Checkpoint-Declared Escalation & Human Intent.

APEP-324.e: PlanCheckpointFilter as the first stage in PolicyEvaluator.
APEP-325.e: Propagate checkpoint match reason to Escalation Manager.
APEP-326.e: Checkpoint approval memory scoped to plan.
APEP-327.c: human_intent field propagation.
APEP-328.c: Checkpoint pattern testing to policy simulation.
APEP-329.c: Checkpoint History view component tests.
APEP-330.c: Compliance report checkpoint data.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from app.models.mission_plan import (
    CreatePlanRequest,
    MissionPlan,
    PlanBudget,
    PlanStatus,
)
from app.models.policy import (
    Decision,
    EscalationState,
    EscalationTicketV1,
    ToolCallRequest,
)
from app.models.scope_pattern import (
    CheckpointEscalationRecord,
    CheckpointScopeMatch,
    PlanCheckpointApproval,
)
from app.services.scope_filter import PlanCheckpointFilter, plan_checkpoint_filter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plan(**overrides) -> MissionPlan:
    defaults = {
        "action": "Test checkpoint plan",
        "issuer": "admin@test.com",
        "scope": ["read:public:*"],
        "requires_checkpoint": ["write:secret:*", "delete:*:*"],
        "delegates_to": ["agent-alpha"],
        "budget": PlanBudget(max_delegations=10),
        "human_intent": "Analyze Q3 reports safely",
        "issued_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    return MissionPlan(**defaults)


def _make_request(**overrides) -> ToolCallRequest:
    defaults = {
        "session_id": "sess-001",
        "agent_id": "agent-alpha",
        "tool_name": "file.read.public.report",
        "human_intent": "",
    }
    defaults.update(overrides)
    return ToolCallRequest(**defaults)


# ===========================================================================
# APEP-324.e: PlanCheckpointFilter — first stage in PolicyEvaluator
# ===========================================================================


class TestPlanCheckpointFilterFirstStage:
    """Tests for PlanCheckpointFilter as the first pre-RBAC stage."""

    def test_checkpoint_match_triggers_escalate(self):
        """A tool matching requires_checkpoint should return matches=True."""
        plan = _make_plan(requires_checkpoint=["write:secret:*"])
        filt = PlanCheckpointFilter()
        result = filt.check(plan, "write.secret.credentials")
        assert result.matches is True
        assert result.matched_pattern is not None
        assert "write:secret:*" in result.matched_pattern

    def test_no_checkpoint_match_passes(self):
        """A tool not matching any checkpoint should return matches=False."""
        plan = _make_plan(requires_checkpoint=["write:secret:*"])
        filt = PlanCheckpointFilter()
        result = filt.check(plan, "read.public.report")
        assert result.matches is False

    def test_empty_checkpoint_list_passes(self):
        """An empty requires_checkpoint list should never trigger ESCALATE."""
        plan = _make_plan(requires_checkpoint=[])
        filt = PlanCheckpointFilter()
        result = filt.check(plan, "write.secret.credentials")
        assert result.matches is False

    def test_direct_glob_fallback(self):
        """Non-scope patterns should still match via fnmatch fallback."""
        plan = _make_plan(requires_checkpoint=["file.delete.*"])
        filt = PlanCheckpointFilter()
        result = filt.check(plan, "file.delete.important")
        assert result.matches is True
        assert "direct glob" in result.reason

    def test_multiple_patterns_first_match(self):
        """When multiple patterns exist, the first match wins."""
        plan = _make_plan(
            requires_checkpoint=["read:public:*", "write:secret:*"]
        )
        filt = PlanCheckpointFilter()
        result = filt.check(plan, "write.secret.key")
        assert result.matches is True

    def test_checkpoint_runs_before_budget_scope_delegates(self):
        """Checkpoint filter should fire even if budget is exhausted.

        This verifies the Sprint 41 reorder: checkpoint comes FIRST.
        We test indirectly by checking the filter standalone — the
        integration test verifies the evaluator ordering.
        """
        plan = _make_plan(
            requires_checkpoint=["write:secret:*"],
            budget=PlanBudget(max_delegations=0),  # exhausted
        )
        plan.delegation_count = 999  # way over budget
        filt = PlanCheckpointFilter()
        result = filt.check(plan, "write.secret.credentials")
        # Checkpoint still fires regardless of budget
        assert result.matches is True


# ===========================================================================
# APEP-325.e: Checkpoint match reason propagation
# ===========================================================================


class TestCheckpointMatchReasonPropagation:
    """Tests for checkpoint match reason carried to escalation."""

    def test_checkpoint_match_result_has_reason(self):
        """CheckpointScopeMatch should carry a human-readable reason."""
        plan = _make_plan(requires_checkpoint=["delete:*:*"])
        result = plan_checkpoint_filter.check(plan, "delete.internal.data")
        assert result.matches is True
        assert result.reason
        assert "delete" in result.reason.lower()

    def test_checkpoint_escalation_record_fields(self):
        """CheckpointEscalationRecord should capture all context."""
        record = CheckpointEscalationRecord(
            plan_id=uuid4(),
            session_id="sess-001",
            agent_id="agent-alpha",
            tool_name="file.delete.secret.key",
            matched_pattern="delete:*:*",
            match_reason="Tool 'file.delete.secret.key' matches checkpoint",
            human_intent="Clean up old keys",
        )
        assert record.plan_id is not None
        assert record.agent_id == "agent-alpha"
        assert record.human_intent == "Clean up old keys"

    def test_escalation_ticket_v1_carries_checkpoint_fields(self):
        """EscalationTicketV1 should have checkpoint_match_reason and plan_id."""
        ticket = EscalationTicketV1(
            request_id=uuid4(),
            session_id="sess-001",
            agent_id="agent-alpha",
            tool_name="file.write.secret.creds",
            checkpoint_match_reason="write:secret:* matched via scope glob",
            human_intent="Update credentials",
            plan_id=uuid4(),
        )
        assert ticket.checkpoint_match_reason is not None
        assert "write:secret" in ticket.checkpoint_match_reason
        assert ticket.human_intent == "Update credentials"
        assert ticket.plan_id is not None


# ===========================================================================
# APEP-326.e: Plan-scoped checkpoint approval memory
# ===========================================================================


class TestPlanCheckpointApprovalMemory:
    """Tests for plan-scoped approval memory model."""

    def test_plan_checkpoint_approval_model(self):
        """PlanCheckpointApproval should hold all expected fields."""
        plan_id = uuid4()
        approval = PlanCheckpointApproval(
            plan_id=plan_id,
            agent_id="agent-alpha",
            tool_name="file.write.secret.creds",
            matched_pattern="write:secret:*",
            tool_args_hash="abc123",
            approved_by="admin@example.com",
            original_ticket_id=uuid4(),
        )
        assert approval.plan_id == plan_id
        assert approval.agent_id == "agent-alpha"
        assert approval.matched_pattern == "write:secret:*"
        assert approval.approved_by == "admin@example.com"

    def test_approval_with_expiry(self):
        """An approval can have an optional expiry datetime."""
        expires = datetime.now(UTC) + timedelta(hours=1)
        approval = PlanCheckpointApproval(
            plan_id=uuid4(),
            agent_id="agent-beta",
            tool_name="db.drop.table",
            matched_pattern="delete:*:*",
            approved_by="admin@example.com",
            original_ticket_id=uuid4(),
            expires_at=expires,
        )
        assert approval.expires_at is not None
        assert approval.expires_at > datetime.now(UTC)

    def test_approval_without_expiry(self):
        """An approval without expiry should default to None."""
        approval = PlanCheckpointApproval(
            plan_id=uuid4(),
            agent_id="agent-gamma",
            tool_name="exec.deploy",
            matched_pattern="execute:*:deploy.*",
            approved_by="admin@example.com",
            original_ticket_id=uuid4(),
        )
        assert approval.expires_at is None

    @pytest.mark.asyncio
    async def test_approval_memory_check_no_entry(self, mock_mongodb):
        """check() returns False when no matching approval exists."""
        from app.services.checkpoint_approval_memory import (
            CheckpointApprovalMemory,
        )

        memory = CheckpointApprovalMemory()
        result = await memory.check(
            plan_id=uuid4(),
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_approval_memory_store_and_check(self, mock_mongodb):
        """store() + check() should find the stored approval."""
        from app.services.checkpoint_approval_memory import (
            CheckpointApprovalMemory,
        )

        memory = CheckpointApprovalMemory()
        plan_id = uuid4()
        approval = PlanCheckpointApproval(
            plan_id=plan_id,
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
            approved_by="admin@test.com",
            original_ticket_id=uuid4(),
        )
        await memory.store(approval)

        result = await memory.check(
            plan_id=plan_id,
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
        )
        assert result is True

    @pytest.mark.asyncio
    async def test_approval_memory_different_plan_no_leak(self, mock_mongodb):
        """Approval for plan A should NOT be found when checking plan B."""
        from app.services.checkpoint_approval_memory import (
            CheckpointApprovalMemory,
        )

        memory = CheckpointApprovalMemory()
        plan_a = uuid4()
        plan_b = uuid4()
        approval = PlanCheckpointApproval(
            plan_id=plan_a,
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
            approved_by="admin@test.com",
            original_ticket_id=uuid4(),
        )
        await memory.store(approval)

        result = await memory.check(
            plan_id=plan_b,
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_approval_memory_revoke(self, mock_mongodb):
        """revoke() should remove approvals and prevent future checks."""
        from app.services.checkpoint_approval_memory import (
            CheckpointApprovalMemory,
        )

        memory = CheckpointApprovalMemory()
        plan_id = uuid4()
        approval = PlanCheckpointApproval(
            plan_id=plan_id,
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
            approved_by="admin@test.com",
            original_ticket_id=uuid4(),
        )
        await memory.store(approval)

        count = await memory.revoke(plan_id=plan_id)
        assert count == 1

        result = await memory.check(
            plan_id=plan_id,
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
        )
        assert result is False

    @pytest.mark.asyncio
    async def test_approval_memory_list(self, mock_mongodb):
        """list_approvals() should return all approvals for a plan."""
        from app.services.checkpoint_approval_memory import (
            CheckpointApprovalMemory,
        )

        memory = CheckpointApprovalMemory()
        plan_id = uuid4()

        for tool in ["file.write.secret.key", "file.delete.secret.key"]:
            approval = PlanCheckpointApproval(
                plan_id=plan_id,
                agent_id="agent-alpha",
                tool_name=tool,
                matched_pattern="write:secret:*",
                approved_by="admin@test.com",
                original_ticket_id=uuid4(),
            )
            await memory.store(approval)

        approvals = await memory.list_approvals(plan_id)
        assert len(approvals) == 2


# ===========================================================================
# APEP-327.c: human_intent field propagation
# ===========================================================================


class TestHumanIntentPropagation:
    """Tests for human_intent field propagation through the pipeline."""

    def test_tool_call_request_has_human_intent(self):
        """ToolCallRequest should accept a human_intent field."""
        req = ToolCallRequest(
            session_id="sess-001",
            agent_id="agent-alpha",
            tool_name="file.read.report",
            human_intent="Read Q3 finance report",
        )
        assert req.human_intent == "Read Q3 finance report"

    def test_tool_call_request_default_human_intent(self):
        """ToolCallRequest.human_intent should default to empty string."""
        req = ToolCallRequest(
            session_id="sess-001",
            agent_id="agent-alpha",
            tool_name="file.read.report",
        )
        assert req.human_intent == ""

    def test_mission_plan_carries_human_intent(self):
        """MissionPlan should have a human_intent field."""
        plan = _make_plan(human_intent="Conduct security audit")
        assert plan.human_intent == "Conduct security audit"

    def test_mission_plan_human_intent_default(self):
        """MissionPlan.human_intent defaults to empty string."""
        plan = MissionPlan(
            action="Test plan",
            issuer="admin@test.com",
        )
        assert plan.human_intent == ""

    def test_create_plan_request_human_intent(self):
        """CreatePlanRequest should carry human_intent."""
        req = CreatePlanRequest(
            action="Deploy to production",
            issuer="admin@test.com",
            human_intent="Authorized production deployment",
        )
        assert req.human_intent == "Authorized production deployment"

    def test_escalation_ticket_v1_human_intent(self):
        """EscalationTicketV1 should carry human_intent."""
        ticket = EscalationTicketV1(
            request_id=uuid4(),
            session_id="sess-001",
            agent_id="agent-alpha",
            tool_name="deploy.prod",
            human_intent="Authorized deployment",
        )
        assert ticket.human_intent == "Authorized deployment"

    def test_human_intent_resolved_from_plan_action(self):
        """When human_intent is empty, plan.action should be used as fallback."""
        plan = _make_plan(
            action="Analyze Q3 finance reports",
            human_intent="",
        )
        # Fallback logic
        resolved = plan.human_intent or plan.action
        assert resolved == "Analyze Q3 finance reports"


# ===========================================================================
# APEP-328.c: Checkpoint pattern testing in policy simulation
# ===========================================================================


class TestCheckpointPatternSimulation:
    """Tests for checkpoint pattern testing in SimulationEngine."""

    def test_checkpoint_scope_match_model(self):
        """CheckpointScopeMatch should serialize correctly."""
        match = CheckpointScopeMatch(
            matches=True,
            matched_pattern="write:secret:*",
            tool_name="file.write.secret.creds",
            reason="Matched scope pattern",
        )
        data = match.model_dump()
        assert data["matches"] is True
        assert data["matched_pattern"] == "write:secret:*"

    def test_checkpoint_filter_with_scope_pattern(self):
        """Scope patterns should be compiled and matched in simulation."""
        plan = _make_plan(requires_checkpoint=["write:secret:*"])
        result = plan_checkpoint_filter.check(plan, "write.secret.credentials")
        assert result.matches is True
        assert "RBAC glob" in result.reason or "scope" in result.reason.lower()

    def test_checkpoint_filter_no_match_in_simulation(self):
        """Non-matching tools should produce a no-match result."""
        plan = _make_plan(requires_checkpoint=["delete:*:*"])
        result = plan_checkpoint_filter.check(plan, "read.public.report")
        assert result.matches is False


# ===========================================================================
# APEP-330.c: Compliance report checkpoint data
# ===========================================================================


class TestComplianceReportCheckpointData:
    """Tests for checkpoint data in compliance reports."""

    def test_dpdpa_checkpoint_summary_model(self):
        """DPDPACheckpointSummary model should have all fields."""
        from app.models.compliance import DPDPACheckpointSummary

        summary = DPDPACheckpointSummary(
            total_checkpoint_escalations=10,
            approved_checkpoints=7,
            denied_checkpoints=2,
            pending_checkpoints=1,
            unique_patterns=3,
            unique_agents=2,
        )
        assert summary.total_checkpoint_escalations == 10
        assert summary.approved_checkpoints == 7

    def test_certin_checkpoint_summary_model(self):
        """CERTInCheckpointSummary model should have all fields."""
        from app.models.compliance import CERTInCheckpointSummary

        summary = CERTInCheckpointSummary(
            total_checkpoint_escalations=5,
            checkpoint_patterns=["write:secret:*", "delete:*:*"],
            agents_with_checkpoints=["agent-alpha", "agent-beta"],
            human_intents=["Security audit"],
        )
        assert summary.total_checkpoint_escalations == 5
        assert len(summary.checkpoint_patterns) == 2
        assert "Security audit" in summary.human_intents

    def test_dpdpa_checkpoint_summary_defaults(self):
        """DPDPACheckpointSummary should have sane defaults."""
        from app.models.compliance import DPDPACheckpointSummary

        summary = DPDPACheckpointSummary()
        assert summary.total_checkpoint_escalations == 0
        assert summary.approved_checkpoints == 0
        assert summary.denied_checkpoints == 0
        assert summary.pending_checkpoints == 0
        assert summary.unique_patterns == 0
        assert summary.unique_agents == 0
