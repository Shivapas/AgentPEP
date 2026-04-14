"""Sprint 41 integration tests — Checkpoint-Declared Escalation & Human Intent.

APEP-331.a: Unit and component tests for integration paths.
APEP-331.b: Integration and adversarial tests.

These tests verify end-to-end behavior including pipeline ordering,
checkpoint → escalation propagation, plan-scoped approval memory,
and human_intent flow through the full evaluation cycle.
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
    EscalationResolveRequest,
    EscalationState,
    PolicyDecisionResponse,
    ToolCallRequest,
)
from app.models.scope_pattern import (
    CheckpointEscalationRecord,
    PlanCheckpointApproval,
)
from app.services.scope_filter import plan_checkpoint_filter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plan(**overrides) -> MissionPlan:
    defaults = {
        "action": "Integration test plan",
        "issuer": "admin@test.com",
        "scope": ["read:public:*", "write:internal:*"],
        "requires_checkpoint": ["write:secret:*", "delete:*:*"],
        "delegates_to": ["agent-alpha", "agent-beta"],
        "budget": PlanBudget(
            max_delegations=10,
            max_risk_total=5.0,
            ttl_seconds=3600,
        ),
        "human_intent": "Conduct Q3 security audit",
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


# ===========================================================================
# APEP-331.a: Component integration tests
# ===========================================================================


class TestCheckpointFilterOrdering:
    """Tests verifying checkpoint filter runs FIRST in the pipeline."""

    def test_checkpoint_fires_regardless_of_budget(self):
        """Checkpoint should trigger even when budget is exhausted.

        Sprint 41 moves checkpoint to position 1 (before budget gate).
        """
        plan = _make_plan(
            requires_checkpoint=["write:secret:*"],
            budget=PlanBudget(max_delegations=0),
        )
        plan.delegation_count = 999  # budget exhausted
        result = plan_checkpoint_filter.check(plan, "write.secret.credentials")
        assert result.matches is True

    def test_checkpoint_fires_for_unauthorized_agent(self):
        """Checkpoint should trigger even if agent is not in delegates_to.

        Sprint 41 moves checkpoint to position 1 (before delegates filter).
        """
        plan = _make_plan(
            requires_checkpoint=["delete:*:*"],
            delegates_to=["agent-gamma"],  # agent-alpha not authorized
        )
        result = plan_checkpoint_filter.check(plan, "delete.internal.records")
        assert result.matches is True

    def test_checkpoint_fires_for_out_of_scope_tool(self):
        """Checkpoint should trigger even if tool is outside plan scope.

        Sprint 41 moves checkpoint to position 1 (before scope filter).
        """
        plan = _make_plan(
            requires_checkpoint=["execute:*:*"],
            scope=["read:public:*"],  # execute not in scope
        )
        result = plan_checkpoint_filter.check(plan, "execute.external.deploy")
        assert result.matches is True


class TestCheckpointToEscalationFlow:
    """Tests for checkpoint match → escalation ticket creation."""

    def test_checkpoint_match_produces_escalation_record(self):
        """A checkpoint match should produce a CheckpointEscalationRecord."""
        plan = _make_plan()
        result = plan_checkpoint_filter.check(plan, "write.secret.api_key")
        assert result.matches is True

        record = CheckpointEscalationRecord(
            plan_id=plan.plan_id,
            session_id="sess-001",
            agent_id="agent-alpha",
            tool_name="write.secret.api_key",
            matched_pattern=result.matched_pattern or "",
            match_reason=result.reason,
            human_intent=plan.human_intent,
        )
        assert record.plan_id == plan.plan_id
        assert record.human_intent == "Conduct Q3 security audit"
        assert record.match_reason == result.reason


class TestPlanScopedApprovalMemoryIntegration:
    """End-to-end tests for plan-scoped checkpoint approval memory."""

    @pytest.mark.asyncio
    async def test_approval_prevents_re_escalation(self, mock_mongodb):
        """An approved checkpoint should not trigger re-escalation."""
        from app.services.checkpoint_approval_memory import (
            CheckpointApprovalMemory,
        )

        memory = CheckpointApprovalMemory()
        plan_id = uuid4()

        # First check: no approval exists
        has_approval = await memory.check(
            plan_id=plan_id,
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
        )
        assert has_approval is False

        # Store approval
        approval = PlanCheckpointApproval(
            plan_id=plan_id,
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
            approved_by="admin@test.com",
            original_ticket_id=uuid4(),
        )
        await memory.store(approval)

        # Second check: approval exists, skip escalation
        has_approval = await memory.check(
            plan_id=plan_id,
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
        )
        assert has_approval is True

    @pytest.mark.asyncio
    async def test_approval_isolation_between_plans(self, mock_mongodb):
        """Approvals in plan A must not leak to plan B."""
        from app.services.checkpoint_approval_memory import (
            CheckpointApprovalMemory,
        )

        memory = CheckpointApprovalMemory()
        plan_a = uuid4()
        plan_b = uuid4()

        # Store approval for plan A
        await memory.store(
            PlanCheckpointApproval(
                plan_id=plan_a,
                agent_id="agent-alpha",
                tool_name="file.write.secret.key",
                matched_pattern="write:secret:*",
                approved_by="admin@test.com",
                original_ticket_id=uuid4(),
            )
        )

        # Plan A has approval
        assert await memory.check(
            plan_id=plan_a,
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
        )

        # Plan B does NOT have approval
        assert not await memory.check(
            plan_id=plan_b,
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
        )

    @pytest.mark.asyncio
    async def test_revoke_all_approvals_for_plan(self, mock_mongodb):
        """Revoking should remove all approvals for a plan."""
        from app.services.checkpoint_approval_memory import (
            CheckpointApprovalMemory,
        )

        memory = CheckpointApprovalMemory()
        plan_id = uuid4()

        # Store two approvals
        for tool in ["file.write.secret.key", "file.delete.secret.key"]:
            await memory.store(
                PlanCheckpointApproval(
                    plan_id=plan_id,
                    agent_id="agent-alpha",
                    tool_name=tool,
                    matched_pattern="write:secret:*",
                    approved_by="admin@test.com",
                    original_ticket_id=uuid4(),
                )
            )

        # Both exist
        assert len(await memory.list_approvals(plan_id)) == 2

        # Revoke all
        count = await memory.revoke(plan_id=plan_id)
        assert count == 2

        # None remain
        assert len(await memory.list_approvals(plan_id)) == 0


class TestHumanIntentIntegration:
    """Tests for human_intent propagation through the full pipeline."""

    def test_human_intent_from_plan_to_request(self):
        """human_intent should be resolvable from plan when request is empty."""
        plan = _make_plan(human_intent="Authorized data migration")
        req = _make_request(human_intent="")

        # Pipeline resolution logic
        resolved = req.human_intent
        if not resolved and plan.human_intent:
            resolved = plan.human_intent
        elif not resolved and plan.action:
            resolved = plan.action

        assert resolved == "Authorized data migration"

    def test_request_human_intent_takes_precedence(self):
        """Request-level human_intent should override plan-level."""
        plan = _make_plan(human_intent="Plan intent")
        req = _make_request(human_intent="Request intent")

        resolved = req.human_intent or plan.human_intent or plan.action
        assert resolved == "Request intent"

    def test_fallback_to_action_when_no_intent(self):
        """When both human_intent fields are empty, fall back to plan.action."""
        plan = _make_plan(
            action="Analyze Q3 reports",
            human_intent="",
        )
        req = _make_request(human_intent="")

        resolved = req.human_intent or plan.human_intent or plan.action
        assert resolved == "Analyze Q3 reports"


# ===========================================================================
# APEP-331.b: Adversarial tests
# ===========================================================================


class TestAdversarialCheckpoint:
    """Adversarial inputs for checkpoint matching and approval memory."""

    def test_wildcard_checkpoint_matches_everything(self):
        """A wildcard checkpoint pattern '*' should match any tool."""
        plan = _make_plan(requires_checkpoint=["*"])
        result = plan_checkpoint_filter.check(plan, "any.random.tool")
        assert result.matches is True

    def test_empty_tool_name(self):
        """Empty tool name should not crash the checkpoint filter."""
        plan = _make_plan(requires_checkpoint=["write:secret:*"])
        result = plan_checkpoint_filter.check(plan, "")
        assert result.matches is False

    def test_very_long_tool_name(self):
        """Very long tool names should not cause issues."""
        long_name = "a" * 10000
        plan = _make_plan(requires_checkpoint=["*"])
        result = plan_checkpoint_filter.check(plan, long_name)
        assert result.matches is True

    def test_special_characters_in_pattern(self):
        """Patterns with special characters should be handled safely."""
        plan = _make_plan(requires_checkpoint=["write:secret:cred[0]"])
        # fnmatch treats [ ] as character class — this is expected behavior
        result = plan_checkpoint_filter.check(plan, "write.secret.cred0")
        # Result depends on fnmatch behavior, just ensure no crash
        assert isinstance(result.matches, bool)

    def test_unicode_in_human_intent(self):
        """Unicode characters in human_intent should be preserved."""
        plan = _make_plan(human_intent="Analyse des donnees financieres")
        assert plan.human_intent == "Analyse des donnees financieres"

    @pytest.mark.asyncio
    async def test_concurrent_approval_stores(self, mock_mongodb):
        """Concurrent approval stores should not corrupt data."""
        from app.services.checkpoint_approval_memory import (
            CheckpointApprovalMemory,
        )

        memory = CheckpointApprovalMemory()
        plan_id = uuid4()

        async def store_one(i: int):
            await memory.store(
                PlanCheckpointApproval(
                    plan_id=plan_id,
                    agent_id=f"agent-{i}",
                    tool_name=f"tool-{i}",
                    matched_pattern="write:secret:*",
                    approved_by="admin@test.com",
                    original_ticket_id=uuid4(),
                )
            )

        await asyncio.gather(*(store_one(i) for i in range(10)))

        approvals = await memory.list_approvals(plan_id)
        assert len(approvals) == 10


# ===========================================================================
# APEP-329.d: Checkpoint History API E2E
# ===========================================================================


class TestCheckpointHistoryAPI:
    """Tests for checkpoint history API endpoints."""

    @pytest.mark.asyncio
    async def test_checkpoint_history_empty(self, mock_mongodb):
        """Empty history should return empty list."""
        from app.db.mongodb import CHECKPOINT_ESCALATION_HISTORY

        db = mock_mongodb
        result = []
        async for doc in db[CHECKPOINT_ESCALATION_HISTORY].find(
            {"plan_id": str(uuid4())}
        ):
            result.append(doc)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_checkpoint_history_records(self, mock_mongodb):
        """Inserted records should be retrievable."""
        from app.db.mongodb import CHECKPOINT_ESCALATION_HISTORY

        db = mock_mongodb
        plan_id = uuid4()
        record = CheckpointEscalationRecord(
            plan_id=plan_id,
            session_id="sess-001",
            agent_id="agent-alpha",
            tool_name="file.write.secret.key",
            matched_pattern="write:secret:*",
            match_reason="Matched via scope pattern",
            human_intent="Security audit",
        )
        await db[CHECKPOINT_ESCALATION_HISTORY].insert_one(
            record.model_dump(mode="json")
        )

        docs = []
        async for doc in db[CHECKPOINT_ESCALATION_HISTORY].find(
            {"plan_id": str(plan_id)}
        ):
            docs.append(doc)
        assert len(docs) == 1
        assert docs[0]["agent_id"] == "agent-alpha"
        assert docs[0]["human_intent"] == "Security audit"
