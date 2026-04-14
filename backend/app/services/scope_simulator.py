"""Sprint 43 -- Scope Simulator: interactive scope evaluation engine.

APEP-340/341: The scope simulator evaluates a tool call against a set of
scope patterns (from a MissionPlan or inline) and produces a detailed
result showing whether the tool is allowed, denied, or triggers a
checkpoint escalation.

Used by:
- Console scope simulator UI (APEP-340)
- CLI ``agentpep scope simulate`` command (APEP-341)
- POST /v1/scope/simulate API endpoint
"""

from __future__ import annotations

import logging
from uuid import UUID

from app.models.mission_plan import MissionPlan, PlanBudget, PlanStatus
from app.models.scope_pattern_library import ScopeSimulateRequest, ScopeSimulateResult
from app.services.scope_filter import plan_checkpoint_filter, plan_scope_filter
from app.services.scope_pattern_compiler import scope_pattern_compiler

logger = logging.getLogger(__name__)


class ScopeSimulator:
    """Simulates scope evaluation for a tool call against plan scope patterns.

    The simulator checks two dimensions:
    1. **Scope allow**: Is the tool within the plan's allowed scope?
    2. **Checkpoint trigger**: Does the tool trigger a requires_checkpoint pattern?

    The effective decision is:
    - DENY if the tool is outside the allowed scope.
    - ESCALATE if the tool triggers a checkpoint pattern.
    - ALLOW otherwise.

    Usage::

        sim = ScopeSimulator()
        result = sim.simulate(ScopeSimulateRequest(
            scope=["read:public:*"],
            requires_checkpoint=["delete:*:*"],
            tool_name="file.read.public.report",
        ))
        assert result.effective_decision == "ALLOW"
    """

    async def simulate(self, request: ScopeSimulateRequest) -> ScopeSimulateResult:
        """Run a scope simulation for a single tool call.

        If ``plan_id`` is set, fetches the plan from the service and uses
        its scope/checkpoint configuration.  Otherwise, builds an ephemeral
        plan from the inline ``scope`` and ``requires_checkpoint`` fields.
        """
        plan: MissionPlan

        if request.plan_id is not None:
            plan = await self._get_plan(request.plan_id)
        else:
            plan = MissionPlan(
                action=request.action or "scope-simulation",
                issuer="simulator",
                scope=request.scope or [],
                requires_checkpoint=request.requires_checkpoint or [],
                status=PlanStatus.ACTIVE,
                budget=PlanBudget(),
            )

        return self._evaluate(plan, request.tool_name, request.action)

    def simulate_sync(
        self,
        scope: list[str],
        requires_checkpoint: list[str],
        tool_name: str,
        action: str = "",
    ) -> ScopeSimulateResult:
        """Synchronous simulation used by the CLI and offline evaluator.

        Builds an ephemeral plan and evaluates the tool call.
        """
        plan = MissionPlan(
            action=action or "scope-simulation",
            issuer="simulator",
            scope=scope,
            requires_checkpoint=requires_checkpoint,
            status=PlanStatus.ACTIVE,
            budget=PlanBudget(),
        )
        return self._evaluate(plan, tool_name, action)

    def simulate_batch_sync(
        self,
        scope: list[str],
        requires_checkpoint: list[str],
        tool_names: list[str],
        action: str = "",
    ) -> list[ScopeSimulateResult]:
        """Simulate multiple tool names against the same scope configuration."""
        plan = MissionPlan(
            action=action or "scope-simulation",
            issuer="simulator",
            scope=scope,
            requires_checkpoint=requires_checkpoint,
            status=PlanStatus.ACTIVE,
            budget=PlanBudget(),
        )
        return [self._evaluate(plan, tool_name, action) for tool_name in tool_names]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate(
        self, plan: MissionPlan, tool_name: str, action: str = ""
    ) -> ScopeSimulateResult:
        """Core evaluation logic shared by async and sync paths."""
        # 1. Scope allow check
        scope_result = plan_scope_filter.check(plan, tool_name)

        # 2. Checkpoint check
        checkpoint_result = plan_checkpoint_filter.check(plan, tool_name)

        # 3. Compile scope patterns for informational output
        compiled_patterns: list[str] = []
        for pattern in plan.scope:
            compiled = scope_pattern_compiler.compile(pattern)
            compiled_patterns.extend(compiled.rbac_patterns)

        # 4. Determine effective decision
        if not scope_result.allowed:
            effective = "DENY"
        elif checkpoint_result.matches:
            effective = "ESCALATE"
        else:
            effective = "ALLOW"

        return ScopeSimulateResult(
            tool_name=tool_name,
            action=action,
            scope_allowed=scope_result.allowed,
            scope_matched_pattern=scope_result.matched_scope,
            scope_reason=scope_result.reason,
            checkpoint_triggered=checkpoint_result.matches,
            checkpoint_matched_pattern=checkpoint_result.matched_pattern,
            checkpoint_reason=checkpoint_result.reason,
            effective_decision=effective,
            compiled_rbac_patterns=compiled_patterns,
        )

    async def _get_plan(self, plan_id: UUID) -> MissionPlan:
        """Fetch a plan from the mission plan service."""
        from app.services.mission_plan_service import mission_plan_service

        plan = await mission_plan_service.get_plan(plan_id)
        if plan is None:
            raise ValueError(f"Plan {plan_id} not found")
        return plan


# Module-level singleton
scope_simulator = ScopeSimulator()
