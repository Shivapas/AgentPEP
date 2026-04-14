"""Sprint 40 — PlanDelegatesToFilter: pre-confused-deputy stage.

APEP-316: PlanDelegatesToFilter as a pre-stage in PolicyEvaluator.
APEP-317: delegates_to enforcement logic.

If a session is bound to a MissionPlan that has a non-empty ``delegates_to``
list, the calling ``agent_id`` MUST appear in that list.  If not, the request
is denied with reason code ``PLAN_AGENT_NOT_AUTHORIZED``.
"""

from __future__ import annotations

import fnmatch
import logging

from app.models.mission_plan import MissionPlan, PlanDenialReason
from app.models.plan_budget_gate import DelegationCheckResult

logger = logging.getLogger(__name__)


class PlanDelegatesToFilter:
    """Pre-confused-deputy filter: validates agent authorization under a plan.

    When a plan declares ``delegates_to``, only agents in that whitelist
    (or matching its glob patterns) may execute tool calls under the plan.
    An empty ``delegates_to`` means no delegation restriction — all bound
    agents are permitted.
    """

    def check(self, plan: MissionPlan, agent_id: str) -> DelegationCheckResult:
        """Check whether *agent_id* is authorized by the plan's delegates_to.

        Returns a :class:`DelegationCheckResult` with ``authorized=True`` if:
        - The plan's ``delegates_to`` list is empty (no restriction), OR
        - The ``agent_id`` appears literally in ``delegates_to``, OR
        - The ``agent_id`` matches a glob pattern in ``delegates_to``.
        """
        if not plan.delegates_to:
            return DelegationCheckResult(
                authorized=True,
                agent_id=agent_id,
                plan_id=plan.plan_id,
                reason="No delegation restriction (delegates_to is empty)",
            )

        # Exact match first, then glob match
        if agent_id in plan.delegates_to:
            return DelegationCheckResult(
                authorized=True,
                agent_id=agent_id,
                plan_id=plan.plan_id,
                reason=f"Agent '{agent_id}' found in delegates_to whitelist",
            )

        # Glob pattern matching (e.g. "agent-*", "team-alpha-*")
        for pattern in plan.delegates_to:
            if fnmatch.fnmatch(agent_id, pattern):
                return DelegationCheckResult(
                    authorized=True,
                    agent_id=agent_id,
                    plan_id=plan.plan_id,
                    reason=f"Agent '{agent_id}' matched delegates_to pattern '{pattern}'",
                )

        logger.warning(
            "plan_agent_not_authorized",
            extra={
                "plan_id": str(plan.plan_id),
                "agent_id": agent_id,
                "delegates_to": plan.delegates_to,
            },
        )

        return DelegationCheckResult(
            authorized=False,
            agent_id=agent_id,
            plan_id=plan.plan_id,
            reason=(
                f"{PlanDenialReason.PLAN_AGENT_NOT_AUTHORIZED}: "
                f"agent '{agent_id}' is not in plan delegates_to "
                f"{plan.delegates_to}"
            ),
        )

    def get_denial_reason(self) -> PlanDenialReason:
        """Return the denial reason code for this filter."""
        return PlanDenialReason.PLAN_AGENT_NOT_AUTHORIZED


# Module-level singleton
plan_delegates_filter = PlanDelegatesToFilter()
