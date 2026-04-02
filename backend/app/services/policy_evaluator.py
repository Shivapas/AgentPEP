"""PolicyEvaluator — reads rules from MongoDB and evaluates tool call requests.

Sprint 3 refactor: delegates to RoleResolver (APEP-021), RuleMatcher (APEP-022/023),
RuleCache (APEP-026), and uses JSON schema + regex validators (APEP-024/025).
"""

import asyncio
import hashlib
import json
import logging
import time
from uuid import UUID

from app.core.config import settings
from app.db import mongodb as db_module
from app.models.policy import (
    AuditDecision,
    Decision,
    PolicyDecisionResponse,
    ToolCallRequest,
)
from app.services.role_resolver import role_resolver
from app.services.rule_cache import rule_cache
from app.services.rule_matcher import rule_matcher

logger = logging.getLogger(__name__)


class PolicyEvaluator:
    """Evaluates tool call requests against the policy rule stack.

    Rules are fetched (with caching) from MongoDB, sorted by priority
    (lower = higher priority), and evaluated with first-match semantics.
    Default is deny-by-default.
    """

    async def evaluate(self, request: ToolCallRequest) -> PolicyDecisionResponse:
        """Evaluate a tool call request and return a policy decision."""
        start = time.monotonic()

        try:
            decision_response = await asyncio.wait_for(
                self._evaluate_internal(request, start),
                timeout=settings.evaluation_timeout_s,
            )
        except asyncio.TimeoutError:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            if settings.default_fail_mode == "FAIL_OPEN":
                decision = Decision.ALLOW
                reason = "Policy evaluation timed out — FAIL_OPEN mode, defaulting to ALLOW"
            else:
                decision = Decision.TIMEOUT
                reason = "Policy evaluation timed out — FAIL_CLOSED mode, defaulting to TIMEOUT"

            decision_response = PolicyDecisionResponse(
                request_id=request.request_id,
                decision=decision,
                reason=reason,
                latency_ms=elapsed_ms,
            )

        await self._write_audit_log(request, decision_response)
        return decision_response

    async def _evaluate_internal(
        self, request: ToolCallRequest, start: float
    ) -> PolicyDecisionResponse:
        """Core evaluation logic: resolve roles, fetch cached rules, match, decide."""
        # Resolve all agent roles (direct + inherited via hierarchy)
        agent_roles = await role_resolver.resolve_roles(request.agent_id)

        # Fetch enabled rules (cached with TTL)
        rules = await rule_cache.get_rules()

        # First-match evaluation via RuleMatcher
        result = rule_matcher.match(
            tool_name=request.tool_name,
            tool_args=request.tool_args,
            agent_roles=agent_roles,
            rules=rules,
        )

        elapsed_ms = int((time.monotonic() - start) * 1000)

        if not result.matched:
            # Deny-by-default when no rule matches
            return PolicyDecisionResponse(
                request_id=request.request_id,
                decision=Decision.DRY_RUN if request.dry_run else Decision.DENY,
                reason=result.reason,
                latency_ms=elapsed_ms,
            )

        matched_rule = result.rule
        assert matched_rule is not None

        decision = matched_rule.action

        # DRY_RUN mode: evaluate fully but never enforce
        if request.dry_run:
            decision = Decision.DRY_RUN

        return PolicyDecisionResponse(
            request_id=request.request_id,
            decision=decision,
            matched_rule_id=matched_rule.rule_id,
            reason=result.reason,
            latency_ms=elapsed_ms,
        )

    @staticmethod
    async def _write_audit_log(
        request: ToolCallRequest, response: PolicyDecisionResponse
    ) -> None:
        """Write an audit decision record to MongoDB."""
        db = db_module.get_database()

        args_hash = hashlib.sha256(
            json.dumps(request.tool_args, sort_keys=True).encode()
        ).hexdigest()

        audit = AuditDecision(
            session_id=request.session_id,
            agent_id=request.agent_id,
            agent_role="unknown",
            tool_name=request.tool_name,
            tool_args_hash=args_hash,
            delegation_chain=request.delegation_chain,
            matched_rule_id=response.matched_rule_id,
            decision=response.decision,
            risk_score=response.risk_score,
            taint_flags=response.taint_flags,
            latency_ms=response.latency_ms,
        )

        try:
            await db[db_module.AUDIT_DECISIONS].insert_one(
                audit.model_dump(mode="json")
            )
        except Exception:
            # Audit write failure should not block the decision
            pass


# Module-level singleton
policy_evaluator = PolicyEvaluator()
