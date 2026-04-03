"""PolicyEvaluator — reads rules from MongoDB and evaluates tool call requests.

Sprint 3 refactor: delegates to RoleResolver (APEP-021), RuleMatcher (APEP-022/023),
RuleCache (APEP-026), and uses JSON schema + regex validators (APEP-024/025).
Sprint 5: integrates taint checking (APEP-043) — escalates if UNTRUSTED/QUARANTINE
args are used on privileged tools with taint_check enabled.
Sprint 7: integrates confused-deputy detector (APEP-060) — validates delegation
chains, enforces depth limits, and detects implicit delegation.
Sprint 26: adds OpenTelemetry spans (APEP-207) and audit write metrics (APEP-204).
"""

import asyncio
import hashlib
import json
import time
from uuid import UUID

from app.core.config import settings
from app.core.observability import (
    AUDIT_WRITE_LATENCY,
    AUDIT_WRITE_TOTAL,
    ESCALATION_BACKLOG,
    get_tracer,
)
from app.core.structured_logging import get_logger
from app.db import mongodb as db_module
from app.models.policy import (
    AuditDecision,
    Decision,
    PolicyDecisionResponse,
    TaintLevel,
    ToolCallRequest,
)
from app.services.confused_deputy import confused_deputy_detector
from app.services.role_resolver import role_resolver
from app.services.rule_cache import rule_cache
from app.services.rule_matcher import rule_matcher
from app.services.taint_graph import session_graph_manager

logger = get_logger(__name__)
tracer = get_tracer(__name__)


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

        # Track escalation backlog
        if decision_response.decision == Decision.ESCALATE:
            ESCALATION_BACKLOG.inc()

        await self._write_audit_log(request, decision_response)

        logger.info(
            "policy_decision",
            decision_id=str(decision_response.request_id),
            session_id=request.session_id,
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            decision=decision_response.decision.value,
            latency_ms=decision_response.latency_ms,
            matched_rule_id=str(decision_response.matched_rule_id) if decision_response.matched_rule_id else None,
            reason=decision_response.reason,
        )

        return decision_response

    async def _evaluate_internal(
        self, request: ToolCallRequest, start: float
    ) -> PolicyDecisionResponse:
        """Core evaluation logic: resolve roles, fetch cached rules, match, decide."""

        # --- Confused-deputy check (APEP-060) ---
        with tracer.start_as_current_span(
            "confused_deputy_check",
            attributes={"agentpep.agent_id": request.agent_id},
        ):
            if request.delegation_hops:
                deputy_ok, deputy_reason = await confused_deputy_detector.evaluate(
                    session_id=request.session_id,
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    delegation_hops=request.delegation_hops,
                )
                if not deputy_ok:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    # ESCALATE for implicit delegation warnings, DENY for hard violations
                    if deputy_reason.startswith("ESCALATE:"):
                        decision = Decision.ESCALATE
                        reason = deputy_reason[len("ESCALATE: "):]
                    else:
                        decision = Decision.DENY
                        reason = deputy_reason

                    if request.dry_run:
                        decision = Decision.DRY_RUN

                    return PolicyDecisionResponse(
                        request_id=request.request_id,
                        decision=decision,
                        reason=f"Confused-deputy check: {reason}",
                        latency_ms=elapsed_ms,
                    )
            else:
                # No explicit delegation — check for implicit delegation (APEP-058)
                deputy_ok, deputy_reason = await confused_deputy_detector.evaluate(
                    session_id=request.session_id,
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    delegation_hops=[],
                )
                if not deputy_ok and deputy_reason.startswith("ESCALATE:"):
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    decision = Decision.ESCALATE
                    if request.dry_run:
                        decision = Decision.DRY_RUN
                    return PolicyDecisionResponse(
                        request_id=request.request_id,
                        decision=decision,
                        reason=f"Confused-deputy check: {deputy_reason[len('ESCALATE: '):]!s}",
                        latency_ms=elapsed_ms,
                    )

        # Resolve all agent roles (direct + inherited via hierarchy)
        with tracer.start_as_current_span(
            "resolve_roles",
            attributes={"agentpep.agent_id": request.agent_id},
        ):
            agent_roles = await role_resolver.resolve_roles(request.agent_id)

        # Fetch enabled rules (cached with TTL)
        with tracer.start_as_current_span("fetch_rules"):
            rules = await rule_cache.get_rules()

        # First-match evaluation via RuleMatcher
        with tracer.start_as_current_span(
            "rule_match",
            attributes={
                "agentpep.tool_name": request.tool_name,
                "agentpep.rule_count": len(rules),
            },
        ):
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
        taint_flags: list[str] = []

        # --- Taint check (APEP-043) ---
        if matched_rule.taint_check and request.taint_node_ids:
            with tracer.start_as_current_span(
                "taint_check",
                attributes={"agentpep.taint_node_count": len(request.taint_node_ids)},
            ):
                taint_decision, taint_flags = self._check_taint(
                    request.session_id, request.taint_node_ids
                )
                if taint_decision is not None:
                    decision = taint_decision

        # DRY_RUN mode: evaluate fully but never enforce
        if request.dry_run:
            decision = Decision.DRY_RUN

        reason = result.reason
        if taint_flags:
            reason += f" | Taint flags: {', '.join(taint_flags)}"

        return PolicyDecisionResponse(
            request_id=request.request_id,
            decision=decision,
            matched_rule_id=matched_rule.rule_id,
            reason=reason,
            taint_flags=taint_flags,
            latency_ms=elapsed_ms,
        )

    @staticmethod
    def _check_taint(
        session_id: str, taint_node_ids: list[UUID]
    ) -> tuple[Decision | None, list[str]]:
        """Check taint levels for the given node IDs.

        Returns (escalation_decision, taint_flags).
        - DENY if any node is QUARANTINE
        - ESCALATE if any node is UNTRUSTED
        - None (no override) if all TRUSTED
        """
        graph = session_graph_manager.get_session(session_id)
        if graph is None:
            return None, []

        taint_flags = graph.get_taint_flags(taint_node_ids)

        if graph.has_quarantined_nodes(taint_node_ids):
            return Decision.DENY, taint_flags

        if graph.has_untrusted_nodes(taint_node_ids):
            return Decision.ESCALATE, taint_flags

        return None, taint_flags

    @staticmethod
    async def _write_audit_log(
        request: ToolCallRequest, response: PolicyDecisionResponse
    ) -> None:
        """Write an audit decision record to MongoDB."""
        with tracer.start_as_current_span(
            "audit_log_write",
            attributes={
                "agentpep.decision_id": str(response.request_id),
                "agentpep.decision": response.decision.value,
            },
        ):
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

            audit_start = time.monotonic()
            try:
                await db[db_module.AUDIT_DECISIONS].insert_one(
                    audit.model_dump(mode="json")
                )
                AUDIT_WRITE_TOTAL.labels(status="success").inc()
            except Exception:
                AUDIT_WRITE_TOTAL.labels(status="failure").inc()
                logger.warning(
                    "audit_write_failed",
                    decision_id=str(response.request_id),
                    session_id=request.session_id,
                )
            finally:
                AUDIT_WRITE_LATENCY.observe(time.monotonic() - audit_start)


# Module-level singleton
policy_evaluator = PolicyEvaluator()
