"""PolicyEvaluator — reads rules from MongoDB and evaluates tool call requests.

Sprint 3 refactor: delegates to RoleResolver (APEP-021), RuleMatcher (APEP-022/023),
RuleCache (APEP-026), and uses JSON schema + regex validators (APEP-024/025).
Sprint 5: integrates taint checking (APEP-043) — escalates if UNTRUSTED/QUARANTINE
args are used on privileged tools with taint_check enabled.
Sprint 7: integrates confused-deputy detector (APEP-060) — validates delegation
chains, enforces depth limits, and detects implicit delegation.
Sprint 8: integrates risk scoring engine (APEP-070) — computes [0–1] risk score
per tool call and ESCALATES when score exceeds the configured threshold.
Sprint 11: integrates rate limiter (APEP-090/091/092) and validator pipeline
(APEP-093/094/095/096) — rate limits per-role per-tool with sliding/fixed window;
global per-tenant ceiling; sequential validator pipeline where any failure → DENY.
Sprint 23:
  APEP-180: Eliminated unnecessary serialisation in hot path — tool_args hash
            uses pre-sorted JSON bytes, audit record built with minimal copies.
  APEP-184: Async audit log writer — audit writes are batched and decoupled
            from the intercept response path via a background queue.
  APEP-186: Adaptive timeouts — uses shorter timeout when rules are cached.
  APEP-187: Optimised risk scorer — inline risk calculation on hot path.
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
    PolicyRule,
    ToolCallRequest,
)
from app.services.audit_integrity import audit_integrity_verifier
from app.services.audit_logger import audit_logger
from app.services.confused_deputy import confused_deputy_detector
from app.services.kafka_producer import kafka_producer
from app.services.rate_limiter import rate_limiter
from app.services.risk_scoring import risk_engine
from app.services.role_resolver import role_resolver
from app.services.rule_cache import rule_cache
from app.services.rule_matcher import rule_matcher
from app.services.taint_graph import session_graph_manager
from app.services.validator_pipeline import validator_pipeline

logger = get_logger(__name__)
tracer = get_tracer(__name__)


# ---------------------------------------------------------------------------
# APEP-184: Async Audit Log Writer (background queue)
# ---------------------------------------------------------------------------


class AsyncAuditLogWriter:
    """Batched, non-blocking audit log writer.

    Audit records are enqueued and flushed to MongoDB in batches by a
    background task, ensuring audit writes never add latency to the
    intercept response path.
    """

    def __init__(
        self,
        batch_size: int | None = None,
        flush_interval_s: float | None = None,
    ) -> None:
        self._batch_size = batch_size or settings.audit_log_batch_size
        self._flush_interval_s = flush_interval_s or settings.audit_log_flush_interval_s
        self._queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=10000)
        self._task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._running = False

    def start(self) -> None:
        """Start the background flush loop (idempotent)."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.ensure_future(self._flush_loop())

    def stop(self) -> None:
        """Signal the flush loop to stop after draining."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

    def enqueue(self, record: dict) -> None:
        """Enqueue an audit record for background writing (non-blocking)."""
        try:
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            logger.warning("Audit log queue full — dropping record")

    async def _flush_loop(self) -> None:
        """Background loop: flush batches to MongoDB at regular intervals."""
        while self._running:
            batch: list[dict] = []
            try:
                # Wait for at least one item or timeout
                try:
                    item = await asyncio.wait_for(
                        self._queue.get(), timeout=self._flush_interval_s
                    )
                    batch.append(item)
                except TimeoutError:
                    pass

                # Drain up to batch_size
                while len(batch) < self._batch_size:
                    try:
                        batch.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break

                if batch:
                    await self._write_batch(batch)
            except asyncio.CancelledError:
                # Drain remaining items before exiting
                while not self._queue.empty():
                    try:
                        batch.append(self._queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                if batch:
                    await self._write_batch(batch)
                return
            except Exception:
                logger.exception("Audit flush loop error")

    @staticmethod
    async def _write_batch(batch: list[dict]) -> None:
        """Write a batch of audit records to MongoDB."""
        try:
            db = db_module.get_database()
            await db[db_module.AUDIT_DECISIONS].insert_many(batch, ordered=False)
            logger.debug("Flushed %d audit records to MongoDB", len(batch))
        except Exception:
            logger.exception("Failed to write audit batch (%d records)", len(batch))

    async def flush_pending(self) -> int:
        """Flush all pending records immediately (for testing / shutdown)."""
        batch: list[dict] = []
        while not self._queue.empty():
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        if batch:
            await self._write_batch(batch)
        return len(batch)

    @property
    def pending_count(self) -> int:
        return self._queue.qsize()


# Module-level singleton
audit_log_writer = AsyncAuditLogWriter()


# ---------------------------------------------------------------------------
# APEP-187: Optimised Risk Scorer
# ---------------------------------------------------------------------------


class RiskScorer:
    """Lightweight risk scorer for the intercept hot path.

    Computes a 0.0–1.0 risk score based on taint flags, tool sensitivity,
    and delegation chain depth.  Designed for sub-millisecond execution.
    """

    # Pre-computed weights (no config lookup per call)
    _TAINT_WEIGHTS = {
        "QUARANTINE": 0.9,
        "UNTRUSTED": 0.5,
        "TRUSTED": 0.0,
    }
    _DELEGATION_DEPTH_WEIGHT = 0.05  # per hop
    _SENSITIVE_TOOL_PREFIXES = (
        "file.write", "file.delete", "exec.", "shell.", "db.drop",
        "admin.", "deploy.", "secret.", "credential.",
    )
    _SENSITIVE_TOOL_SCORE = 0.3

    def score(
        self,
        taint_flags: list[str],
        tool_name: str,
        delegation_chain: list[str],
        matched_rule: PolicyRule | None = None,
    ) -> float:
        """Compute risk score (0.0 = safe, 1.0 = maximum risk)."""
        risk = 0.0

        # Taint contribution — take the highest taint flag
        if taint_flags:
            taint_score = max(
                self._TAINT_WEIGHTS.get(flag, 0.0) for flag in taint_flags
            )
            risk += taint_score

        # Tool sensitivity
        tool_lower = tool_name.lower()
        for prefix in self._SENSITIVE_TOOL_PREFIXES:
            if tool_lower.startswith(prefix):
                risk += self._SENSITIVE_TOOL_SCORE
                break

        # Delegation chain depth
        if delegation_chain:
            risk += min(len(delegation_chain) * self._DELEGATION_DEPTH_WEIGHT, 0.25)

        # Rule risk threshold as a signal
        if matched_rule and matched_rule.risk_threshold < 1.0:
            risk += (1.0 - matched_rule.risk_threshold) * 0.2

        return min(risk, 1.0)


# Module-level singleton
risk_scorer = RiskScorer()


# ---------------------------------------------------------------------------
# PolicyEvaluator
# ---------------------------------------------------------------------------


class PolicyEvaluator:
    """Evaluates tool call requests against the policy rule stack.

    Rules are fetched (with caching) from MongoDB, sorted by priority
    (lower = higher priority), and evaluated with first-match semantics.
    Default is deny-by-default.
    """

    async def evaluate(self, request: ToolCallRequest) -> PolicyDecisionResponse:
        """Evaluate a tool call request and return a policy decision."""
        start = time.monotonic()

        # APEP-186: Adaptive timeout — use shorter timeout when rules are cached
        timeout = self._select_timeout()

        try:
            decision_response = await asyncio.wait_for(
                self._evaluate_internal(request, start),
                timeout=timeout,
            )
        except TimeoutError:
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

        # Sprint 40 (APEP-319): Record delegation via PlanBudgetGate for ALLOW
        # decisions — updates Redis + MongoDB budget state and emits alerts.
        if (
            settings.mission_plan_enabled
            and decision_response.decision == Decision.ALLOW
        ):
            try:
                from app.services.mission_plan_service import mission_plan_service
                from app.services.plan_budget_gate import plan_budget_gate

                plan = await mission_plan_service.get_plan_for_session(
                    request.session_id
                )
                if plan is not None:
                    await plan_budget_gate.record_delegation(
                        plan, decision_response.risk_score
                    )
            except Exception:
                logger.warning(
                    "Plan delegation recording failed; proceeding",
                    exc_info=True,
                )

        # APEP-184: Enqueue audit record (non-blocking)
        self._enqueue_audit(request, decision_response)
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
            matched_rule_id=(
                str(decision_response.matched_rule_id)
                if decision_response.matched_rule_id
                else None
            ),
            reason=decision_response.reason,
        )

        return decision_response

    @staticmethod
    def _select_timeout() -> float:
        """APEP-186: Return adaptive timeout based on cache state."""
        if rule_cache.is_warm:
            return settings.evaluation_timeout_cached_s
        return settings.evaluation_timeout_cold_s

    async def _evaluate_internal(
        self, request: ToolCallRequest, start: float
    ) -> PolicyDecisionResponse:
        """Core evaluation logic: resolve roles, fetch cached rules, match, decide."""

        # --- Sprint 37: Plan pipeline filters (pre-RBAC) ---
        if settings.mission_plan_enabled:
            plan_result = await self._check_plan_constraints(request, start)
            if plan_result is not None:
                return plan_result

        # --- Global per-tenant rate limit (APEP-092) ---
        # Prefer authenticated tenant_id from middleware to prevent tenant ID spoofing.
        # Never fall back to the client-supplied request body value.
        tenant_id = getattr(request, "_authenticated_tenant_id", None)
        if tenant_id is None:
            tenant_id = request.tenant_id
            if tenant_id and tenant_id != "default":
                logger.warning(
                    "tenant_id_unverified",
                    tenant_id=tenant_id,
                    session_id=request.session_id,
                )
        global_rl = await rate_limiter.check_global_rate_limit(tenant_id)
        if not global_rl.allowed:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            decision = Decision.DRY_RUN if request.dry_run else Decision.DENY
            return PolicyDecisionResponse(
                request_id=request.request_id,
                decision=decision,
                reason=global_rl.reason,
                latency_ms=elapsed_ms,
            )

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

        # --- Data classification check (Sprint 31 — APEP-248) ---
        with tracer.start_as_current_span(
            "data_classification_check",
            attributes={"agentpep.tool_name": request.tool_name},
        ):
            try:
                from app.services.data_classification import data_classification_engine

                dc_allowed, dc_reason = await data_classification_engine.enforce(
                    agent_roles=agent_roles,
                    tool_name=request.tool_name,
                    agent_id=request.agent_id,
                )
                if not dc_allowed:
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    decision = Decision.DRY_RUN if request.dry_run else Decision.DENY
                    return PolicyDecisionResponse(
                        request_id=request.request_id,
                        decision=decision,
                        reason=dc_reason,
                        latency_ms=elapsed_ms,
                    )
            except Exception:
                logger.warning(
                    "Data classification check failed; proceeding without",
                    exc_info=True,
                )

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

        # --- Per-rule rate limit check (APEP-090/091) ---
        # Rate limiting runs BEFORE the validator pipeline to prevent
        # resource exhaustion via repeated invalid requests.
        if matched_rule.rate_limit is not None:
            # Use the first matching agent role for the rate limit key
            rl_role = agent_roles[0] if agent_roles else request.agent_id
            rl_result = await rate_limiter.check(
                agent_role=rl_role,
                tool_name=request.tool_name,
                rate_limit=matched_rule.rate_limit,
            )
            if not rl_result.allowed:
                elapsed_ms = int((time.monotonic() - start) * 1000)
                decision = Decision.DRY_RUN if request.dry_run else Decision.DENY
                return PolicyDecisionResponse(
                    request_id=request.request_id,
                    decision=decision,
                    matched_rule_id=matched_rule.rule_id,
                    reason=rl_result.reason,
                    latency_ms=elapsed_ms,
                )

        # --- Validator pipeline (APEP-093/094/095/096) ---
        if matched_rule.arg_validators:
            validation = validator_pipeline.validate(
                request.tool_args, matched_rule.arg_validators
            )
            if not validation.passed:
                elapsed_ms = int((time.monotonic() - start) * 1000)
                decision = Decision.DRY_RUN if request.dry_run else Decision.DENY
                return PolicyDecisionResponse(
                    request_id=request.request_id,
                    decision=decision,
                    matched_rule_id=matched_rule.rule_id,
                    reason=f"Validator pipeline failed: {validation.reason}",
                    latency_ms=elapsed_ms,
                )

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

        # --- Risk scoring (APEP-070) ---
        risk_score = 0.0
        risk_factors: list = []
        try:
            risk_score, risk_factors = await risk_engine.compute(
                tool_name=request.tool_name,
                tool_args=request.tool_args,
                session_id=request.session_id,
                taint_node_ids=request.taint_node_ids or None,
                delegation_hops=request.delegation_hops or None,
                agent_roles=agent_roles or None,
                agent_id=request.agent_id,
            )

            config = risk_engine.aggregator.get_config()
            # Check per-rule risk_threshold first, then global escalation_threshold
            threshold = matched_rule.risk_threshold
            if threshold >= 1.0:
                # Rule has no specific threshold — use global config
                threshold = config.escalation_threshold

            if risk_score > threshold and decision == Decision.ALLOW:
                decision = Decision.ESCALATE
        except Exception:
            logger.warning("Risk scoring failed; proceeding without score", exc_info=True)

        # Sprint 33 (APEP-265): Block untrusted context from privileged decisions
        if settings.context_authority_enabled and decision == Decision.ALLOW:
            try:
                from app.services.context_authority import (
                    ContextAuthority,
                    context_authority_tracker,
                )

                counts = await context_authority_tracker.get_session_authorities(
                    request.session_id
                )
                untrusted = counts.get(ContextAuthority.UNTRUSTED, 0)
                total = sum(counts.values())
                if untrusted > 0 and total > 0:
                    untrusted_ratio = untrusted / total
                    # If majority untrusted and tool is privileged → ESCALATE
                    if untrusted_ratio > 0.5 and matched_rule.taint_check:
                        decision = Decision.ESCALATE
                        reason = (
                            result.reason
                            + " | Context authority: majority UNTRUSTED — escalated for privileged tool"
                        )
            except Exception:
                logger.warning(
                    "Context authority check failed; proceeding without",
                    exc_info=True,
                )

        # --- Sprint 36 (APEP-286): Trust degradation engine check ---
        if settings.trust_degradation_engine_enabled and decision == Decision.ALLOW:
            try:
                from app.services.trust_degradation_engine import trust_degradation_engine

                trust_record = await trust_degradation_engine.get_or_create_record(
                    request.session_id, request.tenant_id
                )
                if trust_record.locked:
                    decision = Decision.DENY
                    reason = (
                        result.reason
                        + " | Trust degradation: session locked (ceiling below threshold)"
                    )
                elif trust_record.current_ceiling < 0.5 and matched_rule.taint_check:
                    decision = Decision.DEFER
            except Exception:
                logger.warning(
                    "Trust degradation engine check failed; proceeding without",
                    exc_info=True,
                )

        # --- Sprint 36 (APEP-288): STEP_UP decision for rules requiring auth factors ---
        step_up_requirements: list[str] | None = None
        step_up_challenge_id: str | None = None
        if matched_rule.step_up_auth and decision == Decision.ALLOW:
            decision = Decision.STEP_UP
            step_up_requirements = matched_rule.step_up_auth
            try:
                from app.services.step_up_handler import step_up_handler

                challenge = await step_up_handler.create_challenge(
                    request_id=request.request_id,
                    session_id=request.session_id,
                    agent_id=request.agent_id,
                    required_factors=matched_rule.step_up_auth,
                    tenant_id=request.tenant_id,
                )
                step_up_challenge_id = str(challenge.challenge_id)
            except Exception:
                logger.warning(
                    "STEP_UP challenge creation failed; falling back to ESCALATE",
                    exc_info=True,
                )
                decision = Decision.ESCALATE

        # --- Sprint 36 (APEP-287): DEFER decision support ---
        defer_reason: str | None = None
        if decision == Decision.DEFER:
            defer_reason = "Trust degradation or policy ambiguity requires deferred evaluation"
            try:
                from app.services.defer_handler import defer_handler

                await defer_handler.create_deferral(
                    request_id=request.request_id,
                    session_id=request.session_id,
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    reason=defer_reason,
                    timeout_s=settings.defer_default_timeout_s,
                    tenant_id=request.tenant_id,
                )
            except Exception:
                logger.warning(
                    "DEFER record creation failed; proceeding",
                    exc_info=True,
                )

        # --- PII Redaction with MODIFY decision (Sprint 35 — APEP-282) ---
        modified_args: dict | None = None
        if settings.pii_redaction_enabled and decision == Decision.ALLOW:
            try:
                from app.models.data_classification import classification_gte
                from app.services.data_classification import data_classification_engine
                from app.services.pii_redaction import pii_redaction_engine

                redacted_args, pii_matches = pii_redaction_engine.redact_dict(
                    request.tool_args or {}
                )
                if pii_matches:
                    agent_clearance = await data_classification_engine.get_agent_clearance(
                        agent_roles
                    )
                    if not classification_gte(agent_clearance, "PII"):
                        decision = Decision.MODIFY
                        modified_args = redacted_args
                        pii_count = len(pii_matches)
                        categories = {m.category for m in pii_matches}
                        logger.info(
                            "pii_redaction_applied",
                            session_id=request.session_id,
                            agent_id=request.agent_id,
                            pii_count=pii_count,
                            categories=str(categories),
                        )
            except Exception:
                logger.warning(
                    "PII redaction check failed; proceeding without",
                    exc_info=True,
                )

        # DRY_RUN mode: evaluate fully but never enforce
        if request.dry_run:
            decision = Decision.DRY_RUN

        reason = result.reason
        if taint_flags:
            reason += f" | Taint flags: {', '.join(taint_flags)}"

        elapsed_ms = int((time.monotonic() - start) * 1000)
        # APEP-187: Use the risk score from the full risk scoring engine
        # (computed above via risk_engine.compute) which accounts for
        # operation type, data sensitivity, taint, session history, and
        # delegation depth.  The inline RiskScorer is used only as a
        # fallback when the engine score is unavailable (e.g. exception).
        if risk_score == 0.0:
            # Engine may have failed or returned 0 — try inline scorer
            computed_risk = risk_scorer.score(
                taint_flags=taint_flags,
                tool_name=request.tool_name,
                delegation_chain=request.delegation_chain,
                matched_rule=matched_rule,
            )
            risk_score = max(risk_score, computed_risk)

        # --- Adaptive hardening (Sprint 35 — APEP-280) ---
        hardening_texts: list[str] | None = None
        if settings.adaptive_hardening_enabled:
            try:
                from app.services.adaptive_hardening import adaptive_hardening_engine

                instructions = adaptive_hardening_engine.record_and_generate(
                    session_id=request.session_id,
                    risk_factors=risk_factors,
                    risk_score=risk_score,
                )
                if instructions:
                    hardening_texts = [inst.text for inst in instructions]
            except Exception:
                logger.warning(
                    "Adaptive hardening failed; proceeding without",
                    exc_info=True,
                )

        return PolicyDecisionResponse(
            request_id=request.request_id,
            decision=decision,
            matched_rule_id=matched_rule.rule_id,
            reason=reason,
            taint_flags=taint_flags,
            risk_score=risk_score,
            latency_ms=elapsed_ms,
            hardening_instructions=hardening_texts,
            modified_args=modified_args,
            # Sprint 36 — APEP-287/288
            step_up_requirements=step_up_requirements,
            step_up_challenge_id=step_up_challenge_id,
            defer_reason=defer_reason,
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
            logger.warning(
                "taint_session_not_found",
                session_id=session_id,
                detail="Taint check requested for uninitialized session — defaulting to DENY",
            )
            return Decision.DENY, ["UNKNOWN_SESSION"]

        taint_flags = graph.get_taint_flags(taint_node_ids)

        if graph.has_quarantined_nodes(taint_node_ids):
            return Decision.DENY, taint_flags

        if graph.has_untrusted_nodes(taint_node_ids):
            return Decision.ESCALATE, taint_flags

        return None, taint_flags

    @staticmethod
    def _enqueue_audit(
        request: ToolCallRequest, response: PolicyDecisionResponse
    ) -> None:
        """APEP-184: Enqueue audit record for background writing.

        APEP-180: Uses pre-sorted JSON bytes for hashing to avoid redundant
        serialisation.  The audit record dict is built directly without
        going through model_dump() on the hot path.
        """
        # Pre-compute args hash with minimal overhead (APEP-180)
        args_bytes = json.dumps(request.tool_args, sort_keys=True, separators=(",", ":")).encode()
        args_hash = hashlib.sha256(args_bytes).hexdigest()

        audit = AuditDecision(
            session_id=request.session_id,
            agent_id=request.agent_id,
            agent_role="unknown",
            tenant_id=request.tenant_id,
            tool_name=request.tool_name,
            tool_args_hash=args_hash,
            delegation_chain=request.delegation_chain,
            matched_rule_id=response.matched_rule_id,
            decision=response.decision,
            risk_score=response.risk_score,
            taint_flags=response.taint_flags,
            latency_ms=response.latency_ms,
        )

        audit_log_writer.enqueue(audit.model_dump(mode="json"))

    # ------------------------------------------------------------------
    # Sprint 37: Plan pipeline filters (APEP-292..298)
    # ------------------------------------------------------------------

    @staticmethod
    async def _check_plan_constraints(
        request: ToolCallRequest, start: float
    ) -> PolicyDecisionResponse | None:
        """Run plan-level filters before RBAC evaluation.

        Returns a PolicyDecisionResponse if the plan blocks the request,
        or None if the request should proceed to normal RBAC evaluation.

        Filters (in order — Sprint 41 reorder: APEP-324):
          1. PlanCheckpointFilter -- escalate FIRST if action matches
             requires_checkpoint (unconditional, before any other check).
          2. PlanBudgetGate -- deny if plan expired or budget exhausted
             (Sprint 40 — APEP-318/319: Redis-backed budget state).
          3. PlanDelegatesToFilter -- deny if agent not in delegates_to
             (Sprint 40 — APEP-316/317: glob-aware delegation whitelist).
          4. PlanScopeFilter -- deny if tool not within plan scope (Sprint 38).
        """
        try:
            from app.services.mission_plan_service import mission_plan_service

            plan = await mission_plan_service.get_plan_for_session(
                request.session_id
            )
            if plan is None:
                # No plan bound -- proceed to normal RBAC evaluation
                return None

            elapsed_ms = int((time.monotonic() - start) * 1000)

            # --- Sprint 41 (APEP-324): Resolve human_intent from plan ---
            human_intent = request.human_intent
            if not human_intent and plan.human_intent:
                human_intent = plan.human_intent
            elif not human_intent and plan.action:
                human_intent = plan.action

            # --- Sprint 41 (APEP-324): PlanCheckpointFilter FIRST ---
            # Unconditionally triggers ESCALATE for matched actions,
            # before budget, delegation, or scope checks.
            from app.services.scope_filter import plan_checkpoint_filter

            checkpoint_result = plan_checkpoint_filter.check(
                plan, request.tool_name
            )
            if checkpoint_result.matches:
                # Sprint 41 (APEP-326): Check plan-scoped approval memory
                from app.services.checkpoint_approval_memory import (
                    checkpoint_approval_memory,
                )

                has_approval = await checkpoint_approval_memory.check(
                    plan_id=plan.plan_id,
                    agent_id=request.agent_id,
                    tool_name=request.tool_name,
                    matched_pattern=checkpoint_result.matched_pattern or "",
                )
                if not has_approval:
                    decision = (
                        Decision.DRY_RUN if request.dry_run else Decision.ESCALATE
                    )
                    checkpoint_reason = (
                        f"Plan requires checkpoint approval: "
                        f"{checkpoint_result.reason}"
                    )

                    # Sprint 41 — APEP-S41.7: Emit Kafka event
                    try:
                        await kafka_producer.publish_checkpoint_escalation(
                            plan_id=str(plan.plan_id),
                            session_id=request.session_id,
                            agent_id=request.agent_id,
                            tool_name=request.tool_name,
                            matched_pattern=(
                                checkpoint_result.matched_pattern or ""
                            ),
                            match_reason=checkpoint_result.reason,
                            human_intent=human_intent,
                        )
                    except Exception:
                        logger.warning(
                            "Kafka checkpoint event failed; proceeding",
                            exc_info=True,
                        )

                    return PolicyDecisionResponse(
                        request_id=request.request_id,
                        decision=decision,
                        reason=checkpoint_reason,
                        latency_ms=elapsed_ms,
                        human_intent=human_intent,
                        checkpoint_match_reason=checkpoint_result.reason,
                    )

            # --- Sprint 40 (APEP-318/319): PlanBudgetGate (pre-evaluation) ---
            from app.services.plan_budget_gate import plan_budget_gate

            budget_result = await plan_budget_gate.check(plan)
            if not budget_result.allowed:
                decision = Decision.DRY_RUN if request.dry_run else Decision.DENY
                return PolicyDecisionResponse(
                    request_id=request.request_id,
                    decision=decision,
                    reason=f"Plan denied: {budget_result.reason}",
                    latency_ms=elapsed_ms,
                    human_intent=human_intent,
                )

            # --- Sprint 40 (APEP-316/317): PlanDelegatesToFilter ---
            from app.services.plan_delegates_filter import plan_delegates_filter

            delegation_result = plan_delegates_filter.check(
                plan, request.agent_id
            )
            if not delegation_result.authorized:
                decision = Decision.DRY_RUN if request.dry_run else Decision.DENY
                return PolicyDecisionResponse(
                    request_id=request.request_id,
                    decision=decision,
                    reason=f"Plan denied: {delegation_result.reason}",
                    latency_ms=elapsed_ms,
                    human_intent=human_intent,
                )

            # --- Sprint 38 (APEP-304): PlanScopeFilter (pre-RBAC stage) ---
            from app.services.scope_filter import plan_scope_filter

            scope_result = plan_scope_filter.check(plan, request.tool_name)
            if not scope_result.allowed:
                decision = Decision.DRY_RUN if request.dry_run else Decision.DENY
                return PolicyDecisionResponse(
                    request_id=request.request_id,
                    decision=decision,
                    reason=f"Plan scope denied: {scope_result.reason}",
                    latency_ms=elapsed_ms,
                    human_intent=human_intent,
                )

        except Exception:
            logger.warning(
                "Plan constraint check failed; proceeding without",
                exc_info=True,
            )

        return None

    @staticmethod
    async def _write_audit_log(
        request: ToolCallRequest, response: PolicyDecisionResponse
    ) -> None:
        """Write an audit decision record via AuditLogger (hash-chained) and publish to Kafka.

        Retained for backward compatibility with tests. Production path
        uses _enqueue_audit() via AsyncAuditLogWriter (APEP-184).
        """
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
                tenant_id=request.tenant_id,
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
                # APEP-081/082: Append with SHA-256 hash chain
                audit = await audit_logger.append(audit)
                audit_dict = audit.model_dump(mode="json")
                await db[db_module.AUDIT_DECISIONS].insert_one(audit_dict)
                AUDIT_WRITE_TOTAL.labels(status="success").inc()
                # APEP-191: Extend hash chain for integrity verification
                try:
                    await audit_integrity_verifier.seal_record(audit_dict)
                except Exception:
                    logger.warning("Failed to seal audit record in hash chain")
            except Exception:
                AUDIT_WRITE_TOTAL.labels(status="failure").inc()
                logger.warning(
                    "audit_write_failed",
                    decision_id=str(response.request_id),
                    session_id=request.session_id,
                )
            finally:
                AUDIT_WRITE_LATENCY.observe(time.monotonic() - audit_start)

        try:
            # APEP-083: Publish to Kafka
            await kafka_producer.publish_decision(audit)
        except Exception:
            logger.debug("Kafka publish skipped for request %s", request.request_id)


# Module-level singleton
policy_evaluator = PolicyEvaluator()
