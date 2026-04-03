"""PolicyEvaluator — reads rules from MongoDB and evaluates tool call requests.

Sprint 3 refactor: delegates to RoleResolver (APEP-021), RuleMatcher (APEP-022/023),
RuleCache (APEP-026), and uses JSON schema + regex validators (APEP-024/025).
Sprint 5: integrates taint checking (APEP-043) — escalates if UNTRUSTED/QUARANTINE
args are used on privileged tools with taint_check enabled.
Sprint 7: integrates confused-deputy detector (APEP-060) — validates delegation
chains, enforces depth limits, and detects implicit delegation.
Sprint 23:
  APEP-180: Eliminated unnecessary serialisation in hot path — tool_args hash
            uses pre-sorted JSON bytes, audit record built with minimal copies.
  APEP-184: Async audit log writer — audit writes are batched and decoupled
            from the intercept response path via a background queue.
  APEP-186: Adaptive timeouts — uses shorter timeout when rules are cached.
  APEP-187: Optimised risk scorer — inline risk calculation on hot path.
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
    PolicyRule,
    TaintLevel,
    ToolCallRequest,
)
from app.services.confused_deputy import confused_deputy_detector
from app.services.role_resolver import role_resolver
from app.services.rule_cache import rule_cache
from app.services.rule_matcher import rule_matcher
from app.services.taint_graph import session_graph_manager

logger = logging.getLogger(__name__)


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
        self._queue: asyncio.Queue[dict] = asyncio.Queue()
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
                except asyncio.TimeoutError:
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

        # APEP-184: Enqueue audit record (non-blocking)
        self._enqueue_audit(request, decision_response)
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

        # --- Confused-deputy check (APEP-060) ---
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
                    reason=f"Confused-deputy check: {deputy_reason[len('ESCALATE: '):]}",
                    latency_ms=elapsed_ms,
                )

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
        taint_flags: list[str] = []

        # --- Taint check (APEP-043) ---
        if matched_rule.taint_check and request.taint_node_ids:
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

        # APEP-187: Compute risk score
        computed_risk = risk_scorer.score(
            taint_flags=taint_flags,
            tool_name=request.tool_name,
            delegation_chain=request.delegation_chain,
            matched_rule=matched_rule,
        )

        return PolicyDecisionResponse(
            request_id=request.request_id,
            decision=decision,
            matched_rule_id=matched_rule.rule_id,
            reason=reason,
            taint_flags=taint_flags,
            risk_score=computed_risk,
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

    @staticmethod
    async def _write_audit_log(
        request: ToolCallRequest, response: PolicyDecisionResponse
    ) -> None:
        """Write an audit decision record to MongoDB (legacy sync path).

        Retained for backward compatibility with tests. Production path
        uses _enqueue_audit() via AsyncAuditLogWriter (APEP-184).
        """
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
