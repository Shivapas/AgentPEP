"""SimulationEngine — full DRY_RUN evaluation API for CI/CD integration.

Sprint 19: APEP-151, APEP-152, APEP-154.

Evaluates a tool call request against the full policy stack (role resolution,
rule matching, taint evaluation, confused-deputy detection) without enforcement.
Supports running the same request against two policy versions and diffing results.
"""

import asyncio
import hashlib
import json
import logging
import time
from typing import Any
from uuid import UUID, uuid4

from app.core.config import settings
from app.db import mongodb as db_module
from app.models.policy import (
    Decision,
    DelegationHop,
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


class SimulationStepResult:
    """Detailed output of a single evaluation step."""

    __slots__ = ("step", "passed", "detail")

    def __init__(self, step: str, passed: bool, detail: str = ""):
        self.step = step
        self.passed = passed
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        return {"step": self.step, "passed": self.passed, "detail": self.detail}


class SimulationResult:
    """Full simulation result capturing every evaluation stage (APEP-152)."""

    def __init__(
        self,
        *,
        request_id: UUID,
        decision: Decision,
        matched_rule_id: UUID | None = None,
        matched_rule_name: str = "",
        risk_score: float = 0.0,
        taint_eval: dict[str, Any] | None = None,
        chain_result: dict[str, Any] | None = None,
        resolved_roles: list[str] | None = None,
        steps: list[SimulationStepResult] | None = None,
        reason: str = "",
        latency_ms: int = 0,
        policy_version: str = "current",
    ):
        self.request_id = request_id
        self.decision = decision
        self.matched_rule_id = matched_rule_id
        self.matched_rule_name = matched_rule_name
        self.risk_score = risk_score
        self.taint_eval = taint_eval or {}
        self.chain_result = chain_result or {}
        self.resolved_roles = resolved_roles or []
        self.steps = steps or []
        self.reason = reason
        self.latency_ms = latency_ms
        self.policy_version = policy_version

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": str(self.request_id),
            "decision": self.decision.value,
            "matched_rule_id": str(self.matched_rule_id) if self.matched_rule_id else None,
            "matched_rule_name": self.matched_rule_name,
            "risk_score": self.risk_score,
            "taint_eval": self.taint_eval,
            "chain_result": self.chain_result,
            "resolved_roles": self.resolved_roles,
            "steps": [s.to_dict() for s in self.steps],
            "reason": self.reason,
            "latency_ms": self.latency_ms,
            "policy_version": self.policy_version,
        }


class SimulationDiff:
    """Diff between two simulation results run against different policy versions (APEP-154)."""

    def __init__(self, result_a: SimulationResult, result_b: SimulationResult):
        self.result_a = result_a
        self.result_b = result_b

    @property
    def decision_changed(self) -> bool:
        return self.result_a.decision != self.result_b.decision

    @property
    def matched_rule_changed(self) -> bool:
        return self.result_a.matched_rule_id != self.result_b.matched_rule_id

    @property
    def risk_score_changed(self) -> bool:
        return self.result_a.risk_score != self.result_b.risk_score

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_changed": self.decision_changed,
            "matched_rule_changed": self.matched_rule_changed,
            "risk_score_changed": self.risk_score_changed,
            "version_a": {
                "policy_version": self.result_a.policy_version,
                **self.result_a.to_dict(),
            },
            "version_b": {
                "policy_version": self.result_b.policy_version,
                **self.result_b.to_dict(),
            },
            "changes": self._compute_changes(),
        }

    def _compute_changes(self) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        if self.decision_changed:
            changes.append({
                "field": "decision",
                "from": self.result_a.decision.value,
                "to": self.result_b.decision.value,
            })
        if self.matched_rule_changed:
            changes.append({
                "field": "matched_rule_id",
                "from": str(self.result_a.matched_rule_id) if self.result_a.matched_rule_id else None,
                "to": str(self.result_b.matched_rule_id) if self.result_b.matched_rule_id else None,
            })
        if self.risk_score_changed:
            changes.append({
                "field": "risk_score",
                "from": self.result_a.risk_score,
                "to": self.result_b.risk_score,
            })
        # Compare taint eval
        if self.result_a.taint_eval != self.result_b.taint_eval:
            changes.append({
                "field": "taint_eval",
                "from": self.result_a.taint_eval,
                "to": self.result_b.taint_eval,
            })
        # Compare chain result
        if self.result_a.chain_result != self.result_b.chain_result:
            changes.append({
                "field": "chain_result",
                "from": self.result_a.chain_result,
                "to": self.result_b.chain_result,
            })
        return changes


class SimulationEngine:
    """Evaluates tool call requests against the full policy stack without enforcement.

    Unlike the production PolicyEvaluator, the simulation engine:
    - Never writes audit logs
    - Captures detailed step-by-step evaluation traces
    - Supports evaluating against specific policy rule sets (versions)
    - Supports diffing two runs against different policy versions
    """

    async def simulate(
        self,
        request: ToolCallRequest,
        policy_rules: list[PolicyRule] | None = None,
        policy_version: str = "current",
    ) -> SimulationResult:
        """Run full simulation of a tool call request.

        Args:
            request: The tool call request to simulate.
            policy_rules: Optional explicit rule set. If None, uses current cached rules.
            policy_version: Label for the policy version being evaluated.

        Returns:
            SimulationResult with full evaluation trace.
        """
        start = time.monotonic()
        steps: list[SimulationStepResult] = []
        decision = Decision.DENY
        matched_rule_id: UUID | None = None
        matched_rule_name = ""
        risk_score = 0.0
        taint_eval: dict[str, Any] = {}
        chain_result: dict[str, Any] = {}
        resolved_roles: list[str] = []
        reason = ""

        try:
            result = await asyncio.wait_for(
                self._simulate_internal(
                    request, policy_rules, steps,
                ),
                timeout=settings.evaluation_timeout_s,
            )
            decision = result["decision"]
            matched_rule_id = result.get("matched_rule_id")
            matched_rule_name = result.get("matched_rule_name", "")
            risk_score = result.get("risk_score", 0.0)
            taint_eval = result.get("taint_eval", {})
            chain_result = result.get("chain_result", {})
            resolved_roles = result.get("resolved_roles", [])
            reason = result.get("reason", "")
        except asyncio.TimeoutError:
            steps.append(SimulationStepResult(
                "timeout", False, "Policy evaluation timed out",
            ))
            decision = Decision.TIMEOUT
            reason = "Simulation timed out"

        elapsed_ms = int((time.monotonic() - start) * 1000)

        return SimulationResult(
            request_id=request.request_id,
            decision=decision,
            matched_rule_id=matched_rule_id,
            matched_rule_name=matched_rule_name,
            risk_score=risk_score,
            taint_eval=taint_eval,
            chain_result=chain_result,
            resolved_roles=resolved_roles,
            steps=steps,
            reason=reason,
            latency_ms=elapsed_ms,
            policy_version=policy_version,
        )

    async def _simulate_internal(
        self,
        request: ToolCallRequest,
        policy_rules: list[PolicyRule] | None,
        steps: list[SimulationStepResult],
    ) -> dict[str, Any]:
        """Core simulation logic with step-by-step tracing."""
        result: dict[str, Any] = {}

        # Step 1: Confused-deputy check
        chain_result: dict[str, Any] = {"checked": False}
        if request.delegation_hops:
            deputy_ok, deputy_reason = await confused_deputy_detector.evaluate(
                session_id=request.session_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                delegation_hops=request.delegation_hops,
            )
            chain_result = {
                "checked": True,
                "passed": deputy_ok,
                "reason": deputy_reason,
                "chain_depth": len(request.delegation_hops),
            }
            steps.append(SimulationStepResult(
                "confused_deputy_check",
                deputy_ok,
                deputy_reason if not deputy_ok else "Delegation chain validated",
            ))

            if not deputy_ok:
                if deputy_reason.startswith("ESCALATE:"):
                    decision = Decision.ESCALATE
                    reason = deputy_reason[len("ESCALATE: "):]
                else:
                    decision = Decision.DENY
                    reason = deputy_reason
                result["decision"] = decision
                result["reason"] = f"Confused-deputy check: {reason}"
                result["chain_result"] = chain_result
                return result
        else:
            # Check implicit delegation
            deputy_ok, deputy_reason = await confused_deputy_detector.evaluate(
                session_id=request.session_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                delegation_hops=[],
            )
            if not deputy_ok and deputy_reason.startswith("ESCALATE:"):
                chain_result = {
                    "checked": True,
                    "passed": False,
                    "reason": deputy_reason,
                    "implicit_delegation": True,
                }
                steps.append(SimulationStepResult(
                    "implicit_delegation_check",
                    False,
                    deputy_reason,
                ))
                result["decision"] = Decision.ESCALATE
                result["reason"] = f"Confused-deputy check: {deputy_reason[len('ESCALATE: '):]}"
                result["chain_result"] = chain_result
                return result
            else:
                steps.append(SimulationStepResult(
                    "implicit_delegation_check", True, "No implicit delegation detected",
                ))

        result["chain_result"] = chain_result

        # Step 2: Role resolution
        agent_roles = await role_resolver.resolve_roles(request.agent_id)
        result["resolved_roles"] = agent_roles
        steps.append(SimulationStepResult(
            "role_resolution",
            True,
            f"Resolved roles: {', '.join(agent_roles)}",
        ))

        # Step 3: Fetch rules
        if policy_rules is not None:
            rules = sorted(policy_rules, key=lambda r: r.priority)
            steps.append(SimulationStepResult(
                "rule_fetch",
                True,
                f"Using provided policy version with {len(rules)} rules",
            ))
        else:
            rules = await rule_cache.get_rules()
            steps.append(SimulationStepResult(
                "rule_fetch",
                True,
                f"Fetched {len(rules)} cached rules",
            ))

        # Step 4: Rule matching
        match_result = rule_matcher.match(
            tool_name=request.tool_name,
            tool_args=request.tool_args,
            agent_roles=agent_roles,
            rules=rules,
        )

        if not match_result.matched:
            steps.append(SimulationStepResult(
                "rule_match", False, match_result.reason,
            ))
            result["decision"] = Decision.DENY
            result["reason"] = match_result.reason
            return result

        matched_rule = match_result.rule
        assert matched_rule is not None
        result["matched_rule_id"] = matched_rule.rule_id
        result["matched_rule_name"] = matched_rule.name
        result["risk_score"] = matched_rule.risk_threshold
        decision = matched_rule.action
        steps.append(SimulationStepResult(
            "rule_match",
            True,
            f"Matched rule: {matched_rule.name} (priority {matched_rule.priority}, action {matched_rule.action.value})",
        ))

        # Step 5: Taint evaluation
        taint_eval: dict[str, Any] = {"checked": False}
        taint_flags: list[str] = []
        if matched_rule.taint_check and request.taint_node_ids:
            taint_eval["checked"] = True
            graph = session_graph_manager.get_session(request.session_id)
            if graph is None:
                taint_eval["graph_found"] = False
                steps.append(SimulationStepResult(
                    "taint_check", True, "No taint graph for session — skipping taint check",
                ))
            else:
                taint_eval["graph_found"] = True
                taint_flags = graph.get_taint_flags(request.taint_node_ids)
                taint_eval["flags"] = taint_flags

                has_quarantined = graph.has_quarantined_nodes(request.taint_node_ids)
                has_untrusted = graph.has_untrusted_nodes(request.taint_node_ids)
                taint_eval["has_quarantined"] = has_quarantined
                taint_eval["has_untrusted"] = has_untrusted

                if has_quarantined:
                    decision = Decision.DENY
                    steps.append(SimulationStepResult(
                        "taint_check", False, "QUARANTINE nodes detected — would DENY",
                    ))
                elif has_untrusted:
                    decision = Decision.ESCALATE
                    steps.append(SimulationStepResult(
                        "taint_check", False, "UNTRUSTED nodes detected — would ESCALATE",
                    ))
                else:
                    steps.append(SimulationStepResult(
                        "taint_check", True, "All taint nodes TRUSTED",
                    ))
        else:
            steps.append(SimulationStepResult(
                "taint_check", True,
                "Taint check not required" if not matched_rule.taint_check else "No taint node IDs provided",
            ))

        result["taint_eval"] = taint_eval
        reason = match_result.reason
        if taint_flags:
            reason += f" | Taint flags: {', '.join(taint_flags)}"

        result["decision"] = decision
        result["reason"] = reason
        return result

    async def compare(
        self,
        request: ToolCallRequest,
        rules_a: list[PolicyRule],
        rules_b: list[PolicyRule],
        version_a: str = "version_a",
        version_b: str = "version_b",
    ) -> SimulationDiff:
        """Run the same request against two policy rule sets and diff results (APEP-154)."""
        result_a, result_b = await asyncio.gather(
            self.simulate(request, policy_rules=rules_a, policy_version=version_a),
            self.simulate(request, policy_rules=rules_b, policy_version=version_b),
        )
        return SimulationDiff(result_a, result_b)


# Module-level singleton
simulation_engine = SimulationEngine()
