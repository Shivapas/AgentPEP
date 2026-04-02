"""PolicyEvaluator — reads rules from MongoDB and evaluates tool call requests."""

import asyncio
import fnmatch
import hashlib
import json
import re
import time
from uuid import UUID

from app.core.config import settings
from app.db import mongodb as db_module
from app.models.policy import (
    AuditDecision,
    Decision,
    PolicyDecisionResponse,
    PolicyRule,
    ToolCallRequest,
)


class PolicyEvaluator:
    """Evaluates tool call requests against the policy rule stack.

    Rules are fetched from MongoDB, sorted by priority (lower = higher priority),
    and evaluated with first-match semantics. Default is deny-by-default.
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
        """Core evaluation logic: fetch rules, match, decide."""
        db = db_module.get_database()

        # Resolve agent role from agent profile
        agent_role = await self._resolve_agent_role(request.agent_id)

        # Fetch enabled rules sorted by priority (lower = higher priority)
        cursor = db[db_module.POLICY_RULES].find({"enabled": True}).sort("priority", 1)
        rules_docs = await cursor.to_list(length=1000)

        matched_rule: PolicyRule | None = None

        for doc in rules_docs:
            rule = PolicyRule(**doc)

            # Check if rule applies to this agent's role
            if not self._role_matches(agent_role, rule.agent_role):
                continue

            # Check if tool name matches the rule's tool pattern
            if not self._tool_matches(request.tool_name, rule.tool_pattern):
                continue

            # Check argument validators
            if rule.arg_validators and not self._validate_args(request.tool_args, rule):
                continue

            # First match wins
            matched_rule = rule
            break

        elapsed_ms = int((time.monotonic() - start) * 1000)

        if matched_rule is None:
            # Deny-by-default when no rule matches
            return PolicyDecisionResponse(
                request_id=request.request_id,
                decision=Decision.DRY_RUN if request.dry_run else Decision.DENY,
                reason="No matching policy rule — deny by default",
                latency_ms=elapsed_ms,
            )

        decision = matched_rule.action

        # DRY_RUN mode: evaluate fully but never enforce
        if request.dry_run:
            decision = Decision.DRY_RUN

        return PolicyDecisionResponse(
            request_id=request.request_id,
            decision=decision,
            matched_rule_id=matched_rule.rule_id,
            reason=f"Matched rule: {matched_rule.name} (priority {matched_rule.priority})",
            latency_ms=elapsed_ms,
        )

    async def _resolve_agent_role(self, agent_id: str) -> str:
        """Look up the agent's primary role from agent profiles collection."""
        db = db_module.get_database()
        profile = await db[db_module.AGENT_PROFILES].find_one(
            {"agent_id": agent_id, "enabled": True}
        )
        if profile and profile.get("roles"):
            return profile["roles"][0]
        return "default"

    @staticmethod
    def _role_matches(agent_role: str, rule_roles: list[str]) -> bool:
        """Check if the agent's role is in the rule's target roles, or rule targets '*'."""
        if "*" in rule_roles:
            return True
        return agent_role in rule_roles

    @staticmethod
    def _tool_matches(tool_name: str, tool_pattern: str) -> bool:
        """Match tool name against a glob or regex pattern."""
        # Try glob match first
        if fnmatch.fnmatch(tool_name, tool_pattern):
            return True
        # Try regex match
        try:
            if re.fullmatch(tool_pattern, tool_name):
                return True
        except re.error:
            pass
        return False

    @staticmethod
    def _validate_args(tool_args: dict, rule: PolicyRule) -> bool:
        """Validate tool arguments against rule's arg validators.

        Returns True if all validators pass (or no validators apply).
        Returns False if any validator rejects the arguments.
        """
        for validator in rule.arg_validators:
            arg_value = tool_args.get(validator.arg_name)
            if arg_value is None:
                continue

            arg_str = str(arg_value)

            # Blocklist check
            if validator.blocklist and arg_str in validator.blocklist:
                return False

            # Allowlist check
            if validator.allowlist and arg_str not in validator.allowlist:
                return False

            # Regex pattern check
            if validator.regex_pattern:
                try:
                    if not re.fullmatch(validator.regex_pattern, arg_str):
                        return False
                except re.error:
                    return False

        return True

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
