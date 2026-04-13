"""Local offline policy evaluation mode for dev/test (APEP-035, APEP-238).

Evaluates policy rules locally without requiring a running AgentPEP server.
Rules are loaded from a YAML/dict configuration and matched using the same
glob/regex first-match semantics as the server-side engine.

Sprint 30 (APEP-238): Enhanced with full policy stack support — bundles
RBAC roles, taint checking, risk scoring, and injection detection for
complete local evaluation.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

from agentpep.models import PolicyDecision, PolicyDecisionResponse

logger = logging.getLogger(__name__)


class OfflineRule:
    """A single offline policy rule."""

    def __init__(
        self,
        tool_pattern: str,
        action: PolicyDecision = PolicyDecision.ALLOW,
        agent_roles: list[str] | None = None,
        priority: int = 100,
        taint_check: bool = False,
        risk_threshold: float = 1.0,
    ) -> None:
        self.tool_pattern = tool_pattern
        self.action = action
        self.agent_roles = agent_roles or ["*"]
        self.priority = priority
        self.taint_check = taint_check
        self.risk_threshold = risk_threshold

    def matches_tool(self, tool_name: str) -> bool:
        """Check if tool_name matches this rule's pattern (glob or regex)."""
        if self.tool_pattern.startswith("^") or self.tool_pattern.startswith("(?"):
            return bool(re.fullmatch(self.tool_pattern, tool_name))
        return fnmatch.fnmatch(tool_name, self.tool_pattern)

    def matches_role(self, role: str) -> bool:
        """Check if the given role is covered by this rule."""
        return "*" in self.agent_roles or role in self.agent_roles


class OfflineEvaluator:
    """Evaluate tool calls against a local rule set without a server.

    Rules are evaluated in priority order (lower = higher priority).
    First match wins. Default is deny-by-default.

    Usage::

        evaluator = OfflineEvaluator(rules=[
            OfflineRule(tool_pattern="read_*", action=PolicyDecision.ALLOW),
            OfflineRule(tool_pattern="delete_*", action=PolicyDecision.DENY),
        ])
        response = evaluator.evaluate(
            agent_id="test-agent", tool_name="read_file", role="reader"
        )
    """

    def __init__(
        self,
        rules: list[OfflineRule] | None = None,
        default_action: PolicyDecision = PolicyDecision.DENY,
        roles: dict[str, dict[str, Any]] | None = None,
        risk_config: dict[str, Any] | None = None,
        taint_policy: dict[str, Any] | None = None,
        injection_patterns: list[re.Pattern[str]] | None = None,
    ) -> None:
        self.rules = sorted(rules or [], key=lambda r: r.priority)
        self.default_action = default_action
        # Sprint 30 (APEP-238): Full policy stack
        self._roles = roles or {}
        self._risk_config = risk_config or {}
        self._taint_policy = taint_policy or {}
        self._injection_patterns = injection_patterns or []
        self._escalation_threshold = (
            self._risk_config.get("escalation_threshold", 0.7)
            if self._risk_config else 0.7
        )

    @classmethod
    def from_dict_list(cls, rules: list[dict[str, Any]], **kwargs: Any) -> OfflineEvaluator:
        """Create an OfflineEvaluator from a list of rule dicts.

        Each dict should have keys: ``tool_pattern``, ``action`` (str),
        optionally ``agent_roles`` (list[str]) and ``priority`` (int).
        """
        parsed = []
        for r in rules:
            parsed.append(
                OfflineRule(
                    tool_pattern=r["tool_pattern"],
                    action=PolicyDecision(r.get("action", "ALLOW")),
                    agent_roles=r.get("agent_roles"),
                    priority=r.get("priority", 100),
                    taint_check=r.get("taint_check", False),
                    risk_threshold=r.get("risk_threshold", 1.0),
                )
            )
        return cls(rules=parsed, **kwargs)

    @classmethod
    def from_bundle(cls, bundle: Any) -> OfflineEvaluator:
        """Create an OfflineEvaluator from a PolicyBundle (APEP-238).

        Loads the full policy stack: RBAC roles, rules, risk config,
        taint policy, and injection patterns.

        Args:
            bundle: A PolicyBundle instance from agentpep.policy_bundle.
        """
        rules = []
        for r in bundle.rules:
            if not r.enabled:
                continue
            rules.append(
                OfflineRule(
                    tool_pattern=r.tool_pattern,
                    action=PolicyDecision(r.action),
                    agent_roles=r.agent_roles if r.agent_roles else ["*"],
                    priority=r.priority,
                    taint_check=r.taint_check,
                    risk_threshold=r.risk_threshold,
                )
            )

        # Build roles lookup
        roles_lookup: dict[str, dict[str, Any]] = {}
        for role in bundle.roles:
            if not role.enabled:
                continue
            roles_lookup[role.role_id] = {
                "parent_roles": role.parent_roles,
                "allowed_tools": role.allowed_tools,
                "denied_tools": role.denied_tools,
                "max_risk_threshold": role.max_risk_threshold,
            }

        # Compile injection patterns
        injection_patterns = [p.regex for p in bundle.injection_patterns]

        return cls(
            rules=rules,
            roles=roles_lookup,
            risk_config={
                "escalation_threshold": bundle.risk_config.escalation_threshold,
                "weights": bundle.risk_config.weights,
            },
            taint_policy={
                "max_hop_depth": bundle.taint_policy.max_hop_depth,
                "quarantine_on_injection": bundle.taint_policy.quarantine_on_injection,
            },
            injection_patterns=injection_patterns,
        )

    @classmethod
    def from_yaml(cls, content: str | bytes) -> OfflineEvaluator:
        """Create an OfflineEvaluator from a YAML policy document (APEP-238)."""
        from agentpep.policy_bundle import PolicyBundle
        bundle = PolicyBundle.from_yaml(content)
        return cls.from_bundle(bundle)

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> OfflineEvaluator:
        """Create an OfflineEvaluator from a YAML file (APEP-238)."""
        from agentpep.policy_bundle import PolicyBundle
        bundle = PolicyBundle.from_yaml_file(path)
        return cls.from_bundle(bundle)

    @classmethod
    def from_yaml_directory(cls, directory: str | Path) -> OfflineEvaluator:
        """Create an OfflineEvaluator from a policy-as-code directory (APEP-238)."""
        from agentpep.policy_bundle import PolicyBundle
        bundle = PolicyBundle.from_yaml_directory(directory)
        return cls.from_bundle(bundle)

    def resolve_roles(self, role: str) -> list[str]:
        """Resolve a role and all its inherited parent roles (APEP-238)."""
        if not self._roles:
            return [role]

        resolved: list[str] = []
        visited: set[str] = set()
        stack = [role]

        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            resolved.append(current)
            role_def = self._roles.get(current, {})
            for parent in role_def.get("parent_roles", []):
                if parent not in visited:
                    stack.append(parent)

        return resolved

    def check_role_tool_access(self, role: str, tool_name: str) -> bool | None:
        """Check if a role explicitly allows or denies a tool (APEP-238).

        Returns True if allowed, False if denied, None if no explicit rule.
        """
        resolved = self.resolve_roles(role)
        for r in resolved:
            role_def = self._roles.get(r, {})
            # Check denied first
            for pattern in role_def.get("denied_tools", []):
                if fnmatch.fnmatch(tool_name, pattern):
                    return False
            # Then allowed
            for pattern in role_def.get("allowed_tools", []):
                if fnmatch.fnmatch(tool_name, pattern):
                    return True
        return None

    def check_injection(self, text: str) -> str | None:
        """Check if text matches any injection pattern (APEP-238).

        Returns the matched pattern string if found, None otherwise.
        """
        for pattern in self._injection_patterns:
            if pattern.search(text):
                return pattern.pattern
        return None

    def compute_risk_score(
        self,
        *,
        tool_name: str,
        taint_flags: list[str] | None = None,
        delegation_depth: int = 0,
    ) -> float:
        """Compute a simplified risk score for offline evaluation (APEP-238)."""
        risk = 0.0
        weights = self._risk_config.get("weights", {}) if self._risk_config else {}

        # Taint contribution
        taint_weight = weights.get("taint", 0.20)
        if taint_flags:
            taint_scores = {"QUARANTINE": 0.9, "UNTRUSTED": 0.5, "TRUSTED": 0.0}
            max_taint = max(taint_scores.get(f, 0.0) for f in taint_flags)
            risk += max_taint * taint_weight

        # Delegation depth contribution
        depth_weight = weights.get("delegation_depth", 0.20)
        if delegation_depth > 0:
            risk += min(delegation_depth * 0.1, 0.5) * depth_weight

        # Operation type (simple heuristic)
        op_weight = weights.get("operation_type", 0.25)
        tool_lower = tool_name.lower()
        if any(v in tool_lower for v in ("delete", "drop", "destroy", "remove")):
            risk += 0.8 * op_weight
        elif any(v in tool_lower for v in ("write", "create", "update", "execute", "run")):
            risk += 0.5 * op_weight
        elif any(v in tool_lower for v in ("read", "get", "list", "fetch")):
            risk += 0.1 * op_weight

        return min(risk, 1.0)

    def evaluate(
        self,
        *,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        role: str = "*",
        session_id: str = "offline",
        taint_flags: list[str] | None = None,
        delegation_chain: list[str] | None = None,
    ) -> PolicyDecisionResponse:
        """Evaluate a tool call locally. Returns a PolicyDecisionResponse.

        Sprint 30 (APEP-238): Enhanced with RBAC checking, taint evaluation,
        risk scoring, and injection detection.
        """
        # APEP-238: Check RBAC role-based tool access
        if self._roles and role != "*":
            access = self.check_role_tool_access(role, tool_name)
            if access is False:
                return PolicyDecisionResponse(
                    request_id=uuid4(),
                    decision=PolicyDecision.DENY,
                    reason=f"Role '{role}' denied access to tool '{tool_name}'",
                )

        # APEP-238: Check injection patterns in tool args
        if self._injection_patterns and tool_args:
            for arg_val in tool_args.values():
                if isinstance(arg_val, str):
                    matched = self.check_injection(arg_val)
                    if matched:
                        return PolicyDecisionResponse(
                            request_id=uuid4(),
                            decision=PolicyDecision.DENY,
                            reason=f"Injection pattern detected in tool args: {matched}",
                        )

        # Rule matching (first-match semantics)
        for rule in self.rules:
            if rule.matches_tool(tool_name) and rule.matches_role(role):
                decision = PolicyDecision(rule.action)

                # APEP-238: Risk scoring
                risk_score = self.compute_risk_score(
                    tool_name=tool_name,
                    taint_flags=taint_flags,
                    delegation_depth=len(delegation_chain) if delegation_chain else 0,
                )

                # Escalate if risk exceeds threshold
                if (
                    risk_score > self._escalation_threshold
                    and decision == PolicyDecision.ALLOW
                ):
                    decision = PolicyDecision.ESCALATE

                # APEP-238: Check per-rule risk threshold
                if (
                    risk_score > rule.risk_threshold
                    and decision == PolicyDecision.ALLOW
                ):
                    decision = PolicyDecision.ESCALATE

                return PolicyDecisionResponse(
                    request_id=uuid4(),
                    decision=decision,
                    risk_score=risk_score,
                    taint_flags=taint_flags or [],
                    reason=f"Offline match: pattern='{rule.tool_pattern}' action={decision.value}",
                )

        return PolicyDecisionResponse(
            request_id=uuid4(),
            decision=self.default_action,
            reason=f"No matching offline rule — default {self.default_action.value}",
        )
