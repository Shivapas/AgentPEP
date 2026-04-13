"""Local offline policy evaluation mode for dev/test (APEP-035, APEP-238).

Evaluates policy rules locally without requiring a running AgentPEP server.
Rules are loaded from a YAML/dict configuration and matched using the same
glob/regex first-match semantics as the server-side engine.

Sprint 30 (APEP-238): Enhanced with full policy stack — RBAC hierarchy
resolution, taint tracking, risk scoring, and injection detection for
comprehensive offline evaluation without a server connection.
"""

from __future__ import annotations

import fnmatch
import hashlib
import logging
import re
from collections import defaultdict
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
        risk_threshold: float = 1.0,
        taint_check: bool = False,
        rate_limit: dict[str, Any] | None = None,
        arg_validators: list[dict[str, Any]] | None = None,
    ) -> None:
        self.tool_pattern = tool_pattern
        self.action = action
        self.agent_roles = agent_roles or ["*"]
        self.priority = priority
        self.risk_threshold = risk_threshold
        self.taint_check = taint_check
        self.rate_limit = rate_limit
        self.arg_validators = arg_validators or []

    def matches_tool(self, tool_name: str) -> bool:
        """Check if tool_name matches this rule's pattern (glob or regex)."""
        if self.tool_pattern.startswith("^") or self.tool_pattern.startswith("(?"):
            return bool(re.fullmatch(self.tool_pattern, tool_name))
        return fnmatch.fnmatch(tool_name, self.tool_pattern)

    def matches_role(self, role: str) -> bool:
        """Check if the given role is covered by this rule."""
        return "*" in self.agent_roles or role in self.agent_roles


# ---------------------------------------------------------------------------
# APEP-238: Offline role hierarchy
# ---------------------------------------------------------------------------


class OfflineRoleHierarchy:
    """Resolve effective permissions from a role hierarchy DAG (APEP-238)."""

    def __init__(self, roles: list[dict[str, Any]] | None = None) -> None:
        self._roles: dict[str, dict[str, Any]] = {}
        for r in roles or []:
            self._roles[r["role_id"]] = r

    def get_role(self, role_id: str) -> dict[str, Any] | None:
        return self._roles.get(role_id)

    def resolve_allowed_tools(self, role_id: str, visited: set[str] | None = None) -> set[str]:
        """Collect allowed_tools from this role and all ancestors."""
        if visited is None:
            visited = set()
        if role_id in visited:
            return set()
        visited.add(role_id)

        role = self._roles.get(role_id)
        if not role:
            return set()

        tools = set(role.get("allowed_tools", []))
        for parent in role.get("parent_roles", []):
            tools |= self.resolve_allowed_tools(parent, visited)
        return tools

    def resolve_denied_tools(self, role_id: str, visited: set[str] | None = None) -> set[str]:
        """Collect denied_tools from this role and all ancestors."""
        if visited is None:
            visited = set()
        if role_id in visited:
            return set()
        visited.add(role_id)

        role = self._roles.get(role_id)
        if not role:
            return set()

        tools = set(role.get("denied_tools", []))
        for parent in role.get("parent_roles", []):
            tools |= self.resolve_denied_tools(parent, visited)
        return tools

    def resolve_max_risk_threshold(self, role_id: str, visited: set[str] | None = None) -> float:
        """Most restrictive risk threshold across hierarchy."""
        if visited is None:
            visited = set()
        if role_id in visited:
            return 1.0
        visited.add(role_id)

        role = self._roles.get(role_id)
        if not role:
            return 1.0

        threshold = role.get("max_risk_threshold", 1.0)
        for parent in role.get("parent_roles", []):
            threshold = min(threshold, self.resolve_max_risk_threshold(parent, visited))
        return threshold

    def is_tool_denied(self, role_id: str, tool_name: str) -> bool:
        """Check if a tool is explicitly denied for this role (considering hierarchy)."""
        denied = self.resolve_denied_tools(role_id)
        return any(fnmatch.fnmatch(tool_name, pat) for pat in denied)


# ---------------------------------------------------------------------------
# APEP-238: Offline taint tracker
# ---------------------------------------------------------------------------


class OfflineTaintTracker:
    """Per-session taint tracking for offline evaluation (APEP-238)."""

    def __init__(self) -> None:
        self._session_taint: dict[str, str] = {}  # session_id -> taint_level

    def set_taint(self, session_id: str, level: str) -> None:
        current = self._session_taint.get(session_id, "TRUSTED")
        rank = {"TRUSTED": 0, "UNTRUSTED": 1, "QUARANTINE": 2}
        if rank.get(level, 0) > rank.get(current, 0):
            self._session_taint[session_id] = level

    def get_taint(self, session_id: str) -> str:
        return self._session_taint.get(session_id, "TRUSTED")

    def clear(self, session_id: str) -> None:
        self._session_taint.pop(session_id, None)


# ---------------------------------------------------------------------------
# APEP-238: Offline risk scorer
# ---------------------------------------------------------------------------

_DELETE_VERBS = re.compile(
    r"(delete|remove|destroy|drop|purge|truncate|erase|kill|terminate|revoke)",
    re.IGNORECASE,
)
_WRITE_VERBS = re.compile(
    r"(write|create|update|put|patch|insert|set|modify|upload"
    r"|send|post|execute|run|invoke|deploy|push|publish)",
    re.IGNORECASE,
)
_HIGH_RISK_TOOLS = re.compile(
    r"(rm_rf|drop_table|exec_command|shell|sudo|chmod|chown|format_disk|truncate_table)",
    re.IGNORECASE,
)


class OfflineRiskScorer:
    """Lightweight risk scoring for offline evaluation (APEP-238).

    Scores based on operation type, taint level, and delegation depth.
    """

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        escalation_threshold: float = 0.7,
    ) -> None:
        self.weights = weights or {
            "operation_type": 0.35,
            "taint": 0.30,
            "delegation_depth": 0.20,
            "data_sensitivity": 0.15,
        }
        self.escalation_threshold = escalation_threshold

    def score(
        self,
        tool_name: str,
        taint_level: str = "TRUSTED",
        delegation_depth: int = 0,
        tool_args: dict[str, Any] | None = None,
    ) -> float:
        factors: dict[str, float] = {}

        # Operation type
        if _HIGH_RISK_TOOLS.search(tool_name):
            factors["operation_type"] = 1.0
        elif _DELETE_VERBS.search(tool_name):
            factors["operation_type"] = 0.8
        elif _WRITE_VERBS.search(tool_name):
            factors["operation_type"] = 0.4
        else:
            factors["operation_type"] = 0.1

        # Taint
        taint_scores = {"TRUSTED": 0.0, "UNTRUSTED": 0.6, "QUARANTINE": 1.0}
        factors["taint"] = taint_scores.get(taint_level, 0.0)

        # Delegation depth
        factors["delegation_depth"] = min(delegation_depth / 5.0, 1.0)

        # Data sensitivity (check args for PII-like patterns)
        sensitivity = 0.0
        if tool_args:
            args_str = str(tool_args).lower()
            pii_patterns = ["password", "ssn", "credit_card", "secret", "token", "api_key"]
            for pat in pii_patterns:
                if pat in args_str:
                    sensitivity = max(sensitivity, 0.7)
                    break
        factors["data_sensitivity"] = sensitivity

        # Weighted sum
        total_weight = sum(self.weights.get(k, 0) for k in factors)
        if total_weight == 0:
            return 0.0
        return sum(
            factors[k] * self.weights.get(k, 0) / total_weight
            for k in factors
        )


# ---------------------------------------------------------------------------
# APEP-238: Offline injection detector
# ---------------------------------------------------------------------------

_DEFAULT_INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)ignore\s+all\s+previous\s+instructions", "prompt_override", "CRITICAL"),
    (r"(?i)you\s+are\s+now\s+(a|an)\s+", "role_hijack", "HIGH"),
    (r"(?i)system\s*:\s*", "system_escape", "HIGH"),
    (r"(?i)forget\s+(everything|all|your)\s+", "prompt_override", "HIGH"),
    (r"(?i)do\s+not\s+follow\s+(any|your)\s+", "prompt_override", "HIGH"),
    (r"(?i)disregard\s+(all|any|previous)\s+", "prompt_override", "HIGH"),
    (r"(?i)jailbreak", "jailbreak", "CRITICAL"),
    (r"(?i)DAN\s+mode", "jailbreak", "CRITICAL"),
    (r"%[0-9a-fA-F]{2}", "encoding_bypass", "MEDIUM"),
    (r"\\u[0-9a-fA-F]{4}", "encoding_bypass", "MEDIUM"),
]


class OfflineInjectionDetector:
    """Detect prompt injection patterns in tool arguments (APEP-238)."""

    def __init__(
        self, patterns: list[tuple[str, str, str]] | None = None
    ) -> None:
        raw = patterns or _DEFAULT_INJECTION_PATTERNS
        self._compiled: list[tuple[re.Pattern[str], str, str]] = [
            (re.compile(p), cat, sev)
            for p, cat, sev in raw
        ]

    @classmethod
    def from_signature_dicts(
        cls, signatures: list[dict[str, Any]]
    ) -> OfflineInjectionDetector:
        """Build from a list of injection signature dicts (as in YAML policies)."""
        patterns = [
            (s["pattern"], s.get("category", "unknown"), s.get("severity", "HIGH"))
            for s in signatures
        ]
        return cls(patterns=patterns)

    def check(self, text: str) -> list[dict[str, str]]:
        """Check text for injection patterns. Returns list of matches."""
        matches: list[dict[str, str]] = []
        for pattern, category, severity in self._compiled:
            if pattern.search(text):
                matches.append({
                    "category": category,
                    "severity": severity,
                    "pattern": pattern.pattern,
                })
        return matches

    def check_args(self, tool_args: dict[str, Any]) -> list[dict[str, str]]:
        """Check all tool argument values for injection patterns."""
        text = " ".join(str(v) for v in tool_args.values())
        return self.check(text)


# ---------------------------------------------------------------------------
# APEP-238: Offline rate limiter
# ---------------------------------------------------------------------------


class OfflineRateLimiter:
    """Simple in-memory rate limiter for offline evaluation (APEP-238)."""

    def __init__(self) -> None:
        self._counters: dict[str, int] = defaultdict(int)

    def check(self, key: str, limit: int) -> bool:
        """Check and increment. Returns True if under limit."""
        self._counters[key] += 1
        return self._counters[key] <= limit

    def reset(self) -> None:
        self._counters.clear()


# ---------------------------------------------------------------------------
# Enhanced OfflineEvaluator
# ---------------------------------------------------------------------------


class OfflineEvaluator:
    """Evaluate tool calls against a local rule set without a server.

    Rules are evaluated in priority order (lower = higher priority).
    First match wins. Default is deny-by-default.

    Sprint 30 (APEP-238): Enhanced with full policy stack support:
    - RBAC hierarchy resolution
    - Taint tracking per session
    - Risk scoring (operation type, data sensitivity, taint, delegation)
    - Injection detection
    - Rate limiting

    Usage::

        evaluator = OfflineEvaluator(rules=[
            OfflineRule(tool_pattern="read_*", action=PolicyDecision.ALLOW),
            OfflineRule(tool_pattern="delete_*", action=PolicyDecision.DENY),
        ])
        response = evaluator.evaluate(
            agent_id="test-agent", tool_name="read_file", role="reader"
        )

    Full-stack usage::

        evaluator = OfflineEvaluator.from_policy_bundle(bundle_dict)
        response = evaluator.evaluate(
            agent_id="agent-1", tool_name="delete_db", role="admin",
            tool_args={"table": "users"},
        )
    """

    def __init__(
        self,
        rules: list[OfflineRule] | None = None,
        default_action: PolicyDecision = PolicyDecision.DENY,
        role_hierarchy: OfflineRoleHierarchy | None = None,
        risk_scorer: OfflineRiskScorer | None = None,
        injection_detector: OfflineInjectionDetector | None = None,
        taint_tracker: OfflineTaintTracker | None = None,
        rate_limiter: OfflineRateLimiter | None = None,
    ) -> None:
        self.rules = sorted(rules or [], key=lambda r: r.priority)
        self.default_action = default_action
        self.role_hierarchy = role_hierarchy
        self.risk_scorer = risk_scorer
        self.injection_detector = injection_detector
        self.taint_tracker = taint_tracker or OfflineTaintTracker()
        self.rate_limiter = rate_limiter or OfflineRateLimiter()

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
                    risk_threshold=r.get("risk_threshold", 1.0),
                    taint_check=r.get("taint_check", False),
                    rate_limit=r.get("rate_limit"),
                    arg_validators=r.get("arg_validators"),
                )
            )
        return cls(rules=parsed, **kwargs)

    @classmethod
    def from_policy_bundle(
        cls,
        bundle: dict[str, Any],
        default_action: PolicyDecision = PolicyDecision.DENY,
    ) -> OfflineEvaluator:
        """Create a full-stack OfflineEvaluator from a policy bundle dict (APEP-238).

        The bundle dict can contain: roles, rules, risk_model,
        injection_signatures — matching the YAML policy format.
        """
        # Rules
        rules: list[OfflineRule] = []
        for r in bundle.get("rules", []):
            rules.append(
                OfflineRule(
                    tool_pattern=r["tool_pattern"],
                    action=PolicyDecision(r.get("action", "ALLOW")),
                    agent_roles=r.get("agent_role", r.get("agent_roles", ["*"])),
                    priority=r.get("priority", 100),
                    risk_threshold=r.get("risk_threshold", 1.0),
                    taint_check=r.get("taint_check", False),
                    rate_limit=r.get("rate_limit"),
                    arg_validators=r.get("arg_validators"),
                )
            )

        # Role hierarchy
        role_hierarchy = None
        if "roles" in bundle:
            role_hierarchy = OfflineRoleHierarchy(bundle["roles"])

        # Risk scorer
        risk_scorer = None
        risk_cfg = bundle.get("risk_model")
        if risk_cfg:
            weights = risk_cfg.get("default_weights")
            risk_scorer = OfflineRiskScorer(
                weights=weights,
                escalation_threshold=risk_cfg.get("escalation_threshold", 0.7),
            )
        else:
            risk_scorer = OfflineRiskScorer()

        # Injection detector
        injection_detector = None
        sigs = bundle.get("injection_signatures")
        if sigs:
            injection_detector = OfflineInjectionDetector.from_signature_dicts(sigs)
        else:
            injection_detector = OfflineInjectionDetector()

        return cls(
            rules=rules,
            default_action=default_action,
            role_hierarchy=role_hierarchy,
            risk_scorer=risk_scorer,
            injection_detector=injection_detector,
        )

    @classmethod
    def from_yaml(
        cls,
        yaml_content: str,
        default_action: PolicyDecision = PolicyDecision.DENY,
    ) -> OfflineEvaluator:
        """Create a full-stack OfflineEvaluator from a YAML string (APEP-238)."""
        try:
            import yaml as _yaml
        except ImportError:
            raise ImportError("PyYAML is required for YAML loading: pip install pyyaml")
        bundle = _yaml.safe_load(yaml_content)
        if not isinstance(bundle, dict):
            raise ValueError("YAML root must be a mapping")
        return cls.from_policy_bundle(bundle, default_action=default_action)

    def evaluate(
        self,
        *,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        role: str = "*",
        session_id: str = "offline",
        delegation_chain: list[str] | None = None,
        taint_level: str | None = None,
    ) -> PolicyDecisionResponse:
        """Evaluate a tool call locally with full policy stack (APEP-238).

        Returns a PolicyDecisionResponse with risk_score, taint_flags,
        and detailed reason.
        """
        tool_args = tool_args or {}
        delegation_chain = delegation_chain or []
        reasons: list[str] = []
        risk_score = 0.0
        taint_flags: list[str] = []

        # 1. RBAC check: explicit deny via role hierarchy
        if self.role_hierarchy:
            if self.role_hierarchy.is_tool_denied(role, tool_name):
                return PolicyDecisionResponse(
                    request_id=uuid4(),
                    decision=PolicyDecision.DENY,
                    risk_score=0.0,
                    reason=f"Tool '{tool_name}' denied for role '{role}' by RBAC hierarchy",
                )

        # 2. Injection detection
        if self.injection_detector and tool_args:
            matches = self.injection_detector.check_args(tool_args)
            if matches:
                categories = [m["category"] for m in matches]
                severities = [m["severity"] for m in matches]
                taint_flags.extend(categories)
                self.taint_tracker.set_taint(session_id, "QUARANTINE")
                if "CRITICAL" in severities:
                    return PolicyDecisionResponse(
                        request_id=uuid4(),
                        decision=PolicyDecision.DENY,
                        risk_score=1.0,
                        taint_flags=taint_flags,
                        reason=f"Injection detected: {', '.join(categories)}",
                    )
                reasons.append(f"injection_signals={categories}")

        # 3. Taint check
        effective_taint = taint_level or self.taint_tracker.get_taint(session_id)
        if effective_taint != "TRUSTED":
            taint_flags.append(effective_taint)

        # 4. Risk scoring
        if self.risk_scorer:
            risk_score = self.risk_scorer.score(
                tool_name=tool_name,
                taint_level=effective_taint,
                delegation_depth=len(delegation_chain),
                tool_args=tool_args,
            )

        # 5. Rule matching (first-match semantics)
        matched_rule: OfflineRule | None = None
        for rule in self.rules:
            if rule.matches_tool(tool_name) and rule.matches_role(role):
                matched_rule = rule
                break

        if matched_rule is None:
            return PolicyDecisionResponse(
                request_id=uuid4(),
                decision=self.default_action,
                risk_score=risk_score,
                taint_flags=taint_flags,
                reason=f"No matching offline rule — default {self.default_action.value}",
            )

        # 6. Taint escalation
        if matched_rule.taint_check and effective_taint in ("UNTRUSTED", "QUARANTINE"):
            return PolicyDecisionResponse(
                request_id=uuid4(),
                decision=PolicyDecision.ESCALATE,
                risk_score=risk_score,
                taint_flags=taint_flags,
                reason=(
                    f"Taint escalation: level={effective_taint} "
                    f"on rule '{matched_rule.tool_pattern}'"
                ),
            )

        # 7. Risk threshold check
        if risk_score > matched_rule.risk_threshold:
            escalation_threshold = (
                self.risk_scorer.escalation_threshold
                if self.risk_scorer
                else 0.7
            )
            if risk_score >= escalation_threshold:
                return PolicyDecisionResponse(
                    request_id=uuid4(),
                    decision=PolicyDecision.ESCALATE,
                    risk_score=risk_score,
                    taint_flags=taint_flags,
                    reason=(
                        f"Risk score {risk_score:.2f} exceeds rule threshold "
                        f"{matched_rule.risk_threshold:.2f}"
                    ),
                )

        # 8. Rate limiting
        if matched_rule.rate_limit:
            limit = matched_rule.rate_limit.get("count", 100)
            rate_key = f"{agent_id}:{matched_rule.tool_pattern}"
            if not self.rate_limiter.check(rate_key, limit):
                return PolicyDecisionResponse(
                    request_id=uuid4(),
                    decision=PolicyDecision.DENY,
                    risk_score=risk_score,
                    taint_flags=taint_flags,
                    reason=f"Rate limit exceeded: {limit} calls on '{matched_rule.tool_pattern}'",
                )

        # 9. Arg validation
        if matched_rule.arg_validators and tool_args:
            for validator in matched_rule.arg_validators:
                arg_name = validator.get("arg_name", "")
                val = tool_args.get(arg_name)
                if val is None:
                    continue
                val_str = str(val)

                # Regex check
                if regex := validator.get("regex_pattern"):
                    if not re.fullmatch(regex, val_str):
                        return PolicyDecisionResponse(
                            request_id=uuid4(),
                            decision=PolicyDecision.DENY,
                            risk_score=risk_score,
                            taint_flags=taint_flags,
                            reason=f"Arg validation failed: '{arg_name}' doesn't match regex",
                        )

                # Blocklist
                if blocklist := validator.get("blocklist"):
                    if val_str in blocklist:
                        return PolicyDecisionResponse(
                            request_id=uuid4(),
                            decision=PolicyDecision.DENY,
                            risk_score=risk_score,
                            taint_flags=taint_flags,
                            reason=f"Arg validation failed: '{arg_name}' is in blocklist",
                        )

                # Allowlist
                if allowlist := validator.get("allowlist"):
                    if val_str not in allowlist:
                        return PolicyDecisionResponse(
                            request_id=uuid4(),
                            decision=PolicyDecision.DENY,
                            risk_score=risk_score,
                            taint_flags=taint_flags,
                            reason=f"Arg validation failed: '{arg_name}' not in allowlist",
                        )

        # 10. Role risk threshold
        if self.role_hierarchy:
            role_threshold = self.role_hierarchy.resolve_max_risk_threshold(role)
            if risk_score > role_threshold:
                return PolicyDecisionResponse(
                    request_id=uuid4(),
                    decision=PolicyDecision.ESCALATE,
                    risk_score=risk_score,
                    taint_flags=taint_flags,
                    reason=(
                        f"Risk score {risk_score:.2f} exceeds role '{role}' "
                        f"max threshold {role_threshold:.2f}"
                    ),
                )

        # All checks passed — return rule action
        reason_parts = [
            f"Offline match: pattern='{matched_rule.tool_pattern}' action={matched_rule.action.value}"
        ]
        if reasons:
            reason_parts.extend(reasons)
        if risk_score > 0:
            reason_parts.append(f"risk_score={risk_score:.2f}")

        return PolicyDecisionResponse(
            request_id=uuid4(),
            decision=matched_rule.action,
            risk_score=risk_score,
            taint_flags=taint_flags,
            reason="; ".join(reason_parts),
        )
