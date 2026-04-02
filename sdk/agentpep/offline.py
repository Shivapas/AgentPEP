"""Local offline policy evaluation mode for dev/test (APEP-035).

Evaluates policy rules locally without requiring a running AgentPEP server.
Rules are loaded from a YAML/dict configuration and matched using the same
glob/regex first-match semantics as the server-side engine.
"""

from __future__ import annotations

import fnmatch
import logging
import re
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
    ) -> None:
        self.tool_pattern = tool_pattern
        self.action = action
        self.agent_roles = agent_roles or ["*"]
        self.priority = priority

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
    ) -> None:
        self.rules = sorted(rules or [], key=lambda r: r.priority)
        self.default_action = default_action

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
                )
            )
        return cls(rules=parsed, **kwargs)

    def evaluate(
        self,
        *,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        role: str = "*",
        session_id: str = "offline",
    ) -> PolicyDecisionResponse:
        """Evaluate a tool call locally. Returns a PolicyDecisionResponse."""
        for rule in self.rules:
            if rule.matches_tool(tool_name) and rule.matches_role(role):
                return PolicyDecisionResponse(
                    request_id=uuid4(),
                    decision=rule.action,
                    reason=f"Offline match: pattern='{rule.tool_pattern}' action={rule.action.value}",
                )

        return PolicyDecisionResponse(
            request_id=uuid4(),
            decision=self.default_action,
            reason=f"No matching offline rule — default {self.default_action.value}",
        )
