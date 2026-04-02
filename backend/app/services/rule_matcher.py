"""RuleMatcher — glob/regex tool matching, argument validation, first-match evaluation.

APEP-022: Glob + regex matching on tool_name against rules.
APEP-023: Priority-ordered first-match evaluation with deny-by-default.
APEP-024: JSON schema validation on tool arguments.
APEP-025: Regex allowlist/blocklist validators on tool arguments.
"""

import fnmatch
import logging
import re
from typing import Any

import jsonschema

from app.models.policy import ArgValidator, Decision, PolicyRule

logger = logging.getLogger(__name__)


class MatchResult:
    """Result of rule matching against a tool call."""

    __slots__ = ("matched", "rule", "reason")

    def __init__(self, matched: bool, rule: PolicyRule | None = None, reason: str = ""):
        self.matched = matched
        self.rule = rule
        self.reason = reason


class RuleMatcher:
    """Matches tool calls against policy rules with first-match semantics."""

    def match(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        agent_roles: list[str],
        rules: list[PolicyRule],
    ) -> MatchResult:
        """Evaluate rules in priority order; return first match or deny-by-default.

        Rules must already be sorted by priority (ascending = highest priority first).
        """
        for rule in rules:
            if not rule.enabled:
                continue

            # Check role match
            if not self.role_matches(agent_roles, rule.agent_role):
                continue

            # Check tool name match
            if not self.tool_matches(tool_name, rule.tool_pattern):
                continue

            # Check argument validators (blocklist, allowlist, regex, JSON schema)
            arg_valid, arg_reason = self.validate_args(tool_args, rule.arg_validators)
            if not arg_valid:
                logger.debug(
                    "Rule %s matched tool %s but args failed: %s",
                    rule.name, tool_name, arg_reason,
                )
                continue

            return MatchResult(
                matched=True,
                rule=rule,
                reason=f"Matched rule: {rule.name} (priority {rule.priority})",
            )

        return MatchResult(
            matched=False,
            reason="No matching policy rule — deny by default",
        )

    @staticmethod
    def role_matches(agent_roles: list[str], rule_roles: list[str]) -> bool:
        """Check if any of the agent's roles match the rule's target roles.

        Supports wildcard '*' to match all roles. With role hierarchy,
        agent_roles contains all resolved roles (direct + inherited).
        """
        if "*" in rule_roles:
            return True
        return any(role in rule_roles for role in agent_roles)

    @staticmethod
    def tool_matches(tool_name: str, tool_pattern: str) -> bool:
        """Match tool name against a glob or regex pattern.

        Tries glob (fnmatch) first, then falls back to regex (re.fullmatch).
        """
        if fnmatch.fnmatch(tool_name, tool_pattern):
            return True
        try:
            if re.fullmatch(tool_pattern, tool_name):
                return True
        except re.error:
            pass
        return False

    @staticmethod
    def validate_args(
        tool_args: dict[str, Any], validators: list[ArgValidator]
    ) -> tuple[bool, str]:
        """Validate tool arguments against all validators.

        Returns (True, "") if all pass, or (False, reason) on first failure.
        Implements APEP-024 (JSON schema) and APEP-025 (regex/allowlist/blocklist).
        """
        for validator in validators:
            arg_value = tool_args.get(validator.arg_name)

            # --- JSON Schema validation (APEP-024) ---
            if validator.json_schema is not None:
                try:
                    jsonschema.validate(instance=arg_value, schema=validator.json_schema)
                except jsonschema.ValidationError as e:
                    return False, f"Arg '{validator.arg_name}' failed schema: {e.message}"
                except jsonschema.SchemaError as e:
                    logger.warning("Invalid JSON schema in validator: %s", e.message)
                    return False, f"Invalid schema for '{validator.arg_name}'"

            if arg_value is None:
                continue

            arg_str = str(arg_value)

            # --- Blocklist check (APEP-025) ---
            if validator.blocklist and arg_str in validator.blocklist:
                return False, f"Arg '{validator.arg_name}' value in blocklist"

            # --- Allowlist check (APEP-025) ---
            if validator.allowlist and arg_str not in validator.allowlist:
                return False, f"Arg '{validator.arg_name}' value not in allowlist"

            # --- Regex pattern check (APEP-025) ---
            if validator.regex_pattern:
                try:
                    if not re.fullmatch(validator.regex_pattern, arg_str):
                        return (
                            False,
                            f"Arg '{validator.arg_name}' does not match pattern "
                            f"'{validator.regex_pattern}'",
                        )
                except re.error:
                    return False, f"Invalid regex for '{validator.arg_name}'"

        return True, ""


# Module-level singleton
rule_matcher = RuleMatcher()
