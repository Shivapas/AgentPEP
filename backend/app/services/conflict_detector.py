"""ConflictDetector — detects overlapping policy rules with conflicting actions.

APEP-028: Identifies rules that match the same tool patterns and roles but
prescribe different actions, logging warnings to help administrators
resolve ambiguities in their policy stacks.
"""

import logging

from app.db import mongodb as db_module
from app.models.policy import PolicyRule
from app.services.rule_matcher import RuleMatcher

logger = logging.getLogger(__name__)


class RuleConflict:
    """Describes a detected conflict between two policy rules."""

    __slots__ = ("rule_a", "rule_b", "overlap_type", "detail")

    def __init__(self, rule_a: PolicyRule, rule_b: PolicyRule, overlap_type: str, detail: str):
        self.rule_a = rule_a
        self.rule_b = rule_b
        self.overlap_type = overlap_type
        self.detail = detail

    def __repr__(self) -> str:
        return (
            f"RuleConflict('{self.rule_a.name}' vs '{self.rule_b.name}' "
            f"— {self.overlap_type}: {self.detail})"
        )


class ConflictDetector:
    """Detects and logs conflicts between policy rules."""

    def __init__(self) -> None:
        self._matcher = RuleMatcher()

    async def detect_conflicts(self) -> list[RuleConflict]:
        """Scan all enabled rules and detect overlapping conflicts.

        Two rules conflict when they have overlapping roles AND overlapping
        tool patterns but prescribe different actions.
        """
        db = db_module.get_database()
        cursor = db[db_module.POLICY_RULES].find({"enabled": True}).sort("priority", 1)
        docs = await cursor.to_list(length=1000)
        rules = [PolicyRule(**doc) for doc in docs]

        conflicts: list[RuleConflict] = []

        for i, rule_a in enumerate(rules):
            for rule_b in rules[i + 1 :]:
                # Skip if same action — no conflict
                if rule_a.action == rule_b.action:
                    continue

                # Check role overlap
                if not self._roles_overlap(rule_a.agent_role, rule_b.agent_role):
                    continue

                # Check tool pattern overlap
                if not self._patterns_overlap(rule_a.tool_pattern, rule_b.tool_pattern):
                    continue

                conflict = RuleConflict(
                    rule_a=rule_a,
                    rule_b=rule_b,
                    overlap_type="action_conflict",
                    detail=(
                        f"Rules '{rule_a.name}' (priority {rule_a.priority}, "
                        f"action {rule_a.action.value}) and '{rule_b.name}' "
                        f"(priority {rule_b.priority}, action {rule_b.action.value}) "
                        f"overlap on roles and tool patterns. First-match will use "
                        f"'{rule_a.name}' due to higher priority."
                    ),
                )
                conflicts.append(conflict)
                logger.warning("Policy rule conflict detected: %s", conflict.detail)

        if conflicts:
            logger.warning("Total policy rule conflicts detected: %d", len(conflicts))
        else:
            logger.info("No policy rule conflicts detected")

        return conflicts

    @staticmethod
    def _roles_overlap(roles_a: list[str], roles_b: list[str]) -> bool:
        """Check if two role lists have any overlap (including wildcard)."""
        if "*" in roles_a or "*" in roles_b:
            return True
        return bool(set(roles_a) & set(roles_b))

    @staticmethod
    def _patterns_overlap(pattern_a: str, pattern_b: str) -> bool:
        """Heuristic check for tool pattern overlap.

        Exact matches, one pattern matching the other, or both being wildcards
        indicate overlap. This is a conservative heuristic — it may report
        false positives but not false negatives for common patterns.
        """
        if pattern_a == pattern_b:
            return True

        # Check if one pattern matches the other literally
        matcher = RuleMatcher()
        if matcher.tool_matches(pattern_a, pattern_b):
            return True
        if matcher.tool_matches(pattern_b, pattern_a):
            return True

        # Both are wildcards covering everything
        if pattern_a in ("*", ".*") and pattern_b in ("*", ".*"):
            return True

        # Check for common glob prefix overlap (e.g., "file_*" and "file_read*")
        # Strip trailing wildcards and check prefix containment
        prefix_a = pattern_a.rstrip("*").rstrip(".")
        prefix_b = pattern_b.rstrip("*").rstrip(".")
        if prefix_a and prefix_b:
            if prefix_a.startswith(prefix_b) or prefix_b.startswith(prefix_a):
                return True

        return False


# Module-level singleton
conflict_detector = ConflictDetector()
