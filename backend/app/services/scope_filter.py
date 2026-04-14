"""Sprint 38 -- PlanCheckpointFilter scope matching & PlanScopeFilter allow-check.

APEP-303: Enhanced PlanCheckpointFilter — matches tool calls against
          requires_checkpoint scope patterns using the ScopePatternCompiler.
APEP-304: PlanScopeFilter — checks whether a tool call falls within the
          plan's allowed scope patterns.

Both filters run in the pre-RBAC stage of the PolicyEvaluator pipeline.
"""

from __future__ import annotations

import fnmatch
import logging

from app.models.mission_plan import MissionPlan
from app.models.scope_pattern import CheckpointScopeMatch, ScopeAllowResult
from app.services.scope_pattern_compiler import scope_pattern_compiler

logger = logging.getLogger(__name__)


class PlanCheckpointFilter:
    """Checks whether a tool call matches any requires_checkpoint scope pattern.

    APEP-303: Enhanced checkpoint matching that compiles scope patterns to
    RBAC globs before matching against tool names. Falls back to direct
    fnmatch for non-scope patterns (backward compatible with Sprint 37).

    Usage::

        filt = PlanCheckpointFilter()
        result = filt.check(plan, "file.write.secret.credentials")
        if result.matches:
            # ESCALATE -- requires human checkpoint approval
            ...
    """

    def check(self, plan: MissionPlan, tool_name: str) -> CheckpointScopeMatch:
        """Check if a tool call matches any requires_checkpoint pattern.

        Tries scope pattern compilation first. If the pattern isn't in
        ``verb:namespace:resource`` format, falls back to direct fnmatch
        matching for backward compatibility with Sprint 37.
        """
        for pattern in plan.requires_checkpoint:
            if self._is_scope_pattern(pattern):
                # Compile scope pattern to RBAC globs and match
                result = scope_pattern_compiler.compile(pattern)
                for rbac_glob in result.rbac_patterns:
                    if fnmatch.fnmatch(tool_name, rbac_glob):
                        return CheckpointScopeMatch(
                            matches=True,
                            matched_pattern=pattern,
                            tool_name=tool_name,
                            reason=(
                                f"Tool '{tool_name}' matches checkpoint scope "
                                f"pattern '{pattern}' (via RBAC glob '{rbac_glob}')"
                            ),
                        )
            else:
                # Sprint 37 fallback: direct fnmatch on tool name
                if fnmatch.fnmatch(tool_name, pattern):
                    return CheckpointScopeMatch(
                        matches=True,
                        matched_pattern=pattern,
                        tool_name=tool_name,
                        reason=(
                            f"Tool '{tool_name}' matches checkpoint "
                            f"pattern '{pattern}' (direct glob)"
                        ),
                    )

        return CheckpointScopeMatch(
            matches=False,
            tool_name=tool_name,
            reason=f"Tool '{tool_name}' does not match any checkpoint patterns",
        )

    @staticmethod
    def _is_scope_pattern(pattern: str) -> bool:
        """Check if a pattern uses scope notation (verb:namespace:resource)."""
        parts = pattern.split(":")
        return len(parts) == 3


class PlanScopeFilter:
    """Checks whether a tool call is within the plan's allowed scope.

    APEP-304: If a plan has scope patterns defined, a tool call must match
    at least one scope pattern to be allowed. If no scope patterns are
    defined (empty list), the plan places no scope restrictions.

    Usage::

        filt = PlanScopeFilter()
        result = filt.check(plan, "file.read.public.report")
        if not result.allowed:
            # DENY -- tool call is outside plan scope
            ...
    """

    def check(self, plan: MissionPlan, tool_name: str) -> ScopeAllowResult:
        """Check if a tool call is within the plan's allowed scope.

        An empty scope list means no restrictions (all tools allowed).
        Otherwise, the tool must match at least one scope pattern.
        """
        if not plan.scope:
            return ScopeAllowResult(
                allowed=True,
                tool_name=tool_name,
                reason="Plan has no scope restrictions",
            )

        for pattern in plan.scope:
            if self._is_scope_pattern(pattern):
                # Compile scope pattern to RBAC globs and match
                result = scope_pattern_compiler.compile(pattern)
                for rbac_glob in result.rbac_patterns:
                    if fnmatch.fnmatch(tool_name, rbac_glob):
                        return ScopeAllowResult(
                            allowed=True,
                            matched_scope=pattern,
                            tool_name=tool_name,
                            reason=(
                                f"Tool '{tool_name}' is within scope "
                                f"pattern '{pattern}' (via RBAC glob '{rbac_glob}')"
                            ),
                        )
            else:
                # Fallback: direct fnmatch on tool name
                if fnmatch.fnmatch(tool_name, pattern):
                    return ScopeAllowResult(
                        allowed=True,
                        matched_scope=pattern,
                        tool_name=tool_name,
                        reason=(
                            f"Tool '{tool_name}' is within scope "
                            f"pattern '{pattern}' (direct glob)"
                        ),
                    )

        return ScopeAllowResult(
            allowed=False,
            tool_name=tool_name,
            reason=(
                f"Tool '{tool_name}' is outside the plan's allowed scope. "
                f"Allowed scopes: {', '.join(plan.scope)}"
            ),
        )

    @staticmethod
    def _is_scope_pattern(pattern: str) -> bool:
        """Check if a pattern uses scope notation (verb:namespace:resource)."""
        parts = pattern.split(":")
        return len(parts) == 3


# Module-level singletons
plan_checkpoint_filter = PlanCheckpointFilter()
plan_scope_filter = PlanScopeFilter()
