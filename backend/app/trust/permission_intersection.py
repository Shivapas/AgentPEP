"""Effective permission calculator — intersection of root and agent permissions.

Implements the invariant defined in PRD v2.1 FEATURE-04:

    effective_permissions = root_permissions ∩ requested_permissions

A subagent can never hold permissions that the root principal does not have.
Any requested permissions beyond the root set constitute a privilege escalation
attempt and trigger a TRUST_VIOLATION event (see trust/events.py).

Sprint S-E06 (E06-T03)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PermissionIntersectionResult:
    """Outcome of a single permission intersection check.

    Attributes:
        effective:           Permissions the agent may actually exercise.
                             Always a subset of root_permissions.
        escalated:           Permissions the agent requested that are NOT in
                             root_permissions.  Non-empty → escalation detected.
        escalation_detected: Convenience flag; True iff escalated is non-empty.
    """

    effective: frozenset[str]
    escalated: frozenset[str]
    escalation_detected: bool


# ---------------------------------------------------------------------------
# Calculator
# ---------------------------------------------------------------------------


class EffectivePermissionCalculator:
    """Computes effective permissions and detects privilege escalation attempts.

    This is a pure function wrapped in a class for consistency with the rest of
    the trust module.  It holds no state.

    Usage::

        result = permission_calculator.compute(
            root_permissions={"read_files", "write_files"},
            requested_permissions={"read_files", "write_files", "execute_shell"},
        )
        if result.escalation_detected:
            emit_trust_violation_event(...)
        # effective = {"read_files", "write_files"}
        # escalated = {"execute_shell"}
    """

    def compute(
        self,
        root_permissions: Iterable[str],
        requested_permissions: Iterable[str],
    ) -> PermissionIntersectionResult:
        """Compute the intersection of root and requested permissions.

        Args:
            root_permissions:      Permissions held by the root principal.
            requested_permissions: Permissions the delegated agent claims.

        Returns:
            PermissionIntersectionResult with effective set and escalation details.
        """
        root = frozenset(root_permissions)
        requested = frozenset(requested_permissions)

        effective = root & requested
        escalated = requested - root

        return PermissionIntersectionResult(
            effective=effective,
            escalated=escalated,
            escalation_detected=bool(escalated),
        )

    def check_escalation(
        self,
        root_permissions: Iterable[str],
        requested_permissions: Iterable[str],
    ) -> bool:
        """Return True if requested permissions exceed root permissions.

        Convenience method for call sites that only need the boolean decision.
        """
        return bool(frozenset(requested_permissions) - frozenset(root_permissions))

    def effective_only(
        self,
        root_permissions: Iterable[str],
        requested_permissions: Iterable[str],
    ) -> frozenset[str]:
        """Return only the effective permission set (intersection).

        Convenience method for call sites that only need the effective set and
        do not need escalation details.
        """
        return frozenset(root_permissions) & frozenset(requested_permissions)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

permission_calculator = EffectivePermissionCalculator()
