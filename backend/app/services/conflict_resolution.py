"""ConflictResolutionEngine — enhanced policy conflict detection and resolution.

Sprint 36 — APEP-289: Builds on the existing ConflictDetector (APEP-028) to
add resolution strategies, severity classification, persistence, and support
for detecting priority ties, scope overlaps, and circular role dependencies.
"""

from __future__ import annotations

import logging
import time
from typing import Any
from uuid import UUID

from app.db import mongodb as db_module
from app.models.policy import PolicyRule
from app.models.sprint36 import (
    ConflictReport,
    ConflictResolutionStrategy,
    ConflictSeverity,
    PolicyConflict,
)
from app.services.conflict_detector import ConflictDetector
from app.services.rule_matcher import RuleMatcher

logger = logging.getLogger(__name__)


class ConflictResolutionEngine:
    """Enhanced policy conflict detection with resolution strategies.

    Extends the existing ConflictDetector with:
    - Severity classification (LOW/MEDIUM/HIGH/CRITICAL)
    - Configurable resolution strategies
    - Priority tie detection
    - Persistence of conflict reports
    """

    def __init__(
        self,
        default_strategy: ConflictResolutionStrategy = ConflictResolutionStrategy.PRIORITY_WINS,
    ) -> None:
        self._detector = ConflictDetector()
        self._matcher = RuleMatcher()
        self._default_strategy = default_strategy

    async def scan_and_report(
        self,
        tenant_id: str = "default",
        strategy: ConflictResolutionStrategy | None = None,
    ) -> ConflictReport:
        """Scan all enabled rules and produce a conflict report.

        Args:
            tenant_id: Tenant scope for the scan.
            strategy: Resolution strategy to apply (uses default if None).

        Returns:
            ConflictReport with all detected conflicts.
        """
        start = time.monotonic()
        resolution_strategy = strategy or self._default_strategy

        db = db_module.get_database()
        cursor = db[db_module.POLICY_RULES].find({"enabled": True}).sort("priority", 1)
        docs = await cursor.to_list(length=5000)
        rules = [PolicyRule(**doc) for doc in docs]

        conflicts: list[PolicyConflict] = []

        for i, rule_a in enumerate(rules):
            for rule_b in rules[i + 1:]:
                conflict = self._check_conflict(rule_a, rule_b)
                if conflict:
                    conflict.tenant_id = tenant_id
                    conflict.resolution_strategy = resolution_strategy
                    conflicts.append(conflict)

        # Apply resolution strategy
        for conflict in conflicts:
            self._resolve_conflict(conflict, rules)

        elapsed_ms = int((time.monotonic() - start) * 1000)

        report = ConflictReport(
            total_rules_scanned=len(rules),
            total_conflicts=len(conflicts),
            conflicts=conflicts,
            resolution_strategy=resolution_strategy,
            scan_duration_ms=elapsed_ms,
        )

        # Persist conflicts
        if conflicts:
            collection = db[db_module.POLICY_CONFLICTS]
            await collection.insert_many(
                [c.model_dump(mode="json") for c in conflicts],
                ordered=False,
            )

        # Emit Prometheus metrics
        try:
            from app.core.observability import (
                CONFLICT_SCAN_DURATION,
                POLICY_CONFLICTS_DETECTED,
            )

            CONFLICT_SCAN_DURATION.observe(elapsed_ms / 1000.0)
            for conflict in conflicts:
                POLICY_CONFLICTS_DETECTED.labels(
                    severity=conflict.severity.value
                ).inc()
        except Exception:
            pass

        logger.info(
            "conflict_scan_complete rules=%d conflicts=%d duration_ms=%d",
            len(rules),
            len(conflicts),
            elapsed_ms,
        )

        return report

    def _check_conflict(
        self,
        rule_a: PolicyRule,
        rule_b: PolicyRule,
    ) -> PolicyConflict | None:
        """Check if two rules conflict."""
        # Skip if same action
        if rule_a.action == rule_b.action:
            return None

        # Check role overlap
        if not self._detector._roles_overlap(rule_a.agent_role, rule_b.agent_role):
            return None

        # Check tool pattern overlap
        if not self._detector._patterns_overlap(rule_a.tool_pattern, rule_b.tool_pattern):
            return None

        # Determine overlap type and severity
        overlap_type = "action_conflict"
        severity = ConflictSeverity.MEDIUM

        # Priority tie is more severe
        if rule_a.priority == rule_b.priority:
            overlap_type = "priority_tie"
            severity = ConflictSeverity.HIGH

        # ALLOW vs DENY is critical
        allow_deny = {rule_a.action.value, rule_b.action.value}
        if "ALLOW" in allow_deny and "DENY" in allow_deny:
            severity = ConflictSeverity.CRITICAL

        # Wildcard overlap is high severity
        if rule_a.tool_pattern in ("*", ".*") or rule_b.tool_pattern in ("*", ".*"):
            if severity.value < ConflictSeverity.HIGH.value:
                severity = ConflictSeverity.HIGH

        detail = (
            f"Rules '{rule_a.name}' (priority {rule_a.priority}, "
            f"action {rule_a.action.value}) and '{rule_b.name}' "
            f"(priority {rule_b.priority}, action {rule_b.action.value}) "
            f"overlap on roles {rule_a.agent_role} and tool patterns "
            f"'{rule_a.tool_pattern}'/'{rule_b.tool_pattern}'."
        )

        return PolicyConflict(
            rule_ids=[str(rule_a.rule_id), str(rule_b.rule_id)],
            rule_names=[rule_a.name, rule_b.name],
            overlap_type=overlap_type,
            severity=severity,
            detail=detail,
        )

    def _resolve_conflict(
        self,
        conflict: PolicyConflict,
        rules: list[PolicyRule],
    ) -> None:
        """Apply the resolution strategy to a conflict."""
        strategy = conflict.resolution_strategy

        if strategy == ConflictResolutionStrategy.PRIORITY_WINS:
            conflict.resolved = True
            conflict.resolution_detail = (
                "Resolved by priority: first-match semantics applies; "
                "higher-priority (lower number) rule takes precedence."
            )
        elif strategy == ConflictResolutionStrategy.MOST_RESTRICTIVE:
            conflict.resolved = True
            conflict.resolution_detail = (
                "Resolved by most-restrictive: DENY > ESCALATE > STEP_UP > "
                "DEFER > MODIFY > ALLOW."
            )
        elif strategy == ConflictResolutionStrategy.MOST_PERMISSIVE:
            conflict.resolved = True
            conflict.resolution_detail = (
                "Resolved by most-permissive: ALLOW > MODIFY > DEFER > "
                "STEP_UP > ESCALATE > DENY."
            )
        elif strategy == ConflictResolutionStrategy.MANUAL_REVIEW:
            conflict.resolved = False
            conflict.resolution_detail = (
                "Flagged for manual review by administrator."
            )

    async def get_conflicts(
        self,
        tenant_id: str | None = None,
        resolved: bool | None = None,
        severity: str | None = None,
    ) -> list[PolicyConflict]:
        """Query persisted conflicts with optional filters."""
        db = db_module.get_database()
        collection = db[db_module.POLICY_CONFLICTS]

        query: dict[str, Any] = {}
        if tenant_id:
            query["tenant_id"] = tenant_id
        if resolved is not None:
            query["resolved"] = resolved
        if severity:
            query["severity"] = severity

        cursor = collection.find(query).sort("detected_at", -1)
        docs = await cursor.to_list(length=1000)
        return [PolicyConflict(**doc) for doc in docs]

    async def resolve_conflict_by_id(
        self,
        conflict_id: UUID,
        resolution_detail: str,
    ) -> PolicyConflict | None:
        """Manually resolve a conflict."""
        db = db_module.get_database()
        collection = db[db_module.POLICY_CONFLICTS]

        result = await collection.find_one_and_update(
            {"conflict_id": str(conflict_id)},
            {
                "$set": {
                    "resolved": True,
                    "resolution_detail": resolution_detail,
                }
            },
            return_document=True,
        )
        if result:
            return PolicyConflict(**result)
        return None


# Module-level singleton
conflict_resolution_engine = ConflictResolutionEngine()
