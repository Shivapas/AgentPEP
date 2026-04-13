"""Policy diff engine — compare two YAML policy sets (APEP-237).

Sprint 30: Compares two YAMLPolicyDocument instances and produces a structured
diff of added, removed, and changed roles, rules, risk config, and taint policy.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from app.models.yaml_policy import YAMLPolicyDocument

logger = logging.getLogger(__name__)


class DiffChangeType(StrEnum):
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    CHANGED = "CHANGED"


@dataclass
class DiffEntry:
    """A single diff entry describing a change between two policy sets."""

    section: str  # e.g., "roles", "rules", "risk", "taint"
    change_type: DiffChangeType
    identifier: str  # e.g., role_id or rule name
    old_value: dict[str, Any] | None = None
    new_value: dict[str, Any] | None = None
    changed_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "section": self.section,
            "change_type": self.change_type.value,
            "identifier": self.identifier,
        }
        if self.old_value is not None:
            result["old_value"] = self.old_value
        if self.new_value is not None:
            result["new_value"] = self.new_value
        if self.changed_fields:
            result["changed_fields"] = self.changed_fields
        return result


@dataclass
class PolicyDiffResult:
    """Result of comparing two YAML policy documents."""

    entries: list[DiffEntry] = field(default_factory=list)

    @property
    def added_count(self) -> int:
        return sum(1 for e in self.entries if e.change_type == DiffChangeType.ADDED)

    @property
    def removed_count(self) -> int:
        return sum(1 for e in self.entries if e.change_type == DiffChangeType.REMOVED)

    @property
    def changed_count(self) -> int:
        return sum(1 for e in self.entries if e.change_type == DiffChangeType.CHANGED)

    @property
    def has_changes(self) -> bool:
        return len(self.entries) > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "has_changes": self.has_changes,
            "summary": {
                "added": self.added_count,
                "removed": self.removed_count,
                "changed": self.changed_count,
                "total": len(self.entries),
            },
            "entries": [e.to_dict() for e in self.entries],
        }


class PolicyDiffEngine:
    """Compare two YAMLPolicyDocument instances and produce a structured diff."""

    def diff(
        self,
        old: YAMLPolicyDocument,
        new: YAMLPolicyDocument,
    ) -> PolicyDiffResult:
        """Compute the diff between two policy documents."""
        result = PolicyDiffResult()

        self._diff_roles(old, new, result)
        self._diff_rules(old, new, result)
        self._diff_risk(old, new, result)
        self._diff_taint(old, new, result)

        return result

    def _diff_roles(
        self,
        old: YAMLPolicyDocument,
        new: YAMLPolicyDocument,
        result: PolicyDiffResult,
    ) -> None:
        """Diff role definitions by role_id."""
        old_roles = {r.role_id: r for r in old.roles}
        new_roles = {r.role_id: r for r in new.roles}

        old_ids = set(old_roles.keys())
        new_ids = set(new_roles.keys())

        # Added roles
        for role_id in sorted(new_ids - old_ids):
            result.entries.append(
                DiffEntry(
                    section="roles",
                    change_type=DiffChangeType.ADDED,
                    identifier=role_id,
                    new_value=new_roles[role_id].model_dump(),
                )
            )

        # Removed roles
        for role_id in sorted(old_ids - new_ids):
            result.entries.append(
                DiffEntry(
                    section="roles",
                    change_type=DiffChangeType.REMOVED,
                    identifier=role_id,
                    old_value=old_roles[role_id].model_dump(),
                )
            )

        # Changed roles
        for role_id in sorted(old_ids & new_ids):
            old_dict = old_roles[role_id].model_dump()
            new_dict = new_roles[role_id].model_dump()
            changed_fields = [
                k for k in old_dict if old_dict[k] != new_dict.get(k)
            ]
            if changed_fields:
                result.entries.append(
                    DiffEntry(
                        section="roles",
                        change_type=DiffChangeType.CHANGED,
                        identifier=role_id,
                        old_value=old_dict,
                        new_value=new_dict,
                        changed_fields=changed_fields,
                    )
                )

    def _diff_rules(
        self,
        old: YAMLPolicyDocument,
        new: YAMLPolicyDocument,
        result: PolicyDiffResult,
    ) -> None:
        """Diff rule definitions by name (since rule_id may be auto-generated)."""
        old_rules = {r.name: r for r in old.rules}
        new_rules = {r.name: r for r in new.rules}

        old_names = set(old_rules.keys())
        new_names = set(new_rules.keys())

        # Added rules
        for name in sorted(new_names - old_names):
            result.entries.append(
                DiffEntry(
                    section="rules",
                    change_type=DiffChangeType.ADDED,
                    identifier=name,
                    new_value=new_rules[name].model_dump(),
                )
            )

        # Removed rules
        for name in sorted(old_names - new_names):
            result.entries.append(
                DiffEntry(
                    section="rules",
                    change_type=DiffChangeType.REMOVED,
                    identifier=name,
                    old_value=old_rules[name].model_dump(),
                )
            )

        # Changed rules
        for name in sorted(old_names & new_names):
            old_dict = old_rules[name].model_dump()
            new_dict = new_rules[name].model_dump()
            # Ignore rule_id differences (may be auto-generated)
            old_cmp = {k: v for k, v in old_dict.items() if k != "rule_id"}
            new_cmp = {k: v for k, v in new_dict.items() if k != "rule_id"}
            changed_fields = [
                k for k in old_cmp if old_cmp[k] != new_cmp.get(k)
            ]
            if changed_fields:
                result.entries.append(
                    DiffEntry(
                        section="rules",
                        change_type=DiffChangeType.CHANGED,
                        identifier=name,
                        old_value=old_dict,
                        new_value=new_dict,
                        changed_fields=changed_fields,
                    )
                )

    def _diff_risk(
        self,
        old: YAMLPolicyDocument,
        new: YAMLPolicyDocument,
        result: PolicyDiffResult,
    ) -> None:
        """Diff risk configuration."""
        old_dict = old.risk.model_dump()
        new_dict = new.risk.model_dump()

        if old_dict != new_dict:
            changed_fields = [k for k in old_dict if old_dict[k] != new_dict.get(k)]
            result.entries.append(
                DiffEntry(
                    section="risk",
                    change_type=DiffChangeType.CHANGED,
                    identifier="risk_config",
                    old_value=old_dict,
                    new_value=new_dict,
                    changed_fields=changed_fields,
                )
            )

    def _diff_taint(
        self,
        old: YAMLPolicyDocument,
        new: YAMLPolicyDocument,
        result: PolicyDiffResult,
    ) -> None:
        """Diff taint policy configuration."""
        old_dict = old.taint.model_dump()
        new_dict = new.taint.model_dump()

        if old_dict != new_dict:
            changed_fields = [k for k in old_dict if old_dict[k] != new_dict.get(k)]
            result.entries.append(
                DiffEntry(
                    section="taint",
                    change_type=DiffChangeType.CHANGED,
                    identifier="taint_policy",
                    old_value=old_dict,
                    new_value=new_dict,
                    changed_fields=changed_fields,
                )
            )


# Module-level singleton
policy_diff_engine = PolicyDiffEngine()
