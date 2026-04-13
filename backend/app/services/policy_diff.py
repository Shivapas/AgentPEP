"""Policy diff engine — Sprint 30 (APEP-237).

Compares two PolicyBundle instances and produces a structured diff
of added, removed, and changed items across roles, rules, risk config,
taint policies, and data classifications.

Usage::

    differ = PolicyDiffEngine()
    diff = differ.diff(old_bundle, new_bundle)
    print(diff.summary())
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from app.services.yaml_policy_loader import PolicyBundle


class ChangeType(StrEnum):
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    CHANGED = "CHANGED"


@dataclass(frozen=True)
class DiffEntry:
    """A single change between two policy sets."""

    category: str  # e.g. "role", "rule", "risk_model", "sanitisation_gate", etc.
    change_type: ChangeType
    key: str  # identifier (role_id, rule name, gate name, etc.)
    old_value: dict[str, Any] | None = None
    new_value: dict[str, Any] | None = None
    changed_fields: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "category": self.category,
            "change_type": self.change_type.value,
            "key": self.key,
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
    """Structured diff between two policy bundles."""

    entries: list[DiffEntry] = field(default_factory=list)

    @property
    def added(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.change_type == ChangeType.ADDED]

    @property
    def removed(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.change_type == ChangeType.REMOVED]

    @property
    def changed(self) -> list[DiffEntry]:
        return [e for e in self.entries if e.change_type == ChangeType.CHANGED]

    @property
    def has_changes(self) -> bool:
        return len(self.entries) > 0

    @property
    def total_changes(self) -> int:
        return len(self.entries)

    def summary(self) -> str:
        if not self.entries:
            return "No changes detected."
        parts = []
        if self.added:
            parts.append(f"{len(self.added)} added")
        if self.removed:
            parts.append(f"{len(self.removed)} removed")
        if self.changed:
            parts.append(f"{len(self.changed)} changed")
        return f"Policy diff: {', '.join(parts)} ({self.total_changes} total)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_changes": self.total_changes,
            "added": len(self.added),
            "removed": len(self.removed),
            "changed": len(self.changed),
            "summary": self.summary(),
            "entries": [e.to_dict() for e in self.entries],
        }


# ---------------------------------------------------------------------------
# Diff helpers
# ---------------------------------------------------------------------------


def _model_to_comparable(obj: Any) -> dict[str, Any]:
    """Convert a Pydantic model or dataclass to a plain dict for comparison."""
    if hasattr(obj, "model_dump"):
        d = obj.model_dump()
        # Remove timestamps and auto-generated IDs for comparison
        for key in ("created_at", "updated_at", "rule_id", "gate_id"):
            d.pop(key, None)
        return d
    if hasattr(obj, "__dataclass_fields__"):
        import dataclasses

        return dataclasses.asdict(obj)
    return dict(obj) if isinstance(obj, dict) else {"value": obj}


def _diff_keyed_items(
    old_items: list[Any],
    new_items: list[Any],
    key_attr: str,
    category: str,
) -> list[DiffEntry]:
    """Diff two lists of keyed items (roles, rules, gates, etc.)."""
    old_map: dict[str, Any] = {}
    for item in old_items:
        k = getattr(item, key_attr) if hasattr(item, key_attr) else item.get(key_attr, "")
        old_map[str(k)] = item

    new_map: dict[str, Any] = {}
    for item in new_items:
        k = getattr(item, key_attr) if hasattr(item, key_attr) else item.get(key_attr, "")
        new_map[str(k)] = item

    entries: list[DiffEntry] = []

    # Removed
    for key in old_map:
        if key not in new_map:
            entries.append(
                DiffEntry(
                    category=category,
                    change_type=ChangeType.REMOVED,
                    key=key,
                    old_value=_model_to_comparable(old_map[key]),
                )
            )

    # Added
    for key in new_map:
        if key not in old_map:
            entries.append(
                DiffEntry(
                    category=category,
                    change_type=ChangeType.ADDED,
                    key=key,
                    new_value=_model_to_comparable(new_map[key]),
                )
            )

    # Changed
    for key in old_map:
        if key in new_map:
            old_dict = _model_to_comparable(old_map[key])
            new_dict = _model_to_comparable(new_map[key])
            changed_fields = [
                f for f in set(old_dict) | set(new_dict)
                if old_dict.get(f) != new_dict.get(f)
            ]
            if changed_fields:
                entries.append(
                    DiffEntry(
                        category=category,
                        change_type=ChangeType.CHANGED,
                        key=key,
                        old_value=old_dict,
                        new_value=new_dict,
                        changed_fields=sorted(changed_fields),
                    )
                )

    return entries


# ---------------------------------------------------------------------------
# Policy Diff Engine
# ---------------------------------------------------------------------------


class PolicyDiffEngine:
    """Compare two PolicyBundle instances and produce a structured diff (APEP-237)."""

    def diff(self, old: PolicyBundle, new: PolicyBundle) -> PolicyDiffResult:
        """Compute the full diff between two policy bundles."""
        entries: list[DiffEntry] = []

        # Roles
        entries.extend(
            _diff_keyed_items(old.roles, new.roles, "role_id", "role")
        )

        # Rules (keyed by name since rule_id may be auto-generated)
        entries.extend(
            _diff_keyed_items(old.rules, new.rules, "name", "rule")
        )

        # Sanitisation gates
        entries.extend(
            _diff_keyed_items(
                old.sanitisation_gates, new.sanitisation_gates, "name", "sanitisation_gate"
            )
        )

        # Injection signatures
        entries.extend(
            _diff_keyed_items(
                old.injection_signatures,
                new.injection_signatures,
                "signature_id",
                "injection_signature",
            )
        )

        # Classification levels
        entries.extend(
            _diff_keyed_items(
                old.classification_levels,
                new.classification_levels,
                "name",
                "classification_level",
            )
        )

        # Tool classifications
        entries.extend(
            _diff_keyed_items(
                old.tool_classifications,
                new.tool_classifications,
                "tool_pattern",
                "tool_classification",
            )
        )

        # Risk model (singular — compare as a whole)
        entries.extend(self._diff_risk_model(old.risk_model, new.risk_model))

        return PolicyDiffResult(entries=entries)

    def _diff_risk_model(
        self,
        old: RiskModelConfig | None,
        new: RiskModelConfig | None,
    ) -> list[DiffEntry]:
        """Diff the risk model config."""
        if old is None and new is None:
            return []

        if old is None and new is not None:
            return [
                DiffEntry(
                    category="risk_model",
                    change_type=ChangeType.ADDED,
                    key=new.model_id,
                    new_value=_model_to_comparable(new),
                )
            ]

        if old is not None and new is None:
            return [
                DiffEntry(
                    category="risk_model",
                    change_type=ChangeType.REMOVED,
                    key=old.model_id,
                    old_value=_model_to_comparable(old),
                )
            ]

        # Both exist — compare
        assert old is not None and new is not None
        old_dict = _model_to_comparable(old)
        new_dict = _model_to_comparable(new)
        changed_fields = [
            f for f in set(old_dict) | set(new_dict)
            if old_dict.get(f) != new_dict.get(f)
        ]
        if changed_fields:
            return [
                DiffEntry(
                    category="risk_model",
                    change_type=ChangeType.CHANGED,
                    key=old.model_id,
                    old_value=old_dict,
                    new_value=new_dict,
                    changed_fields=sorted(changed_fields),
                )
            ]
        return []
