"""Policy migration utility — upgrade YAML policy schema versions.

Sprint 34 — APEP-271: ``agentpep policy migrate`` — upgrade policy YAML
between schema versions with backward compatibility.

Supports migrations:
  - 1.0 -> 2.0: Adds data_classification defaults, DEFER/MODIFY/STEP_UP
                 action types, context_authority section, and trust_degradation
                 configuration.

Migration is additive: existing fields are preserved, new fields are added
with sensible defaults.
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Migration result
# ---------------------------------------------------------------------------


@dataclass
class MigrationResult:
    """Result of a policy migration."""

    source_version: str
    target_version: str
    yaml_output: str
    migrated_data: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Migration steps
# ---------------------------------------------------------------------------


def _migrate_1_0_to_2_0(data: dict[str, Any]) -> tuple[dict[str, Any], list[str], list[str]]:
    """Migrate schema v1.0 to v2.0.

    Changes:
    - schema_version: "1.0" -> "2.0"
    - rules: action field now supports DEFER, MODIFY, STEP_UP
    - rules: add optional data_classification_required field
    - roles: add max_delegation_depth field (default 5)
    - Add context_authority section
    - Add trust_degradation section
    - taint: add trust_ceiling_enabled field
    """
    migrated = copy.deepcopy(data)
    warnings: list[str] = []
    changes: list[str] = []

    # Update schema version
    migrated["schema_version"] = "2.0"
    changes.append("Updated schema_version from 1.0 to 2.0")

    # Migrate roles: add max_delegation_depth
    for role in migrated.get("roles", []):
        if "max_delegation_depth" not in role:
            role["max_delegation_depth"] = 5
            changes.append(
                f"Added max_delegation_depth=5 to role '{role.get('role_id', '?')}'"
            )

    # Migrate rules: validate action types and add new fields
    valid_actions_v2 = {"ALLOW", "DENY", "ESCALATE", "DEFER", "MODIFY", "STEP_UP"}
    for rule in migrated.get("rules", []):
        action = rule.get("action", "DENY")
        if action not in valid_actions_v2:
            warnings.append(
                f"Rule '{rule.get('name', '?')}' has unknown action '{action}'"
            )
        # Add data_classification_required field
        if "data_classification_required" not in rule:
            rule["data_classification_required"] = None

    # Add context_authority section if missing
    if "context_authority" not in migrated:
        migrated["context_authority"] = {
            "enabled": True,
            "source_classification": {
                "USER_PROMPT": "AUTHORITATIVE",
                "SYSTEM_PROMPT": "AUTHORITATIVE",
                "TOOL_OUTPUT": "DERIVED",
                "AGENT_MSG": "DERIVED",
                "WEB": "UNTRUSTED",
                "EMAIL": "UNTRUSTED",
            },
            "block_untrusted_in_privileged": True,
        }
        changes.append("Added context_authority section with default classification")

    # Add trust_degradation section if missing
    if "trust_degradation" not in migrated:
        migrated["trust_degradation"] = {
            "enabled": True,
            "initial_ceiling": 1.0,
            "untrusted_penalty": 0.15,
            "quarantine_penalty": 0.40,
            "injection_penalty": 0.50,
            "delegation_penalty_per_hop": 0.05,
            "minimum_ceiling": 0.0,
            "irreversible": True,
        }
        changes.append("Added trust_degradation section with default penalties")

    # Enhance taint section
    taint = migrated.get("taint", {})
    if "trust_ceiling_enabled" not in taint:
        taint["trust_ceiling_enabled"] = True
        changes.append("Added trust_ceiling_enabled=True to taint section")
    migrated["taint"] = taint

    # Enhance risk section
    risk = migrated.get("risk", {})
    weights = risk.get("default_weights", {})
    if "context_authority" not in weights:
        weights["context_authority"] = 0.15
        changes.append("Added context_authority weight (0.15) to risk default_weights")
    risk["default_weights"] = weights
    migrated["risk"] = risk

    return migrated, warnings, changes


# ---------------------------------------------------------------------------
# Migration registry
# ---------------------------------------------------------------------------

_MIGRATIONS: dict[tuple[str, str], Any] = {
    ("1.0", "2.0"): _migrate_1_0_to_2_0,
}

_SUPPORTED_VERSIONS = ["1.0", "2.0"]


# ---------------------------------------------------------------------------
# Migrator
# ---------------------------------------------------------------------------


class PolicyMigrator:
    """Migrate YAML policy files between schema versions (APEP-271).

    Usage::

        migrator = PolicyMigrator()
        result = migrator.migrate_file(Path("policy.yaml"), target_version="2.0")
        print(result.yaml_output)
    """

    def migrate(
        self,
        data: dict[str, Any],
        target_version: str = "2.0",
    ) -> MigrationResult:
        """Migrate a policy dict to the target schema version.

        Args:
            data: Parsed YAML policy data.
            target_version: Target schema version string.

        Returns:
            MigrationResult with migrated YAML and change log.

        Raises:
            ValueError: If migration path is not supported.
        """
        source_version = data.get("schema_version", "1.0")

        if source_version == target_version:
            return MigrationResult(
                source_version=source_version,
                target_version=target_version,
                yaml_output=yaml.dump(data, default_flow_style=False, sort_keys=False),
                migrated_data=data,
                warnings=["No migration needed — already at target version"],
            )

        migration_fn = _MIGRATIONS.get((source_version, target_version))
        if migration_fn is None:
            # Try to find a multi-step path
            path = self._find_migration_path(source_version, target_version)
            if not path:
                raise ValueError(
                    f"No migration path from v{source_version} to v{target_version}. "
                    f"Supported versions: {_SUPPORTED_VERSIONS}"
                )

            # Execute multi-step migration
            current_data = copy.deepcopy(data)
            all_warnings: list[str] = []
            all_changes: list[str] = []

            for step_from, step_to in zip(path[:-1], path[1:]):
                fn = _MIGRATIONS[(step_from, step_to)]
                current_data, warnings, changes = fn(current_data)
                all_warnings.extend(warnings)
                all_changes.extend(changes)

            return MigrationResult(
                source_version=source_version,
                target_version=target_version,
                yaml_output=yaml.dump(
                    current_data, default_flow_style=False, sort_keys=False
                ),
                migrated_data=current_data,
                warnings=all_warnings,
                changes=all_changes,
            )

        migrated_data, warnings, changes = migration_fn(data)

        return MigrationResult(
            source_version=source_version,
            target_version=target_version,
            yaml_output=yaml.dump(
                migrated_data, default_flow_style=False, sort_keys=False
            ),
            migrated_data=migrated_data,
            warnings=warnings,
            changes=changes,
        )

    def migrate_file(
        self,
        path: Path,
        target_version: str = "2.0",
    ) -> MigrationResult:
        """Migrate a YAML policy file to the target schema version."""
        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict):
            raise ValueError(f"Expected YAML mapping in {path}, got {type(data).__name__}")
        return self.migrate(data, target_version=target_version)

    def _find_migration_path(
        self, source: str, target: str
    ) -> list[str] | None:
        """Find a migration path through available step migrations."""
        # BFS through migration graph
        from collections import deque

        graph: dict[str, list[str]] = {}
        for (s, t) in _MIGRATIONS:
            graph.setdefault(s, []).append(t)

        queue: deque[list[str]] = deque([[source]])
        visited: set[str] = {source}

        while queue:
            path = queue.popleft()
            current = path[-1]

            if current == target:
                return path

            for neighbor in graph.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(path + [neighbor])

        return None
