"""Built-in Chain Pattern Library — Sprint 49 (APEP-390).

Provides 10 built-in attack chain patterns covering common multi-step
attack sequences.  Patterns are loaded at module level and can be
extended with custom patterns via the management API.

Each pattern defines an ordered sequence of tool-call glob patterns,
a time window, severity, and recommended action.  The library serves
as the default pattern set for the ToolCallChainDetector.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from typing import Any

from app.models.tool_call_chain import (
    ChainCategory,
    ChainDetectionAction,
    ChainMatchStrategy,
    ChainSeverity,
    ToolCallChainPattern,
    ToolCallChainStep,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Built-in patterns (10 patterns — APEP-390)
# ---------------------------------------------------------------------------

_BUILTIN_PATTERNS: list[ToolCallChainPattern] = [
    # 1. Data Exfiltration via HTTP
    ToolCallChainPattern(
        pattern_id="CHAIN-001",
        name="Data Exfiltration via HTTP",
        description=(
            "Database query or file read followed by encoding and HTTP POST — "
            "indicates staged data exfiltration to an external endpoint."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="db.query", max_gap=5),
            ToolCallChainStep(tool_pattern="*encode*", optional=True, max_gap=5),
            ToolCallChainStep(tool_pattern="http.post", max_gap=5),
        ],
        category=ChainCategory.DATA_EXFILTRATION,
        severity=ChainSeverity.CRITICAL,
        action=ChainDetectionAction.ESCALATE,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=300,
        risk_boost=0.95,
        mitre_technique_id="T1041",
        enabled=True,
        builtin=True,
    ),
    # 2. Credential Theft Pipeline
    ToolCallChainPattern(
        pattern_id="CHAIN-002",
        name="Credential Theft Pipeline",
        description=(
            "Secret or credential access followed by encoding and network "
            "exfiltration — a complete credential theft kill chain."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="secret.*", max_gap=5),
            ToolCallChainStep(tool_pattern="*encode*", optional=True, max_gap=5),
            ToolCallChainStep(tool_pattern="http.*", max_gap=5),
        ],
        category=ChainCategory.CREDENTIAL_THEFT,
        severity=ChainSeverity.CRITICAL,
        action=ChainDetectionAction.DENY,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=300,
        risk_boost=0.95,
        mitre_technique_id="T1555",
        enabled=True,
        builtin=True,
    ),
    # 3. Privilege Escalation via Backdoor Account
    ToolCallChainPattern(
        pattern_id="CHAIN-003",
        name="Privilege Escalation via Backdoor Account",
        description=(
            "User enumeration followed by account creation and role "
            "modification — indicates creation of a backdoor admin account."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="admin.list_*", max_gap=5),
            ToolCallChainStep(tool_pattern="admin.create_user", max_gap=5),
            ToolCallChainStep(tool_pattern="admin.modify_role", max_gap=5),
        ],
        category=ChainCategory.PRIVILEGE_ESCALATION,
        severity=ChainSeverity.CRITICAL,
        action=ChainDetectionAction.DENY,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=600,
        risk_boost=0.9,
        mitre_technique_id="T1136",
        enabled=True,
        builtin=True,
    ),
    # 4. Malware Drop-Execute-Clean
    ToolCallChainPattern(
        pattern_id="CHAIN-004",
        name="Malware Drop-Execute-Clean",
        description=(
            "File write followed by shell execution and file deletion — "
            "classic malware deployment with evidence cleanup."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="file.write", max_gap=3),
            ToolCallChainStep(tool_pattern="shell.exec", max_gap=3),
            ToolCallChainStep(tool_pattern="file.delete", max_gap=5),
        ],
        category=ChainCategory.DEFENSE_EVASION,
        severity=ChainSeverity.CRITICAL,
        action=ChainDetectionAction.DENY,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=300,
        risk_boost=0.95,
        mitre_technique_id="T1059",
        enabled=True,
        builtin=True,
    ),
    # 5. Reconnaissance and Exfiltration
    ToolCallChainPattern(
        pattern_id="CHAIN-005",
        name="Reconnaissance and Exfiltration",
        description=(
            "Admin enumeration operations followed by HTTP POST — "
            "recon data collected and sent to external endpoint."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="admin.list_*", max_gap=5),
            ToolCallChainStep(tool_pattern="*.read", optional=True, max_gap=5),
            ToolCallChainStep(tool_pattern="http.post", max_gap=5),
        ],
        category=ChainCategory.RECONNAISSANCE,
        severity=ChainSeverity.HIGH,
        action=ChainDetectionAction.ESCALATE,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=600,
        risk_boost=0.8,
        mitre_technique_id="T1087",
        enabled=True,
        builtin=True,
    ),
    # 6. Lateral Movement via Credential Replay
    ToolCallChainPattern(
        pattern_id="CHAIN-006",
        name="Lateral Movement via Credential Replay",
        description=(
            "Credential access followed by admin role modification and "
            "secret access — privilege escalation to access more resources."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="credential.*", max_gap=5),
            ToolCallChainStep(tool_pattern="admin.modify_role", max_gap=5),
            ToolCallChainStep(tool_pattern="secret.*", max_gap=5),
        ],
        category=ChainCategory.LATERAL_MOVEMENT,
        severity=ChainSeverity.HIGH,
        action=ChainDetectionAction.ESCALATE,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=600,
        risk_boost=0.85,
        mitre_technique_id="T1550",
        enabled=True,
        builtin=True,
    ),
    # 7. Persistence via Scheduled Task
    ToolCallChainPattern(
        pattern_id="CHAIN-007",
        name="Persistence via Scheduled Task",
        description=(
            "File write followed by shell exec to install persistence — "
            "sets up scheduled task or cron job for re-entry."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="file.write", max_gap=3),
            ToolCallChainStep(tool_pattern="shell.exec", max_gap=3),
            ToolCallChainStep(tool_pattern="shell.exec", max_gap=5),
        ],
        category=ChainCategory.PERSISTENCE,
        severity=ChainSeverity.HIGH,
        action=ChainDetectionAction.ESCALATE,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=600,
        risk_boost=0.85,
        mitre_technique_id="T1053",
        enabled=True,
        builtin=True,
    ),
    # 8. Supply Chain Injection
    ToolCallChainPattern(
        pattern_id="CHAIN-008",
        name="Supply Chain Injection",
        description=(
            "Package read followed by modification and publish — "
            "tampers with a package artifact before distribution."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="*.read", max_gap=5),
            ToolCallChainStep(tool_pattern="file.write", max_gap=5),
            ToolCallChainStep(tool_pattern="deploy.*", max_gap=5),
        ],
        category=ChainCategory.SUPPLY_CHAIN,
        severity=ChainSeverity.HIGH,
        action=ChainDetectionAction.ESCALATE,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=900,
        risk_boost=0.85,
        mitre_technique_id="T1195",
        enabled=True,
        builtin=True,
    ),
    # 9. Mass Data Destruction
    ToolCallChainPattern(
        pattern_id="CHAIN-009",
        name="Mass Data Destruction",
        description=(
            "Multiple database drop operations followed by file deletion — "
            "coordinated destruction of data across storage layers."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="db.drop*", max_gap=3),
            ToolCallChainStep(tool_pattern="db.drop*", max_gap=3),
            ToolCallChainStep(tool_pattern="file.delete", max_gap=5),
        ],
        category=ChainCategory.DESTRUCTION,
        severity=ChainSeverity.CRITICAL,
        action=ChainDetectionAction.DENY,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=300,
        risk_boost=0.95,
        mitre_technique_id="T1485",
        enabled=True,
        builtin=True,
    ),
    # 10. Resource Abuse via Crypto Mining
    ToolCallChainPattern(
        pattern_id="CHAIN-010",
        name="Resource Abuse via Compute Hijacking",
        description=(
            "HTTP download followed by file write and repeated shell exec — "
            "downloads and runs resource-intensive workloads (e.g. crypto mining)."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="http.*", max_gap=5),
            ToolCallChainStep(tool_pattern="file.write", max_gap=5),
            ToolCallChainStep(tool_pattern="shell.exec", max_gap=3),
        ],
        category=ChainCategory.RESOURCE_ABUSE,
        severity=ChainSeverity.HIGH,
        action=ChainDetectionAction.ESCALATE,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=600,
        risk_boost=0.8,
        mitre_technique_id="T1496",
        enabled=True,
        builtin=True,
    ),
]


# ---------------------------------------------------------------------------
# Security guard: pattern validation (APEP-390.d)
# ---------------------------------------------------------------------------

# Characters allowed in tool_pattern globs
_SAFE_PATTERN_RE = re.compile(r"^[a-zA-Z0-9_.*?\-\[\]]+$")

# Maximum chain length
_MAX_CHAIN_STEPS = 20

# Maximum window
_MAX_WINDOW_SECONDS = 86400


def validate_chain_pattern(pattern: ToolCallChainPattern) -> list[str]:
    """Validate a chain pattern for security issues.

    Returns a list of validation error strings (empty if valid).
    """
    errors: list[str] = []

    if not pattern.name or len(pattern.name.strip()) == 0:
        errors.append("Pattern name must not be empty")

    if len(pattern.steps) < 2:
        errors.append("Pattern must have at least 2 steps")

    if len(pattern.steps) > _MAX_CHAIN_STEPS:
        errors.append(f"Pattern must have at most {_MAX_CHAIN_STEPS} steps")

    for i, step in enumerate(pattern.steps):
        if not _SAFE_PATTERN_RE.match(step.tool_pattern):
            errors.append(
                f"Step {i}: tool_pattern '{step.tool_pattern}' contains unsafe characters"
            )
        if len(step.tool_pattern) > 128:
            errors.append(f"Step {i}: tool_pattern exceeds 128 characters")

    if pattern.window_seconds < 30:
        errors.append("window_seconds must be at least 30")
    if pattern.window_seconds > _MAX_WINDOW_SECONDS:
        errors.append(f"window_seconds must be at most {_MAX_WINDOW_SECONDS}")

    if not (0.0 <= pattern.risk_boost <= 1.0):
        errors.append("risk_boost must be between 0.0 and 1.0")

    return errors


def compute_pattern_integrity_hash(pattern: ToolCallChainPattern) -> str:
    """Compute HMAC-SHA256 integrity hash for a built-in pattern.

    Used to detect tampering of built-in patterns at runtime.
    """
    canonical = json.dumps(
        {
            "pattern_id": pattern.pattern_id,
            "name": pattern.name,
            "steps": [
                {"tool_pattern": s.tool_pattern, "optional": s.optional, "max_gap": s.max_gap}
                for s in pattern.steps
            ],
            "category": pattern.category.value,
            "severity": pattern.severity.value,
            "risk_boost": pattern.risk_boost,
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Library manager
# ---------------------------------------------------------------------------


class ChainPatternLibrary:
    """Manages built-in and custom chain patterns (APEP-390).

    Built-in patterns are immutable and integrity-checked.  Custom
    patterns can be added, updated, and deleted via the management API.
    """

    def __init__(self) -> None:
        self._builtin: list[ToolCallChainPattern] = list(_BUILTIN_PATTERNS)
        self._custom: dict[str, ToolCallChainPattern] = {}
        self._builtin_hashes: dict[str, str] = {}
        self._compute_builtin_hashes()

    def _compute_builtin_hashes(self) -> None:
        """Pre-compute integrity hashes for all built-in patterns."""
        for pattern in self._builtin:
            self._builtin_hashes[pattern.pattern_id] = compute_pattern_integrity_hash(
                pattern
            )

    def verify_builtin_integrity(self) -> list[str]:
        """Verify integrity of all built-in patterns.

        Returns list of pattern_ids that have been tampered with.
        """
        tampered: list[str] = []
        for pattern in self._builtin:
            expected = self._builtin_hashes.get(pattern.pattern_id, "")
            actual = compute_pattern_integrity_hash(pattern)
            if expected != actual:
                tampered.append(pattern.pattern_id)
                logger.warning(
                    "Built-in chain pattern integrity check failed: %s",
                    pattern.pattern_id,
                )
        return tampered

    @property
    def builtin_patterns(self) -> list[ToolCallChainPattern]:
        return list(self._builtin)

    @property
    def custom_patterns(self) -> list[ToolCallChainPattern]:
        return list(self._custom.values())

    def get_all_enabled(self) -> list[ToolCallChainPattern]:
        """Return all enabled patterns (built-in + custom)."""
        return [
            p
            for p in (*self._builtin, *self._custom.values())
            if p.enabled
        ]

    def get_pattern(self, pattern_id: str) -> ToolCallChainPattern | None:
        """Get a pattern by ID (built-in or custom)."""
        for p in self._builtin:
            if p.pattern_id == pattern_id:
                return p
        return self._custom.get(pattern_id)

    def add_custom_pattern(self, pattern: ToolCallChainPattern) -> list[str]:
        """Add a custom pattern.  Returns validation errors (empty if OK)."""
        errors = validate_chain_pattern(pattern)
        if errors:
            return errors
        self._custom[pattern.pattern_id] = pattern
        return []

    def update_custom_pattern(
        self, pattern_id: str, updates: dict[str, Any]
    ) -> tuple[ToolCallChainPattern | None, list[str]]:
        """Update a custom pattern.  Returns (updated_pattern, errors)."""
        existing = self._custom.get(pattern_id)
        if existing is None:
            # Check if it's a built-in — cannot update built-ins
            for p in self._builtin:
                if p.pattern_id == pattern_id:
                    return None, ["Cannot update built-in patterns"]
            return None, ["Pattern not found"]

        updated_data = existing.model_dump()
        updated_data.update(updates)
        updated_pattern = ToolCallChainPattern(**updated_data)

        errors = validate_chain_pattern(updated_pattern)
        if errors:
            return None, errors

        self._custom[pattern_id] = updated_pattern
        return updated_pattern, []

    def delete_custom_pattern(self, pattern_id: str) -> bool:
        """Delete a custom pattern.  Returns True if deleted."""
        # Cannot delete built-in patterns
        for p in self._builtin:
            if p.pattern_id == pattern_id:
                logger.warning(
                    "Attempted to delete built-in pattern: %s", pattern_id
                )
                return False
        return self._custom.pop(pattern_id, None) is not None

    @property
    def total_count(self) -> int:
        return len(self._builtin) + len(self._custom)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

chain_pattern_library = ChainPatternLibrary()
