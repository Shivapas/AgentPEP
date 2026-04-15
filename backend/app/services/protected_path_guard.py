"""Protected Path Patterns for PreToolUse — Sprint 55 (APEP-441).

Defines patterns for file/resource paths that must be protected from
agent tool operations.  When a PreToolUse tool call targets a path
matching a protected pattern, the guard takes the configured action
(DENY, ESCALATE, or AUDIT_ONLY).

Built-in protected patterns cover:
  - Agent instruction files (CLAUDE.md, .cursorrules, AGENTS.md)
  - Environment/secret files (.env, .env.*, credentials.json)
  - Security configuration files (agentpep.yaml, trust config)
  - System critical files (/etc/passwd, /etc/shadow, etc.)
"""

from __future__ import annotations

import fnmatch
import logging
import re

from app.models.camel_seq import (
    ProtectedPathAction,
    ProtectedPathCheckResult,
    ProtectedPathListResponse,
    ProtectedPathPattern,
)

logger = logging.getLogger(__name__)

# Characters allowed in path glob patterns
_SAFE_PATH_PATTERN_RE = re.compile(r"^[a-zA-Z0-9_.*?/\-\[\]{}]+$")


# ---------------------------------------------------------------------------
# Built-in protected path patterns (APEP-441)
# ---------------------------------------------------------------------------

_BUILTIN_PATTERNS: list[ProtectedPathPattern] = [
    # Agent instruction files
    ProtectedPathPattern(
        pattern_id="PP-BUILTIN-001",
        path_glob="**/CLAUDE.md",
        description="Agent instruction file — prevents agent from modifying its own instructions",
        action=ProtectedPathAction.DENY,
        applies_to_tools=["file.write", "file.delete", "file.append"],
        builtin=True,
    ),
    ProtectedPathPattern(
        pattern_id="PP-BUILTIN-002",
        path_glob="**/.cursorrules",
        description="Cursor agent rules file",
        action=ProtectedPathAction.DENY,
        applies_to_tools=["file.write", "file.delete", "file.append"],
        builtin=True,
    ),
    ProtectedPathPattern(
        pattern_id="PP-BUILTIN-003",
        path_glob="**/AGENTS.md",
        description="Multi-agent instruction file",
        action=ProtectedPathAction.DENY,
        applies_to_tools=["file.write", "file.delete", "file.append"],
        builtin=True,
    ),
    ProtectedPathPattern(
        pattern_id="PP-BUILTIN-004",
        path_glob="**/.copilot-instructions.md",
        description="Copilot instruction file",
        action=ProtectedPathAction.DENY,
        applies_to_tools=["file.write", "file.delete", "file.append"],
        builtin=True,
    ),
    # Environment / secret files
    ProtectedPathPattern(
        pattern_id="PP-BUILTIN-005",
        path_glob="**/.env",
        description="Environment secrets file",
        action=ProtectedPathAction.ESCALATE,
        applies_to_tools=["file.write", "file.delete", "file.read"],
        builtin=True,
    ),
    ProtectedPathPattern(
        pattern_id="PP-BUILTIN-006",
        path_glob="**/.env.*",
        description="Environment variant files (.env.local, .env.production, etc.)",
        action=ProtectedPathAction.ESCALATE,
        applies_to_tools=["file.write", "file.delete", "file.read"],
        builtin=True,
    ),
    ProtectedPathPattern(
        pattern_id="PP-BUILTIN-007",
        path_glob="**/credentials.json",
        description="Credential storage file",
        action=ProtectedPathAction.DENY,
        applies_to_tools=["file.write", "file.delete", "file.read"],
        builtin=True,
    ),
    # Security configuration
    ProtectedPathPattern(
        pattern_id="PP-BUILTIN-008",
        path_glob="**/agentpep.yaml",
        description="AgentPEP policy configuration",
        action=ProtectedPathAction.DENY,
        applies_to_tools=["file.write", "file.delete"],
        builtin=True,
    ),
    ProtectedPathPattern(
        pattern_id="PP-BUILTIN-009",
        path_glob=".tooltrust/*",
        description="ToolTrust configuration directory",
        action=ProtectedPathAction.DENY,
        applies_to_tools=["file.write", "file.delete", "shell.exec"],
        builtin=True,
    ),
    # System files
    ProtectedPathPattern(
        pattern_id="PP-BUILTIN-010",
        path_glob="/etc/passwd",
        description="System password file",
        action=ProtectedPathAction.DENY,
        applies_to_tools=["file.write", "file.delete", "file.read"],
        builtin=True,
    ),
    ProtectedPathPattern(
        pattern_id="PP-BUILTIN-011",
        path_glob="/etc/shadow",
        description="System shadow password file",
        action=ProtectedPathAction.DENY,
        applies_to_tools=["file.write", "file.delete", "file.read"],
        builtin=True,
    ),
]


def validate_path_pattern(pattern: ProtectedPathPattern) -> list[str]:
    """Validate a protected path pattern for security issues.

    Returns a list of validation error strings (empty if valid).
    """
    errors: list[str] = []

    if not pattern.path_glob or len(pattern.path_glob.strip()) == 0:
        errors.append("path_glob must not be empty")

    if len(pattern.path_glob) > 512:
        errors.append("path_glob exceeds 512 characters")

    if not _SAFE_PATH_PATTERN_RE.match(pattern.path_glob):
        errors.append(
            f"path_glob '{pattern.path_glob}' contains unsafe characters"
        )

    if not pattern.applies_to_tools:
        errors.append("applies_to_tools must not be empty")

    return errors


class ProtectedPathGuard:
    """Guards protected file paths from agent tool operations (APEP-441).

    Maintains a set of built-in and custom path patterns.  On each
    PreToolUse check, the guard evaluates the tool call's path argument
    against all enabled patterns and returns the appropriate action.
    """

    def __init__(self) -> None:
        self._builtin: list[ProtectedPathPattern] = list(_BUILTIN_PATTERNS)
        self._custom: dict[str, ProtectedPathPattern] = {}

    def check(
        self,
        tool_name: str,
        path: str,
    ) -> ProtectedPathCheckResult:
        """Check a tool call path against all enabled protected patterns.

        Args:
            tool_name: The tool being invoked (e.g. 'file.write').
            path: The file/resource path being accessed.

        Returns:
            ProtectedPathCheckResult with match info and action.
        """
        if not path:
            return ProtectedPathCheckResult(detail="No path to check")

        for pattern in self._get_all_enabled():
            # Check if the tool is in the pattern's applies_to_tools list
            tool_match = any(
                fnmatch.fnmatch(tool_name, tp)
                for tp in pattern.applies_to_tools
            )
            if not tool_match:
                continue

            # Check if the path matches the pattern's glob
            if fnmatch.fnmatch(path, pattern.path_glob):
                return ProtectedPathCheckResult(
                    blocked=pattern.action != ProtectedPathAction.AUDIT_ONLY,
                    matched_pattern_id=pattern.pattern_id,
                    matched_glob=pattern.path_glob,
                    action=pattern.action,
                    detail=(
                        f"Path '{path}' matches protected pattern "
                        f"'{pattern.path_glob}' ({pattern.description})"
                    ),
                )

        return ProtectedPathCheckResult(
            detail=f"Path '{path}' does not match any protected patterns",
        )

    def _get_all_enabled(self) -> list[ProtectedPathPattern]:
        """Return all enabled patterns (built-in + custom)."""
        return [
            p
            for p in (*self._builtin, *self._custom.values())
            if p.enabled
        ]

    @property
    def builtin_patterns(self) -> list[ProtectedPathPattern]:
        return list(self._builtin)

    @property
    def custom_patterns(self) -> list[ProtectedPathPattern]:
        return list(self._custom.values())

    def get_all_patterns(self) -> ProtectedPathListResponse:
        """List all protected path patterns."""
        patterns = self._builtin + list(self._custom.values())
        return ProtectedPathListResponse(
            patterns=patterns,
            total=len(patterns),
        )

    def add_custom_pattern(self, pattern: ProtectedPathPattern) -> list[str]:
        """Add a custom protected path pattern. Returns validation errors."""
        errors = validate_path_pattern(pattern)
        if errors:
            return errors
        self._custom[pattern.pattern_id] = pattern
        return []

    def remove_custom_pattern(self, pattern_id: str) -> bool:
        """Remove a custom pattern. Returns True if removed."""
        for p in self._builtin:
            if p.pattern_id == pattern_id:
                logger.warning(
                    "Attempted to delete built-in protected path: %s",
                    pattern_id,
                )
                return False
        return self._custom.pop(pattern_id, None) is not None

    def get_pattern(self, pattern_id: str) -> ProtectedPathPattern | None:
        """Get a pattern by ID."""
        for p in self._builtin:
            if p.pattern_id == pattern_id:
                return p
        return self._custom.get(pattern_id)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

protected_path_guard = ProtectedPathGuard()
