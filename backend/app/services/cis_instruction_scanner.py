"""CISInstructionScanner — agent instruction file scanner with STRICT mode defaults.

Sprint 54 — APEP-429: Dedicated scanner for agent instruction files
(CLAUDE.md, .cursorrules, AGENTS.md, .github/copilot-instructions.md).

These files are high-value injection targets because they are implicitly
trusted by coding agents.  The scanner enforces STRICT mode with lower
thresholds and QUARANTINE-on-any-HIGH-finding semantics.

Security model:
  - All instruction files are scanned in STRICT mode regardless of caller request.
  - Any HIGH or CRITICAL finding triggers QUARANTINE taint assignment.
  - File type detection uses both filename matching and path heuristics.
  - Content is scanned through the full CIS pipeline (Tier 0 + Tier 1).
"""

from __future__ import annotations

import logging
import os
from pathlib import PurePosixPath

from app.models.cis_scanner import InstructionFileType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Instruction file detection
# ---------------------------------------------------------------------------

# Exact filenames (case-sensitive) that are always instruction files.
_INSTRUCTION_FILENAMES: dict[str, InstructionFileType] = {
    "CLAUDE.md": InstructionFileType.CLAUDE_MD,
    ".cursorrules": InstructionFileType.CURSORRULES,
    "AGENTS.md": InstructionFileType.AGENTS_MD,
}

# Path suffixes for files in subdirectories.
_INSTRUCTION_PATH_SUFFIXES: dict[str, InstructionFileType] = {
    ".github/copilot-instructions.md": InstructionFileType.COPILOT_INSTRUCTIONS,
}


class CISInstructionScanner:
    """Detects and classifies agent instruction files.

    This scanner identifies files that coding agents treat as trusted
    instructions, ensuring they are always scanned in STRICT mode with
    maximum sensitivity.
    """

    def __init__(self) -> None:
        self._filenames = dict(_INSTRUCTION_FILENAMES)
        self._path_suffixes = dict(_INSTRUCTION_PATH_SUFFIXES)

    def is_instruction_file(self, file_path: str) -> bool:
        """Return True if *file_path* is a known agent instruction file."""
        return self.classify(file_path) is not None

    def classify(self, file_path: str) -> InstructionFileType | None:
        """Return the instruction file type, or None if not an instruction file."""
        basename = os.path.basename(file_path)

        # Check exact filename match.
        if basename in self._filenames:
            return self._filenames[basename]

        # Check path suffix match (e.g. .github/copilot-instructions.md).
        normalised = file_path.replace("\\", "/")
        for suffix, file_type in self._path_suffixes.items():
            if normalised.endswith(suffix):
                return file_type

        return None

    def effective_scan_mode(self, file_path: str) -> str:
        """Return the scan mode to apply for *file_path*.

        Instruction files always use STRICT.  Other files return STANDARD.
        """
        if self.is_instruction_file(file_path):
            return "STRICT"
        return "STANDARD"

    def scan_mode_for_file(self, file_path: str, requested_mode: str | None = None) -> str:
        """Return the effective scan mode, enforcing STRICT for instruction files.

        If the file is an instruction file, STRICT is always returned regardless
        of the *requested_mode*.  For other files, returns *requested_mode* or
        auto-detects based on file extension.
        """
        if self.is_instruction_file(file_path):
            return "STRICT"

        if requested_mode is not None:
            return requested_mode

        return self._auto_detect_mode(file_path)

    def _auto_detect_mode(self, file_path: str) -> str:
        """Auto-detect scan mode based on file extension and path heuristics."""
        basename = os.path.basename(file_path).lower()
        path_lower = file_path.lower()

        # Test files and fixtures → LENIENT
        if any(part in path_lower for part in (
            "/test", "/tests/", "/fixtures/", "/testdata/",
            "__tests__", ".test.", ".spec.",
        )):
            return "LENIENT"

        # Config files that agents may read → STANDARD
        config_extensions = {
            ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".env",
        }
        config_filenames = {
            "package.json", "makefile", "dockerfile", "docker-compose.yml",
            "pyproject.toml", "setup.cfg", "tsconfig.json", ".eslintrc.json",
        }
        ext = os.path.splitext(basename)[1]
        if ext in config_extensions or basename in config_filenames:
            return "STANDARD"

        # Documentation → LENIENT
        if ext in (".md", ".rst", ".txt") and not self.is_instruction_file(file_path):
            return "LENIENT"

        # Source code → STANDARD
        return "STANDARD"


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

cis_instruction_scanner = CISInstructionScanner()
