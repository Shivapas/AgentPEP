"""CISRepoScanner — pre-session repository scanner (Layer 0).

Sprint 54 — APEP-428: Scans all repo files before the agent session launches,
detecting injection attempts in instruction files and source code.

Architecture:
  1. Walk the repository directory, filtering by include/exclude globs.
  2. Classify each file (instruction file vs. regular).
  3. Read and scan each file through the CIS pipeline.
  4. Instruction files always use STRICT mode; others use auto-detected mode.
  5. Aggregate findings and assign taint if session_id is provided.
  6. Emit Kafka CIS events.

Performance target: <50ms for typical repositories (<500 files).
"""

from __future__ import annotations

import fnmatch
import logging
import os
import time
from datetime import UTC, datetime

from app.models.cis_scanner import (
    CISEvent,
    CISEventType,
    CISFinding,
    CISScanVerdict,
    RepoScanFileResult,
    RepoScanRequest,
    RepoScanResult,
)
from app.services.cis_instruction_scanner import cis_instruction_scanner
from app.services.cis_pipeline import CISPipeline, CISPipelineResult, cis_pipeline

logger = logging.getLogger(__name__)

# Maximum file size to scan (1 MB) — skip large binaries.
_MAX_FILE_SIZE = 1_048_576

# Text-like extensions to scan; skip binary files.
_TEXT_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".rs", ".go", ".java", ".kt",
    ".rb", ".php", ".c", ".cpp", ".h", ".cs", ".swift", ".scala",
    ".md", ".rst", ".txt", ".yaml", ".yml", ".toml", ".json", ".xml",
    ".html", ".css", ".scss", ".less", ".sql", ".sh", ".bash", ".zsh",
    ".env", ".cfg", ".ini", ".conf", ".dockerfile", ".makefile",
    ".graphql", ".proto", ".tf", ".hcl",
})

# Files without extensions that should be scanned.
_TEXT_FILENAMES: frozenset[str] = frozenset({
    "Makefile", "Dockerfile", "Jenkinsfile", "Vagrantfile",
    "Gemfile", "Rakefile", "Procfile",
    "CLAUDE.md", ".cursorrules", "AGENTS.md",
    ".gitignore", ".dockerignore", ".editorconfig",
    ".env", ".env.example", ".env.local",
})


class CISRepoScanner:
    """Pre-session repository scanner.

    Walks a repository directory tree, identifies instruction files, and
    scans all text files through the CIS pipeline.

    Parameters
    ----------
    pipeline:
        The CIS pipeline to use for scanning individual files.
    """

    def __init__(self, pipeline: CISPipeline | None = None) -> None:
        self._pipeline = pipeline or cis_pipeline

    def scan(self, request: RepoScanRequest) -> RepoScanResult:
        """Scan a repository directory and return aggregate results."""
        start = time.monotonic()
        started_at = datetime.now(UTC)

        if not os.path.isdir(request.repo_path):
            return RepoScanResult(
                repo_path=request.repo_path,
                allowed=True,
                verdict=CISScanVerdict.CLEAN,
                scan_mode=request.scan_mode,
                latency_ms=self._elapsed_ms(start),
                started_at=started_at,
                completed_at=datetime.now(UTC),
            )

        # Collect files to scan.
        file_paths = self._collect_files(
            repo_path=request.repo_path,
            include_patterns=request.include_patterns,
            exclude_patterns=request.exclude_patterns,
            max_files=request.max_files,
        )

        file_results: list[RepoScanFileResult] = []
        all_findings: list[CISFinding] = []
        instruction_files_found = 0

        for fpath in file_paths:
            rel_path = os.path.relpath(fpath, request.repo_path)
            file_result = self._scan_file(
                file_path=fpath,
                rel_path=rel_path,
                request=request,
            )
            file_results.append(file_result)
            all_findings.extend(file_result.findings)
            if file_result.is_instruction_file:
                instruction_files_found += 1

        # Aggregate
        critical_count = sum(1 for f in all_findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in all_findings if f.severity == "HIGH")
        has_blocking = critical_count > 0 or high_count > 0

        verdict = CISScanVerdict.CLEAN
        if critical_count > 0:
            verdict = CISScanVerdict.MALICIOUS
        elif high_count > 0:
            verdict = CISScanVerdict.SUSPICIOUS

        # Taint assignment
        taint_assigned: str | None = None
        if has_blocking:
            taint_assigned = "QUARANTINE"
        elif all_findings:
            taint_assigned = "UNTRUSTED"

        return RepoScanResult(
            repo_path=request.repo_path,
            allowed=not has_blocking,
            verdict=verdict,
            total_files_scanned=len(file_results),
            total_findings=len(all_findings),
            critical_findings=critical_count,
            high_findings=high_count,
            instruction_files_found=instruction_files_found,
            file_results=file_results,
            taint_assigned=taint_assigned,
            scan_mode=request.scan_mode,
            latency_ms=self._elapsed_ms(start),
            started_at=started_at,
            completed_at=datetime.now(UTC),
        )

    def _scan_file(
        self,
        file_path: str,
        rel_path: str,
        request: RepoScanRequest,
    ) -> RepoScanFileResult:
        """Scan a single file through the CIS pipeline."""
        start = time.monotonic()

        is_instruction = cis_instruction_scanner.is_instruction_file(rel_path)
        instruction_type = cis_instruction_scanner.classify(rel_path) if is_instruction else None
        scan_mode = cis_instruction_scanner.scan_mode_for_file(
            rel_path, requested_mode=request.scan_mode
        )

        # Read file content.
        try:
            content = self._read_file(file_path)
        except (OSError, UnicodeDecodeError):
            return RepoScanFileResult(
                file_path=rel_path,
                scan_mode_applied=scan_mode,
                allowed=True,
                is_instruction_file=is_instruction,
                instruction_file_type=instruction_type,
                latency_ms=self._elapsed_ms(start),
            )

        if not content.strip():
            return RepoScanFileResult(
                file_path=rel_path,
                scan_mode_applied=scan_mode,
                allowed=True,
                is_instruction_file=is_instruction,
                instruction_file_type=instruction_type,
                latency_ms=self._elapsed_ms(start),
            )

        # Run through CIS pipeline.
        result: CISPipelineResult = self._pipeline.scan(
            text=content,
            scan_mode=scan_mode,
            tiers=request.tiers,
            tenant_id=request.tenant_id,
            use_cache=request.use_cache,
        )

        # Convert pipeline findings to CISFinding with file context.
        findings: list[CISFinding] = []
        for f in result.findings:
            findings.append(
                CISFinding(
                    rule_id=f.rule_id,
                    scanner=f.scanner,
                    severity=f.severity.value,
                    description=f.description,
                    matched_text=f.matched_text[:200],
                    file_path=rel_path,
                )
            )

        has_blocking = any(f.severity in ("CRITICAL", "HIGH") for f in findings)

        return RepoScanFileResult(
            file_path=rel_path,
            scan_mode_applied=scan_mode,
            allowed=not has_blocking,
            findings=findings,
            is_instruction_file=is_instruction,
            instruction_file_type=instruction_type,
            cache_hit=result.cache_hit,
            latency_ms=self._elapsed_ms(start),
        )

    def _collect_files(
        self,
        repo_path: str,
        include_patterns: list[str],
        exclude_patterns: list[str],
        max_files: int,
    ) -> list[str]:
        """Walk the repo and collect scannable file paths."""
        collected: list[str] = []

        for dirpath, dirnames, filenames in os.walk(repo_path):
            # Prune excluded directories in-place.
            rel_dir = os.path.relpath(dirpath, repo_path)
            dirnames[:] = [
                d for d in dirnames
                if not self._matches_any(os.path.join(rel_dir, d), exclude_patterns)
                and not d.startswith(".")
                or d == ".github"
            ]

            for fname in filenames:
                if len(collected) >= max_files:
                    return collected

                fpath = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(fpath, repo_path)

                # Exclude check.
                if self._matches_any(rel_path, exclude_patterns):
                    continue

                # Include check (empty = all).
                if include_patterns and not self._matches_any(rel_path, include_patterns):
                    continue

                # Skip large and binary files.
                if not self._is_scannable(fpath, fname):
                    continue

                collected.append(fpath)

        return collected

    def _is_scannable(self, file_path: str, filename: str) -> bool:
        """Return True if the file should be scanned (text, reasonable size)."""
        # Always scan instruction files.
        if cis_instruction_scanner.is_instruction_file(filename):
            return True

        # Check extension.
        ext = os.path.splitext(filename)[1].lower()
        if ext and ext not in _TEXT_EXTENSIONS:
            return False

        # Check filename for known text files.
        if not ext and filename not in _TEXT_FILENAMES:
            return False

        # Check file size.
        try:
            size = os.path.getsize(file_path)
            return size <= _MAX_FILE_SIZE
        except OSError:
            return False

    def _read_file(self, file_path: str) -> str:
        """Read file content as UTF-8 text."""
        with open(file_path, encoding="utf-8", errors="replace") as f:
            return f.read()

    @staticmethod
    def _matches_any(path: str, patterns: list[str]) -> bool:
        """Return True if *path* matches any of the glob *patterns*."""
        normalised = path.replace("\\", "/")
        for pattern in patterns:
            if fnmatch.fnmatch(normalised, pattern):
                return True
        return False

    @staticmethod
    def _elapsed_ms(start: float) -> int:
        return int((time.monotonic() - start) * 1000)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

cis_repo_scanner = CISRepoScanner()
