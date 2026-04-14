"""Filesystem Sentinel — Sprint 50 (APEP-399).

Monitors configured directories for file changes using asyncio polling
(with optional watchdog backend).  On file creation or modification,
runs DLP scans on file content to detect leaked secrets, credentials,
and sensitive data.  Attributes events to processes via /proc lineage.

Integrates into the enforcement pipeline:
  - Publishes SENTINEL_HIT events to Kafka agentpep.network topic
  - Feeds signals to the AdaptiveThreatScore engine
  - Can trigger kill switch on critical findings
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import logging
import os
import time
from pathlib import Path
from uuid import uuid4

from app.models.kill_switch import (
    SentinelConfig,
    SentinelEventType,
    SentinelFinding,
    SentinelSeverity,
    SentinelStatus,
)

logger = logging.getLogger(__name__)


class FilesystemSentinel:
    """Monitors filesystem for secret leakage and suspicious file operations.

    Uses asyncio polling to watch configured directories.  File content is
    scanned with the NetworkDLPScanner when created or modified.  Process
    lineage is resolved via /proc on Linux.

    APEP-399.c: Core security logic
    APEP-399.d: Security guards and crypto (hash-based change detection)
    APEP-399.e: Pipeline integration
    """

    def __init__(self, config: SentinelConfig | None = None) -> None:
        self._config = config or SentinelConfig()
        self._running: bool = False
        self._watch_task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._findings: list[SentinelFinding] = []
        self._file_hashes: dict[str, str] = {}  # path -> sha256
        self._start_time: float = 0.0
        self._last_finding_at: float | None = None

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def configure(self, config: SentinelConfig) -> None:
        """Update sentinel configuration."""
        self._config = config

    @property
    def config(self) -> SentinelConfig:
        return self._config

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> SentinelStatus:
        """Return current sentinel status."""
        from datetime import UTC, datetime

        uptime = time.monotonic() - self._start_time if self._running else 0.0
        return SentinelStatus(
            running=self._running,
            watch_paths=self._config.watch_paths,
            findings_count=len(self._findings),
            last_finding_at=(
                datetime.fromtimestamp(self._last_finding_at, tz=UTC)
                if self._last_finding_at
                else None
            ),
            uptime_seconds=uptime,
        )

    @property
    def findings(self) -> list[SentinelFinding]:
        """Return all findings (most recent last)."""
        return list(self._findings)

    @property
    def findings_count(self) -> int:
        return len(self._findings)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the filesystem sentinel."""
        if self._running:
            return

        if not self._config.enabled:
            logger.info("Filesystem sentinel disabled via config")
            return

        self._running = True
        self._start_time = time.monotonic()

        # Initial scan: hash all existing files in watch paths
        await self._initial_scan()

        # Start the polling loop
        self._watch_task = asyncio.ensure_future(self._watch_loop())
        logger.info(
            "Filesystem sentinel started — watching %s",
            self._config.watch_paths,
        )

    async def stop(self) -> None:
        """Stop the filesystem sentinel."""
        self._running = False
        if self._watch_task is not None:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass
            self._watch_task = None
        logger.info("Filesystem sentinel stopped")

    # ------------------------------------------------------------------
    # Core watch loop (APEP-399.c)
    # ------------------------------------------------------------------

    async def _watch_loop(self, poll_interval: float = 2.0) -> None:
        """Poll watched directories for file changes."""
        while self._running:
            try:
                for watch_path in self._config.watch_paths:
                    await self._scan_directory(watch_path)
            except asyncio.CancelledError:
                return
            except Exception:
                logger.warning("Sentinel watch loop error", exc_info=True)

            await asyncio.sleep(poll_interval)

    async def _scan_directory(self, directory: str) -> None:
        """Scan a directory for new/modified files matching patterns."""
        dir_path = Path(directory)
        if not dir_path.is_dir():
            return

        current_files: set[str] = set()

        try:
            for entry in dir_path.iterdir():
                if not entry.is_file():
                    continue

                file_str = str(entry)
                current_files.add(file_str)

                # Check if file matches our patterns
                if not self._matches_pattern(entry.name):
                    continue

                # Compute hash
                file_hash = await self._hash_file(entry)
                if file_hash is None:
                    continue

                prev_hash = self._file_hashes.get(file_str)

                if prev_hash is None:
                    # New file detected
                    self._file_hashes[file_str] = file_hash
                    if self._config.scan_on_create:
                        await self._handle_file_event(
                            entry, SentinelEventType.FILE_CREATED
                        )
                elif prev_hash != file_hash:
                    # Modified file detected
                    self._file_hashes[file_str] = file_hash
                    if self._config.scan_on_modify:
                        await self._handle_file_event(
                            entry, SentinelEventType.FILE_MODIFIED
                        )

            # Check for deleted files
            for tracked_path in list(self._file_hashes.keys()):
                if tracked_path.startswith(directory) and tracked_path not in current_files:
                    del self._file_hashes[tracked_path]
                    finding = SentinelFinding(
                        event_type=SentinelEventType.FILE_DELETED,
                        severity=SentinelSeverity.INFO,
                        file_path=tracked_path,
                        description=f"Tracked file deleted: {tracked_path}",
                    )
                    self._record_finding(finding)

        except PermissionError:
            logger.debug("Permission denied scanning %s", directory)
        except Exception:
            logger.debug("Error scanning %s", directory, exc_info=True)

    async def _handle_file_event(
        self,
        file_path: Path,
        event_type: SentinelEventType,
    ) -> None:
        """Handle a file creation or modification event.

        Runs DLP scan on the file content and resolves process lineage
        if on Linux.
        """
        # Scan file content for secrets
        dlp_findings = await self._scan_file_content(file_path)

        # Resolve process lineage
        process_pid: int | None = None
        process_name: str = ""
        process_chain: list[str] = []

        try:
            from app.services.process_lineage import process_lineage_resolver

            if process_lineage_resolver.available:
                # Try to identify which process last modified the file
                # Use lsof-style lookup via /proc
                pid = self._find_file_owner_pid(file_path)
                if pid is not None:
                    lineage = process_lineage_resolver.resolve(pid)
                    process_pid = pid
                    if lineage.lineage:
                        process_name = lineage.lineage[0].name
                        process_chain = [
                            f"{p.name}({p.pid})" for p in lineage.lineage
                        ]
        except Exception:
            logger.debug("Process lineage resolution failed", exc_info=True)

        if dlp_findings:
            # Secret detected — create critical finding
            for dlp_finding in dlp_findings:
                finding = SentinelFinding(
                    event_type=SentinelEventType.SECRET_DETECTED,
                    severity=SentinelSeverity.CRITICAL,
                    file_path=str(file_path),
                    rule_id=dlp_finding.get("rule_id", ""),
                    description=f"Secret detected in {file_path.name}: {dlp_finding.get('description', '')}",
                    matched_text=dlp_finding.get("matched_text", "")[:50],
                    process_pid=process_pid,
                    process_name=process_name,
                    process_lineage=process_chain,
                    mitre_technique_id="T1552.001",  # Unsecured credentials: files
                )
                self._record_finding(finding)
                await self._publish_finding(finding)
        else:
            # No secrets but still record the file event
            finding = SentinelFinding(
                event_type=event_type,
                severity=SentinelSeverity.LOW,
                file_path=str(file_path),
                description=f"File {event_type.value.lower()}: {file_path.name}",
                process_pid=process_pid,
                process_name=process_name,
                process_lineage=process_chain,
            )
            self._record_finding(finding)

    # ------------------------------------------------------------------
    # DLP scanning (APEP-399.c/d)
    # ------------------------------------------------------------------

    async def _scan_file_content(self, file_path: Path) -> list[dict]:
        """Scan file content using the NetworkDLPScanner."""
        try:
            content = file_path.read_bytes()[:self._config.max_file_scan_bytes]
            text = content.decode("utf-8", errors="replace")
        except (PermissionError, FileNotFoundError):
            return []
        except Exception:
            logger.debug("Failed to read file for DLP scan: %s", file_path)
            return []

        if not text.strip():
            return []

        try:
            from app.services.network_dlp_scanner import network_dlp_scanner

            findings = network_dlp_scanner.scan_text(text)
            return [
                {
                    "rule_id": f.rule_id,
                    "description": f.description,
                    "matched_text": f.matched_text[:50] if f.matched_text else "",
                    "severity": f.severity.value,
                }
                for f in findings
            ]
        except Exception:
            logger.debug("DLP scan failed for %s", file_path, exc_info=True)
            return []

    # ------------------------------------------------------------------
    # File hashing (APEP-399.d — crypto)
    # ------------------------------------------------------------------

    @staticmethod
    async def _hash_file(file_path: Path) -> str | None:
        """Compute SHA-256 hash of a file (first 1MB)."""
        try:
            content = file_path.read_bytes()[:1_048_576]
            return hashlib.sha256(content).hexdigest()
        except (PermissionError, FileNotFoundError):
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _matches_pattern(self, filename: str) -> bool:
        """Check if filename matches any configured file patterns."""
        for pattern in self._config.file_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        # Also always scan files with sensitive extensions
        sensitive_exts = {".env", ".key", ".pem", ".secret", ".credentials", ".token"}
        _, ext = os.path.splitext(filename)
        return ext.lower() in sensitive_exts

    @staticmethod
    def _find_file_owner_pid(file_path: Path) -> int | None:
        """Try to find the PID of the process that has the file open.

        Scans /proc/*/fd/ for symlinks pointing to the file.
        """
        if not os.path.isdir("/proc/1"):
            return None

        target = str(file_path.resolve())
        try:
            for pid_dir in Path("/proc").iterdir():
                if not pid_dir.name.isdigit():
                    continue
                fd_dir = pid_dir / "fd"
                if not fd_dir.is_dir():
                    continue
                try:
                    for fd in fd_dir.iterdir():
                        try:
                            if str(fd.resolve()) == target:
                                return int(pid_dir.name)
                        except (OSError, ValueError):
                            continue
                except PermissionError:
                    continue
        except Exception:
            pass
        return None

    def _record_finding(self, finding: SentinelFinding) -> None:
        """Record a finding and update state."""
        self._findings.append(finding)
        self._last_finding_at = time.time()

        # Keep only last 1000 findings in memory
        if len(self._findings) > 1000:
            self._findings = self._findings[-500:]

        logger.warning(
            "Sentinel finding: %s — %s in %s",
            finding.event_type.value,
            finding.severity.value,
            finding.file_path,
        )

    async def _initial_scan(self) -> None:
        """Hash all existing files in watch paths on startup."""
        for watch_path in self._config.watch_paths:
            dir_path = Path(watch_path)
            if not dir_path.is_dir():
                continue
            try:
                for entry in dir_path.iterdir():
                    if entry.is_file() and self._matches_pattern(entry.name):
                        file_hash = await self._hash_file(entry)
                        if file_hash is not None:
                            self._file_hashes[str(entry)] = file_hash
            except (PermissionError, OSError):
                pass

        logger.info(
            "Sentinel initial scan: tracked %d files", len(self._file_hashes)
        )

    # ------------------------------------------------------------------
    # Kafka publishing (APEP-399.e)
    # ------------------------------------------------------------------

    async def _publish_finding(self, finding: SentinelFinding) -> None:
        """Publish a sentinel finding to Kafka."""
        try:
            from app.services.kafka_producer import kafka_producer

            event = {
                "event_type": "SENTINEL_HIT",
                "sentinel_event_type": finding.event_type.value,
                "severity": finding.severity.value,
                "file_path": finding.file_path,
                "rule_id": finding.rule_id,
                "process_name": finding.process_name,
                "process_pid": finding.process_pid,
                "mitre_technique_id": finding.mitre_technique_id,
                "description": finding.description,
            }
            await kafka_producer.publish_network_event(event)
        except Exception:
            logger.warning("Failed to publish sentinel finding", exc_info=True)

    # ------------------------------------------------------------------
    # Manual scan API
    # ------------------------------------------------------------------

    async def scan_path(self, path: str) -> list[SentinelFinding]:
        """Manually scan a specific file or directory and return findings."""
        p = Path(path)
        results: list[SentinelFinding] = []

        if p.is_file():
            dlp_findings = await self._scan_file_content(p)
            for dlp in dlp_findings:
                finding = SentinelFinding(
                    event_type=SentinelEventType.SECRET_DETECTED,
                    severity=SentinelSeverity.CRITICAL,
                    file_path=str(p),
                    rule_id=dlp.get("rule_id", ""),
                    description=dlp.get("description", ""),
                    matched_text=dlp.get("matched_text", "")[:50],
                    mitre_technique_id="T1552.001",
                )
                results.append(finding)
                self._record_finding(finding)
        elif p.is_dir():
            try:
                for entry in p.iterdir():
                    if entry.is_file():
                        sub_results = await self.scan_path(str(entry))
                        results.extend(sub_results)
            except PermissionError:
                pass

        return results


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

filesystem_sentinel = FilesystemSentinel()
