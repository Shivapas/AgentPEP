"""CISSessionHook — scan-on-session-start hook.

Sprint 54 — APEP-430: Automatically scans the repository when an agent
session starts, applying taint labels to the session graph before the
agent executes any tool calls.

Flow:
  1. Agent session starts → hook fires.
  2. If repo_path is provided, run CISRepoScanner.
  3. Check instruction file results — if any HIGH/CRITICAL, mark session unsafe.
  4. Apply taint labels to the session graph.
  5. Emit Kafka CIS events.
  6. Return session scan result for the agent framework to act on.
"""

from __future__ import annotations

import logging
import time

from app.models.cis_scanner import (
    CISEvent,
    CISEventType,
    CISScanVerdict,
    RepoScanRequest,
    SessionStartScanRequest,
    SessionStartScanResult,
)
from app.services.cis_repo_scanner import CISRepoScanner, cis_repo_scanner

logger = logging.getLogger(__name__)


class CISSessionHook:
    """Pre-session hook that scans the repository before agent execution.

    Designed to be called by the agent framework's session-start lifecycle
    event.  Runs the full repo scanner and applies taint to the session.
    """

    def __init__(self, repo_scanner: CISRepoScanner | None = None) -> None:
        self._repo_scanner = repo_scanner or cis_repo_scanner

    def on_session_start(self, request: SessionStartScanRequest) -> SessionStartScanResult:
        """Run the pre-session scan and return the result.

        This method is synchronous and designed to block session start until
        the scan completes (target <50ms).
        """
        start = time.monotonic()

        repo_scan = None
        instruction_files_clean = True
        session_allowed = True
        taint_assigned: str | None = None

        # Run repo scan if repo_path is provided.
        if request.repo_path:
            repo_request = RepoScanRequest(
                repo_path=request.repo_path,
                session_id=request.session_id,
                agent_id=request.agent_id,
                scan_mode=request.scan_mode,
                tiers=request.tiers,
                max_files=request.max_files,
                tenant_id=request.tenant_id,
            )
            repo_scan = self._repo_scanner.scan(repo_request)

            # Check instruction file results.
            for file_result in repo_scan.file_results:
                if file_result.is_instruction_file and not file_result.allowed:
                    instruction_files_clean = False
                    break

            session_allowed = repo_scan.allowed
            taint_assigned = repo_scan.taint_assigned

        # Apply taint to session graph.
        if taint_assigned and request.session_id:
            self._apply_session_taint(
                session_id=request.session_id,
                taint_level=taint_assigned,
                scan_id=repo_scan.scan_id if repo_scan else None,
            )

        latency_ms = int((time.monotonic() - start) * 1000)

        return SessionStartScanResult(
            session_id=request.session_id,
            repo_scan=repo_scan,
            instruction_files_clean=instruction_files_clean,
            session_allowed=session_allowed,
            taint_assigned=taint_assigned,
            latency_ms=latency_ms,
        )

    def _apply_session_taint(
        self,
        session_id: str,
        taint_level: str,
        scan_id: object | None = None,
    ) -> None:
        """Apply taint label to the session graph."""
        try:
            from app.models.policy import TaintLevel
            from app.services.taint_graph import session_graph_manager

            graph = session_graph_manager.get_or_create(session_id)
            taint = (
                TaintLevel.QUARANTINE
                if taint_level == "QUARANTINE"
                else TaintLevel.UNTRUSTED
            )
            graph.add_node(
                value=f"cis_session_scan:{scan_id}" if scan_id else "cis_session_scan",
                taint_level=taint,
                source="TOOL_OUTPUT",
            )
            logger.info(
                "Applied session taint from pre-session scan",
                extra={
                    "session_id": session_id,
                    "taint_level": taint_level,
                    "scan_id": str(scan_id),
                },
            )
        except Exception:
            logger.exception("Failed to apply session taint from pre-session scan")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

cis_session_hook = CISSessionHook()
