"""CISPostToolScan — PostToolUse auto-scan (Layer 2).

Sprint 54 — APEP-431: Scans all tool output for injection after execution.
If injection is detected, auto-escalates severity and applies QUARANTINE
taint to the session graph.

Security architecture:
  - Scans tool output through the CIS pipeline (Tier 0 + Tier 1).
  - Auto-escalation: MEDIUM findings in tool output are escalated to HIGH.
  - Auto-taint: Any HIGH/CRITICAL finding triggers QUARANTINE on the session.
  - Crypto: Scan results are hashed for integrity verification.
  - Integration: Results feed into the PolicyEvaluator enforcement pipeline.
"""

from __future__ import annotations

import hashlib
import logging
import time
from uuid import uuid4

from app.models.cis_scanner import (
    CISEvent,
    CISEventType,
    CISFinding,
    CISScanVerdict,
    PostToolScanRequest,
    PostToolScanResult,
    PostToolScanTrigger,
)
from app.services.cis_pipeline import CISPipeline, CISPipelineResult, cis_pipeline

logger = logging.getLogger(__name__)


class CISPostToolScan:
    """PostToolUse auto-scanner.

    Scans tool output content through the CIS pipeline and auto-escalates
    findings when injection is detected in tool output.

    Parameters
    ----------
    pipeline:
        CIS pipeline instance for scanning.
    """

    def __init__(self, pipeline: CISPipeline | None = None) -> None:
        self._pipeline = pipeline or cis_pipeline

    def scan(self, request: PostToolScanRequest) -> PostToolScanResult:
        """Scan tool output and return the result with auto-escalation."""
        start = time.monotonic()
        scan_id = uuid4()

        # Run through CIS pipeline.
        pipeline_result: CISPipelineResult = self._pipeline.scan(
            text=request.tool_output,
            scan_mode=request.scan_mode,
            tiers=request.tiers,
            tenant_id=request.tenant_id,
            use_cache=True,
        )

        # Convert findings and apply auto-escalation.
        findings: list[CISFinding] = []
        escalated = False

        for f in pipeline_result.findings:
            severity = f.severity.value
            # Auto-escalate: MEDIUM → HIGH for tool output injection.
            if request.auto_escalate and severity == "MEDIUM":
                severity = "HIGH"
                escalated = True

            findings.append(
                CISFinding(
                    rule_id=f.rule_id,
                    scanner=f.scanner,
                    severity=severity,
                    description=f.description,
                    matched_text=f.matched_text[:200],
                    metadata={
                        "tool_name": request.tool_name,
                        "trigger": request.trigger.value,
                        "original_severity": f.severity.value,
                        "escalated": severity != f.severity.value,
                    },
                )
            )

        # Determine verdict.
        has_critical = any(f.severity == "CRITICAL" for f in findings)
        has_high = any(f.severity == "HIGH" for f in findings)
        has_blocking = has_critical or has_high

        verdict = CISScanVerdict.CLEAN
        if has_critical:
            verdict = CISScanVerdict.MALICIOUS
        elif has_high:
            verdict = CISScanVerdict.SUSPICIOUS

        # Taint assignment.
        taint_assigned: str | None = None
        if request.auto_taint and findings:
            if has_blocking:
                taint_assigned = "QUARANTINE"
            else:
                taint_assigned = "UNTRUSTED"

        # Apply taint to session graph.
        if taint_assigned and request.session_id:
            self._apply_taint(
                session_id=request.session_id,
                taint_level=taint_assigned,
                tool_name=request.tool_name,
                scan_id=scan_id,
            )

        latency_ms = int((time.monotonic() - start) * 1000)

        return PostToolScanResult(
            scan_id=scan_id,
            session_id=request.session_id,
            tool_name=request.tool_name,
            trigger=request.trigger,
            allowed=not has_blocking,
            verdict=verdict,
            findings=findings,
            scan_mode_applied=request.scan_mode,
            taint_assigned=taint_assigned,
            escalated=escalated,
            latency_ms=latency_ms,
        )

    def compute_result_hash(self, result: PostToolScanResult) -> str:
        """Compute SHA-256 hash of scan result for integrity verification."""
        content = (
            f"{result.scan_id}:{result.session_id}:{result.tool_name}"
            f":{result.verdict.value}:{len(result.findings)}"
            f":{result.taint_assigned or 'none'}"
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _apply_taint(
        self,
        session_id: str,
        taint_level: str,
        tool_name: str,
        scan_id: object,
    ) -> None:
        """Apply taint to the session graph from a post-tool scan finding."""
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
                value=f"cis_post_tool:{tool_name}:{scan_id}",
                taint_level=taint,
                source="TOOL_OUTPUT",
            )
            logger.info(
                "Applied taint from PostToolUse scan",
                extra={
                    "session_id": session_id,
                    "tool_name": tool_name,
                    "taint_level": taint_level,
                },
            )
        except Exception:
            logger.exception("Failed to apply taint from PostToolUse scan")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

cis_post_tool_scan = CISPostToolScan()
