"""POST /v1/scan — Programmatic network scan API.

Sprint 44 — APEP-355: Exposes a REST endpoint for URL, DLP, and injection
scanning.  Supports all scan kinds: url, dlp, injection, tool_call.

Sprint 52 — APEP-414/415/416/417: Adds ScanModeRouter (per-category mode
restrictions), CISTrustCache (content-hash bypass), CISAllowlist (permanent
safe-content bypass), and YOLO mode detection (auto-escalation to STRICT).
"""

from __future__ import annotations

import logging
import time

from fastapi import APIRouter

from app.models.network_scan import (
    NetworkScanRequest,
    NetworkScanResult,
    ScanFinding,
    ScanKind,
    ScanSeverity,
)
from app.services.cis_allowlist import cis_allowlist
from app.services.cis_trust_cache import cis_trust_cache
from app.services.network_dlp_scanner import network_dlp_scanner
from app.services.scan_mode_router import CISScanMode, scan_mode_router
from app.services.url_scanner import url_scanner
from app.services.yolo_mode_detector import yolo_detector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["scan"])


def _resolve_scan_mode(request: NetworkScanRequest) -> tuple[CISScanMode, bool]:
    """Determine the effective scan mode, applying YOLO auto-escalation.

    Returns (effective_mode, yolo_detected).
    """
    # Parse requested mode (default STRICT).
    try:
        mode = CISScanMode(request.scan_mode) if request.scan_mode else CISScanMode.STRICT
    except ValueError:
        mode = CISScanMode.STRICT

    # YOLO detection — check prompt text and metadata.
    yolo_detected = False
    yolo_result = yolo_detector.check_all(
        text=request.text or "",
        metadata=dict(request.metadata) if request.metadata else None,
        session_id=request.session_id,
    )
    if yolo_result.detected:
        yolo_detected = True
        mode = CISScanMode.STRICT  # auto-escalate
        logger.warning(
            "YOLO mode detected — auto-escalated to STRICT: %s",
            yolo_result.signals,
        )

    return mode, yolo_detected


@router.post("/scan", response_model=NetworkScanResult)
async def scan(request: NetworkScanRequest) -> NetworkScanResult:
    """Run a programmatic scan on a URL, text, or tool arguments.

    Dispatches to the appropriate scanner(s) based on ``scan_kind``.
    Sprint 52 enhancements: scan mode routing, trust cache, allowlist, YOLO detection.
    """
    start = time.monotonic()
    findings: list[ScanFinding] = []
    scanners_run: list[str] = []
    blocked = False
    cache_hit = False
    allowlisted = False

    # Sprint 52: Resolve effective scan mode with YOLO auto-escalation.
    effective_mode, yolo_detected = _resolve_scan_mode(request)

    if request.scan_kind == ScanKind.URL:
        # Run full 11-layer URL scanner
        if request.url:
            scanners_run.append("URLScanner")
            result = url_scanner.scan(request.url)
            findings.extend(result.findings)
            if result.blocked:
                blocked = True

    elif request.scan_kind == ScanKind.DLP:
        # Run DLP scanner on text and/or URL
        scanners_run.append("NetworkDLPScanner")
        if request.text:
            findings.extend(network_dlp_scanner.scan_text(request.text))
        if request.url:
            findings.extend(network_dlp_scanner.scan_url(request.url))
        if request.tool_args:
            findings.extend(network_dlp_scanner.scan_tool_args(request.tool_args))

    elif request.scan_kind == ScanKind.INJECTION:
        scanners_run.append("ScanModeRouter")
        text = request.text or ""
        tenant_id = request.tenant_id or ""

        # Sprint 52 — APEP-416: Check allowlist first (permanent bypass).
        if cis_allowlist.is_allowed(text, tenant_id=tenant_id):
            allowlisted = True
        # Sprint 52 — APEP-415: Check trust cache (TTL-based bypass).
        elif cis_trust_cache.is_trusted(text):
            cache_hit = True
        else:
            # Sprint 52 — APEP-414: Route through ScanModeRouter.
            matches = scan_mode_router.check(text, mode=effective_mode)
            for match in matches:
                findings.append(
                    ScanFinding(
                        rule_id=match.signature_id,
                        scanner="ScanModeRouter",
                        severity=ScanSeverity(match.severity),
                        description=match.description,
                        matched_text=text[:200],
                    )
                )
            # If clean, cache the result.
            if not findings:
                active_cats = scan_mode_router.active_categories(effective_mode)
                cis_trust_cache.mark_trusted(text, categories_checked=len(active_cats))

    elif request.scan_kind == ScanKind.TOOL_CALL:
        # Run DLP on tool arguments + URL scanner if URL present
        scanners_run.append("NetworkDLPScanner")
        if request.tool_args:
            findings.extend(network_dlp_scanner.scan_tool_args(request.tool_args))
        if request.url:
            scanners_run.append("URLScanner")
            result = url_scanner.scan(request.url)
            findings.extend(result.findings)
            if result.blocked:
                blocked = True

    # Determine if any findings cause a block (CRITICAL or HIGH severity)
    if not blocked:
        for f in findings:
            if f.severity in (ScanSeverity.CRITICAL, ScanSeverity.HIGH):
                blocked = True
                break

    # Taint assignment (if session_id provided and findings exist)
    taint_assigned: str | None = None
    if request.session_id and findings:
        from app.models.policy import TaintLevel

        max_sev = network_dlp_scanner.max_severity(findings)
        if max_sev in (ScanSeverity.CRITICAL, ScanSeverity.HIGH):
            taint_assigned = TaintLevel.QUARANTINE
        elif max_sev == ScanSeverity.MEDIUM:
            taint_assigned = TaintLevel.UNTRUSTED
        else:
            taint_assigned = TaintLevel.UNTRUSTED

        # Apply taint to session graph
        try:
            from app.services.taint_graph import session_graph_manager

            graph = session_graph_manager.get_or_create(request.session_id)
            if taint_assigned == TaintLevel.QUARANTINE:
                graph.add_node(
                    value=f"scan_finding:{findings[0].rule_id}",
                    taint_level=TaintLevel.QUARANTINE,
                    source="TOOL_OUTPUT",
                )
            elif taint_assigned == TaintLevel.UNTRUSTED:
                graph.add_node(
                    value=f"scan_finding:{findings[0].rule_id}",
                    taint_level=TaintLevel.UNTRUSTED,
                    source="TOOL_OUTPUT",
                )
        except Exception:
            logger.exception("Failed to apply taint from scan result")

    # Collect MITRE technique IDs
    mitre_ids = list({f.mitre_technique_id for f in findings if f.mitre_technique_id})

    elapsed_ms = int((time.monotonic() - start) * 1000)

    return NetworkScanResult(
        allowed=not blocked,
        blocked=blocked,
        findings=findings,
        scanners_run=scanners_run,
        taint_assigned=taint_assigned,
        mitre_technique_ids=mitre_ids,
        latency_ms=elapsed_ms,
        # Sprint 52 fields
        scan_mode_used=effective_mode.value,
        cache_hit=cache_hit,
        allowlisted=allowlisted,
        yolo_detected=yolo_detected,
    )
