"""POST /v1/scan — Programmatic network scan API.

Sprint 44 — APEP-355: Exposes a REST endpoint for URL, DLP, and injection
scanning.  Supports all scan kinds: url, dlp, injection, tool_call.
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
)
from app.services.injection_signatures import injection_library, MatchedSignature
from app.models.network_scan import ScanSeverity
from app.services.network_dlp_scanner import network_dlp_scanner
from app.services.url_scanner import url_scanner

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["scan"])


@router.post("/scan", response_model=NetworkScanResult)
async def scan(request: NetworkScanRequest) -> NetworkScanResult:
    """Run a programmatic scan on a URL, text, or tool arguments.

    Dispatches to the appropriate scanner(s) based on ``scan_kind``.
    """
    start = time.monotonic()
    findings: list[ScanFinding] = []
    scanners_run: list[str] = []
    blocked = False

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
        # Run injection signature check
        scanners_run.append("InjectionSignatureLibrary")
        text = request.text or ""
        matches = injection_library.check(text)
        for match in matches:
            findings.append(
                ScanFinding(
                    rule_id=match.signature_id,
                    scanner="InjectionSignatureLibrary",
                    severity=ScanSeverity(match.severity),
                    description=match.description,
                    matched_text=text[:200],
                )
            )

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
    )
