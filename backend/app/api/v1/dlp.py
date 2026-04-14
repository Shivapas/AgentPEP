"""DLP Pre-Scan API — Sprint 45 (APEP-356.d).

Exposes endpoints for manual DLP scanning and pattern management.
The primary DLP integration is via the DLPPreScanStage in the
PolicyEvaluator pipeline (transparent to the /v1/intercept caller).
"""

import time

from fastapi import APIRouter

from app.core.config import settings
from app.core.observability import (
    DLP_SCAN_LATENCY,
    DLP_SCAN_TOTAL,
    DLP_PATTERN_RELOADS,
    get_tracer,
)
from app.models.policy import DLPScanRequest, DLPScanResult
from app.services.network_dlp import network_dlp_scanner

router = APIRouter(prefix="/v1/dlp", tags=["dlp"])

tracer = get_tracer(__name__)


@router.post("/scan", response_model=DLPScanResult)
async def scan_tool_args(request: DLPScanRequest) -> DLPScanResult:
    """Scan tool arguments for sensitive data using DLP patterns.

    This endpoint provides an explicit scan API.  The same scanning logic
    is automatically invoked as a pre-evaluation stage in the intercept
    pipeline when ``dlp_pre_scan_enabled`` is True.
    """
    with tracer.start_as_current_span(
        "dlp_scan",
        attributes={
            "agentpep.session_id": request.session_id,
            "agentpep.agent_id": request.agent_id,
            "agentpep.tool_name": request.tool_name,
        },
    ):
        start = time.monotonic()
        result = network_dlp_scanner.scan_tool_args(request.tool_args)
        elapsed = time.monotonic() - start

        DLP_SCAN_LATENCY.observe(elapsed)
        if result.has_findings:
            for finding in result.findings:
                DLP_SCAN_TOTAL.labels(
                    result="hit",
                    pattern_type=finding.pattern_type.value,
                ).inc()
        else:
            DLP_SCAN_TOTAL.labels(result="miss", pattern_type="none").inc()

        return result


@router.post("/patterns/reload")
async def reload_patterns() -> dict:
    """Hot-reload DLP patterns from MongoDB (APEP-363).

    Merges custom patterns from the ``dlp_patterns`` collection with
    built-in patterns.  Invalidates the scan cache after reload.
    """
    try:
        version = await network_dlp_scanner.reload_patterns()
        DLP_PATTERN_RELOADS.labels(status="success").inc()
        return {
            "status": "ok",
            "version": version,
            "pattern_count": len(network_dlp_scanner.registry.patterns),
        }
    except Exception as exc:
        DLP_PATTERN_RELOADS.labels(status="error").inc()
        return {
            "status": "error",
            "detail": str(exc),
        }


@router.get("/status")
async def dlp_status() -> dict:
    """Return current DLP scanner status and configuration."""
    return {
        "enabled": settings.dlp_pre_scan_enabled,
        "cache_enabled": settings.dlp_cache_enabled,
        "cache_size": network_dlp_scanner.cache.size,
        "pattern_count": len(network_dlp_scanner.registry.patterns),
        "pattern_version": network_dlp_scanner.registry.version,
        "risk_elevation_enabled": settings.dlp_risk_elevation_enabled,
        "taint_assignment_enabled": settings.dlp_taint_assignment_enabled,
    }
