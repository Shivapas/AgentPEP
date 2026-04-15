"""Sprint 56 API Endpoints — YOLO Mode, Session Risk Multiplier & Developer Experience.

APEP-444: Per-session scan mode configuration endpoints.
APEP-445: YOLO mode session flag propagation endpoints.
APEP-448: CIS scan results to compliance export endpoints.
APEP-449: CIS Prometheus metrics status endpoint.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/sprint56", tags=["sprint56"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class SetScanModeRequest(BaseModel):
    """Request to set per-session scan mode."""

    session_id: str
    scan_mode: str = Field(default="STANDARD", description="STRICT, STANDARD, or LENIENT")
    reason: str = Field(default="", description="Reason for the mode change")
    risk_multiplier: float = Field(default=1.0, ge=0.1, le=10.0)
    lock: bool = Field(default=False, description="Lock the mode to prevent downgrade")


class YOLOPropagateRequest(BaseModel):
    """Request to propagate YOLO detection flags."""

    session_id: str
    signals: list[str] = Field(default_factory=list)
    risk_multiplier: float | None = Field(default=None, ge=1.0, le=10.0)
    source: str = Field(default="api", description="Source of the detection")


class YOLOCheckRequest(BaseModel):
    """Request to check for YOLO mode in content/metadata."""

    session_id: str
    text: str = Field(default="", description="Content to scan for YOLO signals")
    metadata: dict[str, Any] = Field(default_factory=dict)


class CISExportRequest(BaseModel):
    """Request for CIS compliance export."""

    template: str = Field(default="CIS_SECURITY")
    format: str = Field(default="json", description="json, csv, or pdf")
    session_id: str | None = None
    severity: str | None = None
    scanner: str | None = None
    limit: int = Field(default=500, ge=1, le=5000)


# ---------------------------------------------------------------------------
# APEP-444: Per-Session Scan Mode Configuration
# ---------------------------------------------------------------------------


@router.post("/session-config/scan-mode")
async def set_session_scan_mode(request: SetScanModeRequest) -> dict:
    """Set or update the per-session scan mode configuration."""
    from app.services.session_scan_config import session_scan_config

    config = await session_scan_config.set_mode(
        request.session_id,
        request.scan_mode,
        reason=request.reason,
        risk_multiplier=request.risk_multiplier,
        lock=request.lock,
    )
    return {
        "session_id": config.session_id,
        "scan_mode": config.scan_mode,
        "risk_multiplier": config.risk_multiplier,
        "locked": config.locked,
        "reason": config.reason,
    }


@router.get("/session-config/scan-mode")
async def get_session_scan_mode(
    session_id: str = Query(..., description="Session ID"),
) -> dict:
    """Get the current scan mode configuration for a session."""
    from app.services.session_scan_config import session_scan_config

    config = await session_scan_config.get_config(session_id)
    if not config:
        return {
            "session_id": session_id,
            "scan_mode": "STANDARD",
            "risk_multiplier": 1.0,
            "locked": False,
            "reason": "default",
        }
    return {
        "session_id": config.session_id,
        "scan_mode": config.scan_mode,
        "risk_multiplier": config.risk_multiplier,
        "locked": config.locked,
        "reason": config.reason,
    }


@router.get("/session-config/resolve")
async def resolve_session_scan_mode(
    session_id: str = Query(..., description="Session ID"),
    requested: str = Query(default="STANDARD", description="Requested scan mode"),
) -> dict:
    """Resolve the effective scan mode (considering session overrides)."""
    from app.services.session_scan_config import session_scan_config

    effective = await session_scan_config.resolve_mode(session_id, requested=requested)
    multiplier = await session_scan_config.get_risk_multiplier(session_id)
    return {
        "session_id": session_id,
        "requested_mode": requested,
        "effective_mode": effective,
        "risk_multiplier": multiplier,
    }


@router.get("/session-config/list")
async def list_session_configs(
    limit: int = Query(default=100, ge=1, le=1000),
    locked_only: bool = Query(default=False),
) -> dict:
    """List all active session scan configs."""
    from app.services.session_scan_config import session_scan_config

    result = await session_scan_config.list_configs(limit=limit, locked_only=locked_only)
    return result.model_dump(mode="json")


@router.delete("/session-config/{session_id}")
async def remove_session_config(session_id: str) -> dict:
    """Remove a session scan configuration."""
    from app.services.session_scan_config import session_scan_config

    deleted = await session_scan_config.remove_config(session_id)
    return {"session_id": session_id, "deleted": deleted}


# ---------------------------------------------------------------------------
# APEP-445: YOLO Mode Session Flag Propagation
# ---------------------------------------------------------------------------


@router.post("/yolo/check")
async def check_yolo_mode(request: YOLOCheckRequest) -> dict:
    """Check for YOLO mode and propagate if detected."""
    from app.services.yolo_session_propagator import yolo_session_propagator

    result = await yolo_session_propagator.check_and_propagate(
        session_id=request.session_id,
        text=request.text,
        metadata=request.metadata,
    )
    return result.model_dump(mode="json")


@router.post("/yolo/propagate")
async def propagate_yolo_flag(request: YOLOPropagateRequest) -> dict:
    """Explicitly propagate a YOLO flag for a session."""
    from app.services.yolo_session_propagator import yolo_session_propagator

    result = await yolo_session_propagator.propagate_flag(
        session_id=request.session_id,
        signals=request.signals,
        risk_multiplier=request.risk_multiplier,
        source=request.source,
    )
    return result.model_dump(mode="json")


@router.get("/yolo/status")
async def get_yolo_status(
    session_id: str = Query(..., description="Session ID"),
) -> dict:
    """Get the YOLO mode status for a session."""
    from app.services.yolo_session_propagator import yolo_session_propagator

    flag = yolo_session_propagator.get_flag(session_id)
    if not flag:
        return {
            "session_id": session_id,
            "yolo_detected": False,
            "risk_multiplier": 1.0,
            "locked": False,
        }
    return flag.model_dump(mode="json")


@router.get("/yolo/sessions")
async def list_yolo_sessions(
    limit: int = Query(default=100, ge=1, le=1000),
    active_only: bool = Query(default=True),
) -> dict:
    """List all sessions with YOLO mode flags."""
    from app.services.yolo_session_propagator import yolo_session_propagator

    result = await yolo_session_propagator.list_flags(
        limit=limit,
        active_only=active_only,
    )
    return result.model_dump(mode="json")


@router.delete("/yolo/{session_id}")
async def clear_yolo_flag(
    session_id: str,
    source: str = Query(default="admin"),
) -> dict:
    """Clear a YOLO flag (admin only)."""
    from app.services.yolo_session_propagator import yolo_session_propagator

    cleared = await yolo_session_propagator.clear_flag(
        session_id, source=source,
    )
    if not cleared:
        raise HTTPException(
            status_code=403,
            detail="Cannot clear locked YOLO flag without admin privileges",
        )
    return {"session_id": session_id, "cleared": True}


# ---------------------------------------------------------------------------
# APEP-448: CIS Scan Results to Compliance Exports
# ---------------------------------------------------------------------------


@router.post("/cis-export")
async def export_cis_findings(request: CISExportRequest) -> Any:
    """Export CIS findings in compliance-ready format."""
    from fastapi.responses import PlainTextResponse, Response

    from app.services.cis_compliance_export import CISExportQuery, cis_compliance_exporter

    query = CISExportQuery(
        template=request.template,
        session_id=request.session_id,
        severity=request.severity,
        scanner=request.scanner,
        limit=request.limit,
    )

    if request.format == "csv":
        csv_data = await cis_compliance_exporter.export_csv(query)
        return PlainTextResponse(
            content=csv_data,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="cis_findings_{request.template}.csv"'
            },
        )

    if request.format == "pdf":
        try:
            pdf_bytes = await cis_compliance_exporter.export_pdf(query)
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="cis_findings_{request.template}.pdf"'
                },
            )
        except ImportError:
            raise HTTPException(
                status_code=501,
                detail="PDF export requires reportlab: pip install reportlab",
            )

    # Default: JSON
    result = await cis_compliance_exporter.export_json(query)
    return result.model_dump(mode="json")


@router.get("/cis-export/templates")
async def list_export_templates() -> list[dict]:
    """List available CIS compliance export templates."""
    from app.services.cis_compliance_export import cis_compliance_exporter

    return cis_compliance_exporter.list_templates()


# ---------------------------------------------------------------------------
# APEP-449: CIS Prometheus Metrics Status
# ---------------------------------------------------------------------------


@router.get("/cis-dashboard")
async def cis_dashboard() -> dict:
    """Return aggregated CIS dashboard data for the frontend widget (APEP-447)."""
    from app.core.observability import CIS_DASHBOARD_QUERIES

    CIS_DASHBOARD_QUERIES.labels(widget="main").inc()

    summary = {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    yolo_data: dict = {"active_count": 0, "sessions": []}
    scan_mode_dist: dict = {"STRICT": 0, "STANDARD": 0, "LENIENT": 0}
    scanner_breakdown: dict = {}
    recent_findings: list = []

    # 1. Query findings summary from MongoDB
    try:
        from app.db.mongodb import get_database

        db = get_database()
        collection = db["cis_findings"]

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = await collection.count_documents({"severity": sev})
            summary[sev.lower()] = count
            summary["total_findings"] += count

        # Scanner breakdown
        for scanner_name in ("InjectionSignatureLibrary", "ONNXSemanticClassifier"):
            count = await collection.count_documents({"scanner": scanner_name})
            if count > 0:
                scanner_breakdown[scanner_name] = count

        # Scan mode distribution
        for mode in ("STRICT", "STANDARD", "LENIENT"):
            count = await collection.count_documents({"scan_mode": mode})
            scan_mode_dist[mode] = count

        # Recent findings
        cursor = collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(10)
        async for doc in cursor:
            recent_findings.append({
                "finding_id": str(doc.get("finding_id", "")),
                "severity": doc.get("severity", "MEDIUM"),
                "scanner": doc.get("scanner", ""),
                "rule_id": doc.get("rule_id", ""),
                "description": doc.get("description", ""),
                "timestamp": doc.get("timestamp", ""),
            })
    except Exception:
        logger.warning("Failed to query CIS dashboard data", exc_info=True)

    # 2. Query YOLO sessions
    try:
        from app.services.yolo_session_propagator import yolo_session_propagator

        yolo_result = await yolo_session_propagator.list_flags(limit=10, active_only=True)
        yolo_data["active_count"] = yolo_result.total
        yolo_data["sessions"] = [
            {
                "session_id": f.session_id,
                "risk_multiplier": f.risk_multiplier,
                "signals": f.signals[:3],
                "detected_at": f.propagated_at.isoformat() if f.propagated_at else "",
            }
            for f in yolo_result.flags
        ]
    except Exception:
        logger.debug("Failed to query YOLO sessions for dashboard")

    return {
        "summary": summary,
        "yolo_sessions": yolo_data,
        "scan_mode_distribution": scan_mode_dist,
        "scanner_breakdown": scanner_breakdown,
        "recent_findings": recent_findings,
    }


@router.get("/cis-metrics/status")
async def cis_metrics_status() -> dict:
    """Return a summary of CIS-related Prometheus metrics."""
    from app.core.observability import (
        CIS_FILE_SCAN_TOTAL,
        CIS_FINDINGS_TOTAL,
        CIS_POST_TOOL_SCAN_TOTAL,
        CIS_REPO_SCAN_TOTAL,
        CIS_SESSION_SCAN_TOTAL,
        ONNX_INFERENCE_TOTAL,
    )

    try:
        from app.core.observability import (
            CIS_YOLO_DETECTIONS,
            CIS_SESSION_CONFIG_CHANGES,
            CIS_COMPLIANCE_EXPORTS,
        )
        sprint56_metrics = {
            "yolo_detections": "active",
            "session_config_changes": "active",
            "compliance_exports": "active",
        }
    except ImportError:
        sprint56_metrics = {}

    return {
        "status": "active",
        "metrics": {
            "cis_repo_scan_total": "active",
            "cis_file_scan_total": "active",
            "cis_session_scan_total": "active",
            "cis_post_tool_scan_total": "active",
            "cis_findings_total": "active",
            "onnx_inference_total": "active",
            **sprint56_metrics,
        },
        "sprint": 56,
    }
