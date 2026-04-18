"""CaMeL SEQ, ToolTrust Bridge & Self-Protection endpoints — Sprint 55.

APEP-437.d: Session marker management API.
APEP-438.d: ToolTrust -> AgentPEP Intercept bridge endpoint.
APEP-439.d: CIS scan verdict as taint input endpoint.
APEP-440/441: Self-protection check and protected path endpoints.

Endpoints:
  POST /v1/camel/bridge/scan        — ToolTrust Layer 3 bridge scan
  POST /v1/camel/markers            — Place a session marker
  GET  /v1/camel/markers            — List markers for a session
  DELETE /v1/camel/markers           — Clear session markers
  POST /v1/camel/seq/evaluate       — Evaluate SEQ rules against a session
  GET  /v1/camel/seq/rules          — List all SEQ rules
  POST /v1/camel/verdict-taint      — Ingest CIS verdict as taint
  POST /v1/camel/self-protect/check — Check self-protection for an operation
  GET  /v1/camel/self-protect/audit — Get self-protection audit log
  POST /v1/camel/paths/check        — Check protected path
  GET  /v1/camel/paths              — List protected path patterns
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.core.observability import (
    CIS_VERDICT_TAINT_TOTAL,
    PROTECTED_PATH_BLOCKED_TOTAL,
    SELF_PROTECTION_BLOCKED_TOTAL,
    SEQ_DETECTION_LATENCY,
    SEQ_MARKERS_PLACED_TOTAL,
    SEQ_RULES_TRIGGERED_TOTAL,
    TOOLTRUST_BRIDGE_LATENCY,
    TOOLTRUST_BRIDGE_TOTAL,
)
from app.models.camel_seq import (
    BridgeScanRequest,
    BridgeScanResponse,
    CISVerdictTaintRequest,
    CISVerdictTaintResponse,
    CallerType,
    MarkerType,
    ProtectedOperation,
    ProtectedPathCheckRequest,
    ProtectedPathCheckResponse,
    SEQDetectionResult,
    SEQRule,
    SEQRuleMatch,
    SelfProtectionResult,
    SessionMarker,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/camel", tags=["camel-seq"])


# ---------------------------------------------------------------------------
# ToolTrust Bridge (APEP-438)
# ---------------------------------------------------------------------------


@router.post("/bridge/scan", response_model=BridgeScanResponse)
async def bridge_scan(request: BridgeScanRequest) -> BridgeScanResponse:
    """ToolTrust Layer 3 PreToolUse -> AgentPEP Intercept bridge.

    Receives a PreToolUse scan from ToolTrust, evaluates through AgentPEP's
    pipeline (markers + SEQ rules + taint), and returns a combined verdict.
    """
    from app.services.tooltrust_bridge import tooltrust_bridge

    result = await tooltrust_bridge.scan(request)

    TOOLTRUST_BRIDGE_TOTAL.labels(decision=result.decision).inc()
    TOOLTRUST_BRIDGE_LATENCY.observe(result.latency_ms / 1000.0)

    return result


# ---------------------------------------------------------------------------
# Session Markers (APEP-437)
# ---------------------------------------------------------------------------


class PlaceMarkerRequest(BaseModel):
    """Request to place a session marker."""

    session_id: str = Field(..., min_length=1)
    marker_type: MarkerType
    tool_name: str = Field(default="")
    agent_id: str = Field(default="")
    metadata: dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: int = Field(default=600, ge=30, le=86400)


class MarkerListResponse(BaseModel):
    """Response listing session markers."""

    session_id: str
    markers: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0


@router.post("/markers", response_model=dict[str, Any])
async def place_marker(request: PlaceMarkerRequest) -> dict[str, Any]:
    """Place a typed marker in a session."""
    from app.services.session_marker_store import session_marker_manager

    marker = session_marker_manager.place_marker(
        session_id=request.session_id,
        marker_type=request.marker_type,
        tool_name=request.tool_name,
        agent_id=request.agent_id,
        metadata=request.metadata,
        ttl_seconds=request.ttl_seconds,
    )

    SEQ_MARKERS_PLACED_TOTAL.labels(marker_type=request.marker_type.value).inc()

    return {
        "marker_id": str(marker.marker_id),
        "session_id": marker.session_id,
        "marker_type": marker.marker_type.value,
        "tool_name": marker.tool_name,
        "created_at": marker.created_at.isoformat(),
    }


@router.get("/markers", response_model=MarkerListResponse)
async def list_markers(
    session_id: str = Query(..., min_length=1),
    marker_type: MarkerType | None = None,
) -> MarkerListResponse:
    """List active markers for a session."""
    from app.services.session_marker_store import session_marker_manager

    markers = session_marker_manager.get_markers(
        session_id=session_id,
        marker_type=marker_type,
    )

    return MarkerListResponse(
        session_id=session_id,
        markers=[
            {
                "marker_id": str(m.marker_id),
                "marker_type": m.marker_type.value,
                "tool_name": m.tool_name,
                "agent_id": m.agent_id,
                "metadata": m.metadata,
                "created_at": m.created_at.isoformat(),
                "ttl_seconds": m.ttl_seconds,
            }
            for m in markers
        ],
        total=len(markers),
    )


@router.delete("/markers")
async def clear_markers(
    session_id: str = Query(..., min_length=1),
) -> dict[str, Any]:
    """Clear all markers for a session."""
    from app.services.session_marker_store import session_marker_manager

    count = session_marker_manager.clear_session(session_id)
    return {"session_id": session_id, "markers_cleared": count}


# ---------------------------------------------------------------------------
# SEQ Rule Evaluation (APEP-436)
# ---------------------------------------------------------------------------


class SEQEvaluateRequest(BaseModel):
    """Request to evaluate SEQ rules against a session."""

    session_id: str = Field(..., min_length=1)
    agent_id: str = Field(default="")


@router.post("/seq/evaluate", response_model=SEQDetectionResult)
async def evaluate_seq_rules(
    request: SEQEvaluateRequest,
) -> SEQDetectionResult:
    """Evaluate all enabled CaMeL-lite SEQ rules against session markers."""
    from app.services.camel_seq_engine import camel_seq_engine

    result = camel_seq_engine.evaluate_session(
        session_id=request.session_id,
        agent_id=request.agent_id,
    )

    SEQ_DETECTION_LATENCY.observe(result.scan_latency_us / 1_000_000)

    for match in result.matches:
        SEQ_RULES_TRIGGERED_TOTAL.labels(
            rule_id=match.rule_id,
            severity=match.severity.value,
        ).inc()

    return result


@router.get("/seq/rules")
async def list_seq_rules() -> list[dict[str, Any]]:
    """List all CaMeL-lite SEQ rules (built-in + custom)."""
    from app.services.camel_seq_engine import camel_seq_engine

    rules = camel_seq_engine.all_rules
    return [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "description": r.description,
            "severity": r.severity.value,
            "action": r.action.value,
            "steps": [
                {
                    "marker_type": s.marker_type.value,
                    "tool_patterns": s.tool_patterns,
                    "gap_tolerant": s.gap_tolerant,
                    "max_gap": s.max_gap,
                }
                for s in r.steps
            ],
            "risk_boost": r.risk_boost,
            "window_seconds": r.window_seconds,
            "enabled": r.enabled,
            "dry_run": r.dry_run,
            "builtin": r.builtin,
        }
        for r in rules
    ]


# ---------------------------------------------------------------------------
# CIS Verdict Taint (APEP-439)
# ---------------------------------------------------------------------------


@router.post("/verdict-taint", response_model=CISVerdictTaintResponse)
async def apply_verdict_taint(
    request: CISVerdictTaintRequest,
) -> CISVerdictTaintResponse:
    """Ingest a CIS scan verdict as a taint signal into the session graph."""
    from app.services.cis_verdict_taint import cis_verdict_taint_service

    result = cis_verdict_taint_service.apply_verdict(request)

    CIS_VERDICT_TAINT_TOTAL.labels(
        verdict=request.verdict,
        taint_level=result.taint_level or "none",
    ).inc()

    return result


# ---------------------------------------------------------------------------
# Self-Protection (APEP-440)
# ---------------------------------------------------------------------------


class SelfProtectCheckRequest(BaseModel):
    """Request to check self-protection for an operation."""

    operation: ProtectedOperation
    api_key: str = Field(default="")
    caller_type: CallerType | None = None
    is_tty: bool = False
    agent_id: str = Field(default="")
    session_id: str = Field(default="")


@router.post("/self-protect/check", response_model=SelfProtectionResult)
async def check_self_protection(
    request: SelfProtectCheckRequest,
) -> SelfProtectionResult:
    """Check whether an agent-initiated operation should be blocked."""
    from app.services.self_protection import self_protection_guard

    result = self_protection_guard.check(
        operation=request.operation,
        api_key=request.api_key,
        caller_type=request.caller_type,
        is_tty=request.is_tty,
        agent_id=request.agent_id,
        session_id=request.session_id,
    )

    if result.blocked:
        SELF_PROTECTION_BLOCKED_TOTAL.labels(
            operation=request.operation.value,
            caller_type=result.caller_type.value,
        ).inc()

    return result


@router.get("/self-protect/audit")
async def self_protection_audit(
    limit: int = Query(default=50, ge=1, le=500),
) -> dict[str, Any]:
    """Get recent self-protection audit events."""
    from app.services.self_protection import self_protection_guard

    events = self_protection_guard.get_audit_log(limit=limit)
    return {
        "events": [
            {
                "event_id": str(e.event_id),
                "operation": e.operation.value,
                "caller_type": e.caller_type.value,
                "api_key_id": e.api_key_id,
                "agent_id": e.agent_id,
                "session_id": e.session_id,
                "reason": e.reason,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in events
        ],
        "total_blocked": self_protection_guard.get_blocked_count(),
    }


# ---------------------------------------------------------------------------
# Protected Paths (APEP-441)
# ---------------------------------------------------------------------------


@router.post("/paths/check", response_model=ProtectedPathCheckResponse)
async def check_protected_path(
    request: ProtectedPathCheckRequest,
) -> ProtectedPathCheckResponse:
    """Check if a file path operation is blocked by protection rules."""
    from app.services.protected_path_guard import protected_path_guard

    result = protected_path_guard.check(request)

    if not result.allowed and result.matched_pattern:
        PROTECTED_PATH_BLOCKED_TOTAL.labels(
            pattern_id=result.matched_pattern,
            operation=request.operation,
        ).inc()

    return result


@router.get("/paths")
async def list_protected_paths() -> list[dict[str, Any]]:
    """List all protected path patterns (built-in + custom)."""
    from app.services.protected_path_guard import protected_path_guard

    return [
        {
            "pattern_id": p.pattern_id,
            "path_pattern": p.path_pattern,
            "description": p.description,
            "operations": p.operations,
            "enforcing": p.enforcing,
            "allow_human_override": p.allow_human_override,
            "enabled": p.enabled,
            "builtin": p.builtin,
        }
        for p in protected_path_guard.all_patterns
    ]
