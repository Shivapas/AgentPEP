"""Sprint 55 API Endpoints — CaMeL SEQ Rules, Layer 3 Bridge & Self-Protection.

APEP-437.d: Session marker management endpoints.
APEP-438.d: ToolTrust → AgentPEP Intercept bridge endpoints.
APEP-439.d: CIS scan verdict taint endpoints.
APEP-440:   Self-protection guard endpoints.
APEP-441:   Protected path pattern endpoints.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query

from app.models.camel_seq import (
    CISVerdictTaintRequest,
    CISVerdictTaintResponse,
    MarkerType,
    ProtectedPathCheckResult,
    ProtectedPathListResponse,
    ProtectedPathPattern,
    SEQDetectionResult,
    SelfProtectionCheckRequest,
    SelfProtectionCheckResponse,
    SessionMarkerListResponse,
    SessionMarkerQuery,
    ToolTrustBridgeRequest,
    ToolTrustBridgeResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/sprint55", tags=["sprint55"])


# ---------------------------------------------------------------------------
# APEP-437.d: Session Marker Management
# ---------------------------------------------------------------------------


@router.get("/markers", response_model=SessionMarkerListResponse)
async def list_session_markers(
    session_id: str = Query(..., description="Session ID"),
    marker_type: MarkerType | None = Query(default=None, description="Filter by marker type"),
    limit: int = Query(default=100, ge=1, le=1000),
) -> SessionMarkerListResponse:
    """List session markers for a given session."""
    from app.services.session_marker_service import session_marker_service

    query = SessionMarkerQuery(
        session_id=session_id,
        marker_types=[marker_type] if marker_type else None,
        limit=limit,
    )
    return await session_marker_service.get_markers(query)


@router.post("/markers/evaluate", response_model=SEQDetectionResult)
async def evaluate_seq_rules(
    session_id: str = Query(..., description="Session ID to evaluate"),
) -> SEQDetectionResult:
    """Evaluate CaMeL-lite SEQ rules against session markers."""
    from app.services.camel_seq_rules import evaluate_seq_markers
    from app.services.session_marker_service import session_marker_service

    markers = await session_marker_service.get_ordered_markers(session_id)
    return await evaluate_seq_markers(session_id, markers)


@router.delete("/markers/{session_id}")
async def clear_session_markers(session_id: str) -> dict:
    """Clear all markers for a session (admin operation)."""
    from app.services.session_marker_service import session_marker_service

    count = await session_marker_service.clear_session(session_id)
    return {"session_id": session_id, "deleted": count}


# ---------------------------------------------------------------------------
# APEP-438.d: ToolTrust → AgentPEP Intercept Bridge
# ---------------------------------------------------------------------------


@router.post("/bridge/tooltrust", response_model=ToolTrustBridgeResponse)
async def tooltrust_bridge_endpoint(
    request: ToolTrustBridgeRequest,
) -> ToolTrustBridgeResponse:
    """Accept a ToolTrust Layer 3 verdict and apply it as a taint signal.

    This endpoint is called by ToolTrust PreToolUse hooks to bridge
    scan verdicts into the AgentPEP Intercept pipeline.
    """
    from app.services.tooltrust_bridge import tooltrust_bridge

    return await tooltrust_bridge.process_verdict(request)


@router.get("/bridge/tooltrust/events")
async def list_bridge_events(
    session_id: str = Query(..., description="Session ID"),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    """List ToolTrust bridge events for a session."""
    from app.services.tooltrust_bridge import tooltrust_bridge

    return await tooltrust_bridge.get_bridge_events(session_id, limit=limit)


# ---------------------------------------------------------------------------
# APEP-439.d: CIS Scan Verdict as Taint Input
# ---------------------------------------------------------------------------


@router.post("/cis-verdict/taint", response_model=CISVerdictTaintResponse)
async def apply_cis_verdict_taint(
    request: CISVerdictTaintRequest,
) -> CISVerdictTaintResponse:
    """Apply a CIS scan verdict as a taint signal to a session."""
    from app.services.cis_verdict_taint import cis_verdict_taint_service

    return await cis_verdict_taint_service.apply_verdict(request)


@router.get("/cis-verdict/events")
async def list_cis_verdict_events(
    session_id: str = Query(..., description="Session ID"),
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict]:
    """List CIS verdict-taint events for a session."""
    from app.services.cis_verdict_taint import cis_verdict_taint_service

    return await cis_verdict_taint_service.get_verdict_events(session_id, limit=limit)


# ---------------------------------------------------------------------------
# APEP-440: Self-Protection Guard
# ---------------------------------------------------------------------------


@router.post("/self-protection/check", response_model=SelfProtectionCheckResponse)
async def check_self_protection(
    request: SelfProtectionCheckRequest,
) -> SelfProtectionCheckResponse:
    """Check whether an operation is allowed by self-protection guards."""
    from app.services.self_protection import self_protection_guard

    response = self_protection_guard.check(request)
    await self_protection_guard.audit_event(request, response)
    return response


@router.post("/self-protection/check-command", response_model=SelfProtectionCheckResponse)
async def check_command_self_protection(
    command: str = Query(..., description="Command to check"),
    caller_type: str = Query(default="agent", description="Caller type"),
) -> SelfProtectionCheckResponse:
    """Check whether a CLI/hook command is blocked by self-protection."""
    from app.services.self_protection import self_protection_guard

    return self_protection_guard.check_command(command, caller_type)


@router.get("/self-protection/events")
async def list_self_protection_events(
    limit: int = Query(default=50, ge=1, le=500),
    blocked_only: bool = Query(default=False),
) -> list[dict]:
    """List self-protection audit events."""
    from app.services.self_protection import self_protection_guard

    events = await self_protection_guard.get_events(limit=limit, blocked_only=blocked_only)
    return [e.model_dump(mode="json") for e in events]


# ---------------------------------------------------------------------------
# APEP-441: Protected Path Patterns
# ---------------------------------------------------------------------------


@router.get("/protected-paths", response_model=ProtectedPathListResponse)
async def list_protected_paths() -> ProtectedPathListResponse:
    """List all protected path patterns (built-in and custom)."""
    from app.services.protected_path_guard import protected_path_guard

    return protected_path_guard.get_all_patterns()


@router.post("/protected-paths/check", response_model=ProtectedPathCheckResult)
async def check_protected_path(
    tool_name: str = Query(..., description="Tool being invoked"),
    path: str = Query(..., description="File/resource path"),
) -> ProtectedPathCheckResult:
    """Check a tool call path against protected path patterns."""
    from app.services.protected_path_guard import protected_path_guard

    return protected_path_guard.check(tool_name, path)


@router.post("/protected-paths", response_model=ProtectedPathPattern)
async def add_protected_path(
    pattern: ProtectedPathPattern,
) -> ProtectedPathPattern:
    """Add a custom protected path pattern."""
    from app.services.protected_path_guard import protected_path_guard

    errors = protected_path_guard.add_custom_pattern(pattern)
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))
    return pattern


@router.delete("/protected-paths/{pattern_id}")
async def remove_protected_path(pattern_id: str) -> dict:
    """Remove a custom protected path pattern."""
    from app.services.protected_path_guard import protected_path_guard

    if not protected_path_guard.remove_custom_pattern(pattern_id):
        raise HTTPException(
            status_code=404,
            detail=f"Pattern '{pattern_id}' not found or is built-in",
        )
    return {"deleted": pattern_id}


# ---------------------------------------------------------------------------
# SEQ Pattern listing (read-only view of CaMeL-lite patterns)
# ---------------------------------------------------------------------------


@router.get("/seq-rules")
async def list_seq_rules() -> list[dict]:
    """List all CaMeL-lite SEQ rules and their modes."""
    from app.services.camel_seq_rules import CAMEL_SEQ_PATTERNS, _SEQ_MODES

    return [
        {
            "pattern_id": p.pattern_id,
            "name": p.name,
            "description": p.description,
            "severity": p.severity.value,
            "action": p.action.value,
            "mode": _SEQ_MODES.get(p.pattern_id, "ADVISORY"),
            "enabled": p.enabled,
            "category": p.category.value,
            "mitre_technique_id": p.mitre_technique_id,
        }
        for p in CAMEL_SEQ_PATTERNS
    ]
