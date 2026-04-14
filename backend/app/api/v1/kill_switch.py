"""Kill Switch API — Sprint 50 (APEP-396.d/398/401.d).

REST endpoints for the kill switch, filesystem sentinel status,
and adaptive threat score.

APEP-398: The kill switch endpoint is also served on an isolated port
(default 8890) so that enterprise firewalls blocking the main port
cannot prevent emergency kill switch activation.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query

from app.models.kill_switch import (
    AdaptiveThreatScoreResult,
    DeescalationTimerStatus,
    KillSwitchActivateRequest,
    KillSwitchDeactivateRequest,
    KillSwitchSource,
    KillSwitchStatus,
    SentinelStatus,
    ThreatScoreRequest,
)
from app.services.adaptive_threat_score import adaptive_threat_score
from app.services.filesystem_sentinel import filesystem_sentinel
from app.services.kill_switch import kill_switch_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["kill_switch"])


# ---------------------------------------------------------------------------
# Kill Switch endpoints (APEP-396.d)
# ---------------------------------------------------------------------------


@router.post("/killswitch/activate", response_model=KillSwitchStatus)
async def activate_kill_switch(
    request: KillSwitchActivateRequest,
) -> KillSwitchStatus:
    """Activate the emergency kill switch via API endpoint.

    This is activation source 1 of 4.  When activated, ALL policy
    evaluations immediately return DENY (FAIL_CLOSED).
    """
    status = await kill_switch_service.activate(
        source=KillSwitchSource.API_ENDPOINT,
        reason=request.reason,
        activated_by=request.activated_by,
    )
    return status


@router.post("/killswitch/deactivate", response_model=KillSwitchStatus)
async def deactivate_kill_switch(
    request: KillSwitchDeactivateRequest,
) -> KillSwitchStatus:
    """Deactivate the kill switch API endpoint source.

    The kill switch only fully deactivates when ALL sources are cleared.
    """
    status = await kill_switch_service.deactivate(
        source=KillSwitchSource.API_ENDPOINT,
        reason=request.reason,
        deactivated_by=request.deactivated_by,
    )
    return status


@router.post("/killswitch/force-deactivate", response_model=KillSwitchStatus)
async def force_deactivate_kill_switch(
    request: KillSwitchDeactivateRequest,
) -> KillSwitchStatus:
    """Force-deactivate the kill switch from ALL sources."""
    status = await kill_switch_service.force_deactivate(
        reason=request.reason,
        deactivated_by=request.deactivated_by,
    )
    return status


@router.get("/killswitch/status", response_model=KillSwitchStatus)
async def get_kill_switch_status() -> KillSwitchStatus:
    """Get current kill switch status."""
    return kill_switch_service.get_status()


# ---------------------------------------------------------------------------
# Filesystem Sentinel endpoints (APEP-399)
# ---------------------------------------------------------------------------


@router.get("/sentinel/status", response_model=SentinelStatus)
async def get_sentinel_status() -> SentinelStatus:
    """Get current filesystem sentinel status."""
    return filesystem_sentinel.get_status()


@router.get("/sentinel/findings")
async def list_sentinel_findings(
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    """List recent filesystem sentinel findings."""
    findings = filesystem_sentinel.findings[-limit:]
    return {
        "findings": [f.model_dump(mode="json") for f in findings],
        "total": filesystem_sentinel.findings_count,
    }


@router.post("/sentinel/scan")
async def trigger_sentinel_scan(
    path: str = Query(..., description="File or directory path to scan"),
) -> dict:
    """Manually trigger a sentinel scan on a specific path."""
    findings = await filesystem_sentinel.scan_path(path)
    return {
        "path": path,
        "findings": [f.model_dump(mode="json") for f in findings],
        "total": len(findings),
    }


# ---------------------------------------------------------------------------
# Adaptive Threat Score endpoints (APEP-401.d)
# ---------------------------------------------------------------------------


@router.post("/threat-score", response_model=AdaptiveThreatScoreResult)
async def get_threat_score(
    request: ThreatScoreRequest,
) -> AdaptiveThreatScoreResult:
    """Get or compute the adaptive threat score for a session."""
    return adaptive_threat_score.get_score(
        session_id=request.session_id,
        agent_id=request.agent_id,
        include_signals=request.include_signals,
    )


@router.get("/threat-score/{session_id}", response_model=AdaptiveThreatScoreResult)
async def get_session_threat_score(
    session_id: str,
    include_signals: bool = Query(default=False),
) -> AdaptiveThreatScoreResult:
    """Get the adaptive threat score for a specific session."""
    return adaptive_threat_score.get_score(
        session_id=session_id,
        include_signals=include_signals,
    )


# ---------------------------------------------------------------------------
# De-escalation timer endpoints (APEP-402)
# ---------------------------------------------------------------------------


@router.get("/threat-score/{session_id}/deescalation", response_model=DeescalationTimerStatus)
async def get_deescalation_status(session_id: str) -> DeescalationTimerStatus:
    """Get de-escalation timer status for a session."""
    return adaptive_threat_score.get_deescalation_status(session_id)


@router.post("/threat-score/{session_id}/deescalation")
async def create_deescalation_timer(
    session_id: str,
    decay_rate: float = Query(default=0.1, ge=0.01, le=1.0),
    interval_seconds: int = Query(default=60, ge=10, le=3600),
    target_score: float = Query(default=0.0, ge=0.0, le=1.0),
) -> dict:
    """Create a de-escalation timer for a session."""
    timer = adaptive_threat_score.create_deescalation_timer(
        session_id=session_id,
        decay_rate=decay_rate,
        interval_seconds=interval_seconds,
        target_score=target_score,
    )
    return timer.model_dump(mode="json")


@router.delete("/threat-score/{session_id}/deescalation")
async def cancel_deescalation_timers(
    session_id: str,
    reason: str = Query(default="Manual cancellation"),
) -> dict:
    """Cancel all active de-escalation timers for a session."""
    cancelled = adaptive_threat_score.cancel_deescalation_timers(session_id, reason)
    return {"session_id": session_id, "cancelled": cancelled}
