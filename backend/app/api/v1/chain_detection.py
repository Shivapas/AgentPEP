"""Chain Detection API — Sprint 49 (APEP-393).

REST endpoints for chain pattern management, detection results,
and escalation handling.
"""

from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.models.tool_call_chain import (
    ChainDetectionResult,
    ChainEscalation,
    ChainEscalationListResponse,
    ChainEscalationResolveRequest,
    ChainPatternCreateRequest,
    ChainPatternListResponse,
    ChainPatternUpdateRequest,
    EscalationStatus,
    ToolCallChainPattern,
)
from app.services.chain_escalation import chain_escalation_manager
from app.services.chain_pattern_library import chain_pattern_library
from app.services.tool_call_chain_detector import tool_call_chain_detector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/chains", tags=["chain_detection"])


# ---------------------------------------------------------------------------
# Pattern management endpoints (APEP-393)
# ---------------------------------------------------------------------------


@router.get("/patterns", response_model=ChainPatternListResponse)
async def list_patterns(
    enabled_only: bool = Query(default=False, description="Filter to enabled patterns only"),
) -> ChainPatternListResponse:
    """List all chain patterns (built-in and custom)."""
    if enabled_only:
        patterns = chain_pattern_library.get_all_enabled()
    else:
        patterns = (
            chain_pattern_library.builtin_patterns
            + chain_pattern_library.custom_patterns
        )
    return ChainPatternListResponse(patterns=patterns, total=len(patterns))


@router.get("/patterns/{pattern_id}", response_model=ToolCallChainPattern)
async def get_pattern(pattern_id: str) -> ToolCallChainPattern:
    """Get a specific chain pattern by ID."""
    pattern = chain_pattern_library.get_pattern(pattern_id)
    if pattern is None:
        raise HTTPException(status_code=404, detail=f"Pattern {pattern_id} not found")
    return pattern


@router.post("/patterns", response_model=ToolCallChainPattern, status_code=201)
async def create_pattern(request: ChainPatternCreateRequest) -> ToolCallChainPattern:
    """Create a new custom chain pattern."""
    pattern = ToolCallChainPattern(
        name=request.name,
        description=request.description,
        steps=request.steps,
        category=request.category,
        severity=request.severity,
        action=request.action,
        match_strategy=request.match_strategy,
        window_seconds=request.window_seconds,
        risk_boost=request.risk_boost,
        mitre_technique_id=request.mitre_technique_id,
        enabled=request.enabled,
        builtin=False,
    )

    errors = chain_pattern_library.add_custom_pattern(pattern)
    if errors:
        raise HTTPException(
            status_code=422,
            detail={"errors": errors},
        )

    # Publish Kafka event
    try:
        from app.services.kafka_producer import kafka_producer

        await kafka_producer.publish_chain_event(
            event_type="CHAIN_PATTERN_CREATED",
            pattern_id=pattern.pattern_id,
            pattern_name=pattern.name,
        )
    except Exception:
        logger.warning("Failed to publish chain pattern creation event", exc_info=True)

    return pattern


@router.put("/patterns/{pattern_id}", response_model=ToolCallChainPattern)
async def update_pattern(
    pattern_id: str,
    request: ChainPatternUpdateRequest,
) -> ToolCallChainPattern:
    """Update an existing custom chain pattern."""
    updates = request.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")

    updated_pattern, errors = chain_pattern_library.update_custom_pattern(
        pattern_id, updates
    )
    if errors:
        raise HTTPException(
            status_code=422 if "Cannot update" not in errors[0] else 403,
            detail={"errors": errors},
        )
    if updated_pattern is None:
        raise HTTPException(status_code=404, detail=f"Pattern {pattern_id} not found")

    # Publish Kafka event
    try:
        from app.services.kafka_producer import kafka_producer

        await kafka_producer.publish_chain_event(
            event_type="CHAIN_PATTERN_UPDATED",
            pattern_id=pattern_id,
            pattern_name=updated_pattern.name,
        )
    except Exception:
        logger.warning("Failed to publish chain pattern update event", exc_info=True)

    return updated_pattern


@router.delete("/patterns/{pattern_id}")
async def delete_pattern(pattern_id: str) -> dict:
    """Delete a custom chain pattern.  Built-in patterns cannot be deleted."""
    deleted = chain_pattern_library.delete_custom_pattern(pattern_id)
    if not deleted:
        # Check if it's a built-in
        pattern = chain_pattern_library.get_pattern(pattern_id)
        if pattern is not None and pattern.builtin:
            raise HTTPException(
                status_code=403,
                detail="Built-in patterns cannot be deleted",
            )
        raise HTTPException(status_code=404, detail=f"Pattern {pattern_id} not found")

    # Publish Kafka event
    try:
        from app.services.kafka_producer import kafka_producer

        await kafka_producer.publish_chain_event(
            event_type="CHAIN_PATTERN_DELETED",
            pattern_id=pattern_id,
        )
    except Exception:
        logger.warning("Failed to publish chain pattern deletion event", exc_info=True)

    return {"status": "deleted", "pattern_id": pattern_id}


# ---------------------------------------------------------------------------
# Detection endpoints (APEP-391)
# ---------------------------------------------------------------------------


@router.post("/detect", response_model=ChainDetectionResult)
async def detect_chains(
    session_id: str = Query(..., description="Session ID to scan"),
    tool_name: str = Query(..., description="Current tool name"),
    agent_id: str = Query(default="", description="Agent ID"),
) -> ChainDetectionResult:
    """Run chain detection for a session's current tool call."""
    result = await tool_call_chain_detector.check_session(
        session_id=session_id,
        current_tool=tool_name,
        agent_id=agent_id,
    )
    return result


@router.get("/status")
async def chain_detection_status() -> dict:
    """Get chain detection system status."""
    tampered = chain_pattern_library.verify_builtin_integrity()
    return {
        "enabled_patterns": len(chain_pattern_library.get_all_enabled()),
        "builtin_patterns": len(chain_pattern_library.builtin_patterns),
        "custom_patterns": len(chain_pattern_library.custom_patterns),
        "total_patterns": chain_pattern_library.total_count,
        "integrity_check": "PASS" if not tampered else "FAIL",
        "tampered_patterns": tampered,
        "pending_escalations": chain_escalation_manager.pending_count,
    }


# ---------------------------------------------------------------------------
# Escalation endpoints (APEP-392)
# ---------------------------------------------------------------------------


@router.get("/escalations", response_model=ChainEscalationListResponse)
async def list_escalations(
    session_id: str | None = Query(default=None, description="Filter by session"),
    status: EscalationStatus | None = Query(default=None, description="Filter by status"),
    limit: int = Query(default=50, ge=1, le=200),
) -> ChainEscalationListResponse:
    """List chain detection escalations."""
    escalations = chain_escalation_manager.list_escalations(
        session_id=session_id,
        status=status,
        limit=limit,
    )
    return ChainEscalationListResponse(
        escalations=escalations, total=len(escalations)
    )


@router.get("/escalations/{escalation_id}", response_model=ChainEscalation)
async def get_escalation(escalation_id: UUID) -> ChainEscalation:
    """Get a specific chain escalation by ID."""
    escalation = chain_escalation_manager.get_escalation(escalation_id)
    if escalation is None:
        raise HTTPException(
            status_code=404,
            detail=f"Escalation {escalation_id} not found",
        )
    return escalation


@router.post("/escalations/{escalation_id}/resolve", response_model=ChainEscalation)
async def resolve_escalation(
    escalation_id: UUID,
    request: ChainEscalationResolveRequest,
) -> ChainEscalation:
    """Resolve a chain detection escalation."""
    if request.status not in (
        EscalationStatus.RESOLVED,
        EscalationStatus.FALSE_POSITIVE,
        EscalationStatus.DISMISSED,
    ):
        raise HTTPException(
            status_code=422,
            detail="Status must be RESOLVED, FALSE_POSITIVE, or DISMISSED",
        )

    resolved = chain_escalation_manager.resolve_escalation(
        escalation_id=escalation_id,
        status=request.status,
        resolution_note=request.resolution_note,
        resolved_by=request.resolved_by,
    )
    if resolved is None:
        raise HTTPException(
            status_code=404,
            detail=f"Escalation {escalation_id} not found",
        )
    return resolved


@router.post("/escalations/{escalation_id}/acknowledge", response_model=ChainEscalation)
async def acknowledge_escalation(escalation_id: UUID) -> ChainEscalation:
    """Acknowledge a pending chain detection escalation."""
    acknowledged = chain_escalation_manager.acknowledge_escalation(escalation_id)
    if acknowledged is None:
        raise HTTPException(
            status_code=404,
            detail=f"Escalation {escalation_id} not found",
        )
    return acknowledged
