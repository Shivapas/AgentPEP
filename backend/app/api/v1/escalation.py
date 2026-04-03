"""Escalation API — real-time queue, approve/deny/bulk actions, WebSocket.

Sprint 18 — APEP-143 through APEP-150.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

from app.models.policy import Decision, EscalationStatus, EscalationTicket
from app.services.escalation_manager import escalation_manager

router = APIRouter(prefix="/v1/escalations", tags=["escalations"])


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class CreateEscalationRequest(BaseModel):
    """Request to create an escalation ticket."""

    request_id: UUID
    session_id: str
    agent_id: str
    agent_role: str = ""
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    taint_flags: list[str] = Field(default_factory=list)
    delegation_chain: list[str] = Field(default_factory=list)
    matched_rule_id: UUID | None = None
    reason: str = ""
    sla_seconds: int = Field(default=300, ge=30, description="SLA timeout in seconds")
    auto_decision: Decision = Decision.DENY


class ResolveEscalationRequest(BaseModel):
    """Request to approve, deny, or escalate-up a ticket (APEP-145)."""

    resolved_by: str
    comment: str = ""


class EscalateUpRequest(BaseModel):
    """Request to escalate a ticket to a higher-tier reviewer (APEP-145)."""

    resolved_by: str
    escalated_to: str
    comment: str = ""


class BulkApproveRequest(BaseModel):
    """Request to bulk-approve all PENDING tickets matching a tool pattern (APEP-146)."""

    tool_pattern: str
    resolved_by: str
    comment: str = ""


class EscalationResponse(BaseModel):
    escalation_id: UUID
    request_id: UUID
    session_id: str
    agent_id: str
    agent_role: str
    tool_name: str
    tool_args: dict[str, Any]
    risk_score: float
    taint_flags: list[str]
    delegation_chain: list[str]
    matched_rule_id: UUID | None
    reason: str
    status: EscalationStatus
    sla_deadline: str | None
    auto_decision: Decision
    resolved_by: str | None
    resolution_comment: str
    escalated_to: str | None
    created_at: str
    resolved_at: str | None


def _ticket_response(ticket: EscalationTicket) -> EscalationResponse:
    return EscalationResponse(
        escalation_id=ticket.escalation_id,
        request_id=ticket.request_id,
        session_id=ticket.session_id,
        agent_id=ticket.agent_id,
        agent_role=ticket.agent_role,
        tool_name=ticket.tool_name,
        tool_args=ticket.tool_args,
        risk_score=ticket.risk_score,
        taint_flags=ticket.taint_flags,
        delegation_chain=ticket.delegation_chain,
        matched_rule_id=ticket.matched_rule_id,
        reason=ticket.reason,
        status=ticket.status,
        sla_deadline=ticket.sla_deadline.isoformat() if ticket.sla_deadline else None,
        auto_decision=ticket.auto_decision,
        resolved_by=ticket.resolved_by,
        resolution_comment=ticket.resolution_comment,
        escalated_to=ticket.escalated_to,
        created_at=ticket.created_at.isoformat(),
        resolved_at=ticket.resolved_at.isoformat() if ticket.resolved_at else None,
    )


# ---------------------------------------------------------------------------
# WebSocket — real-time escalation queue (APEP-143)
# ---------------------------------------------------------------------------


@router.websocket("/ws")
async def escalation_ws(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time escalation queue updates."""
    await websocket.accept()
    escalation_manager.register_ws(websocket)
    try:
        # Send current pending tickets on connect
        pending = await escalation_manager.list_pending()
        import json

        await websocket.send_text(
            json.dumps(
                {
                    "event": "escalation:snapshot",
                    "data": [t.model_dump(mode="json") for t in pending],
                }
            )
        )
        # Keep connection alive until client disconnects
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        escalation_manager.unregister_ws(websocket)


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------


@router.post("", response_model=EscalationResponse, status_code=status.HTTP_201_CREATED)
async def create_escalation(request: CreateEscalationRequest) -> EscalationResponse:
    """Create a new escalation ticket (APEP-143)."""
    ticket = await escalation_manager.create_ticket(
        request_id=request.request_id,
        session_id=request.session_id,
        agent_id=request.agent_id,
        agent_role=request.agent_role,
        tool_name=request.tool_name,
        tool_args=request.tool_args,
        risk_score=request.risk_score,
        taint_flags=request.taint_flags,
        delegation_chain=request.delegation_chain,
        matched_rule_id=request.matched_rule_id,
        reason=request.reason,
        sla_seconds=request.sla_seconds,
        auto_decision=request.auto_decision,
    )
    return _ticket_response(ticket)


@router.get("", response_model=list[EscalationResponse])
async def list_escalations(
    status_filter: EscalationStatus | None = Query(default=None, alias="status"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[EscalationResponse]:
    """List escalation tickets, optionally filtered by status (APEP-143)."""
    tickets = await escalation_manager.list_all(
        status_filter=status_filter, limit=limit, offset=offset
    )
    return [_ticket_response(t) for t in tickets]


@router.get("/pending", response_model=list[EscalationResponse])
async def list_pending_escalations(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[EscalationResponse]:
    """List only PENDING escalation tickets (APEP-143)."""
    tickets = await escalation_manager.list_pending(limit=limit, offset=offset)
    return [_ticket_response(t) for t in tickets]


@router.get("/{escalation_id}", response_model=EscalationResponse)
async def get_escalation(escalation_id: UUID) -> EscalationResponse:
    """Get a single escalation ticket by ID (APEP-144)."""
    ticket = await escalation_manager.get_ticket(escalation_id)
    if ticket is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Escalation '{escalation_id}' not found",
        )
    return _ticket_response(ticket)


@router.post("/{escalation_id}/approve", response_model=EscalationResponse)
async def approve_escalation(
    escalation_id: UUID, request: ResolveEscalationRequest
) -> EscalationResponse:
    """Approve an escalation ticket (APEP-145)."""
    ticket = await escalation_manager.approve(
        escalation_id, resolved_by=request.resolved_by, comment=request.comment
    )
    if ticket is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Escalation '{escalation_id}' not found or already resolved",
        )
    return _ticket_response(ticket)


@router.post("/{escalation_id}/deny", response_model=EscalationResponse)
async def deny_escalation(
    escalation_id: UUID, request: ResolveEscalationRequest
) -> EscalationResponse:
    """Deny an escalation ticket (APEP-145)."""
    ticket = await escalation_manager.deny(
        escalation_id, resolved_by=request.resolved_by, comment=request.comment
    )
    if ticket is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Escalation '{escalation_id}' not found or already resolved",
        )
    return _ticket_response(ticket)


@router.post("/{escalation_id}/escalate-up", response_model=EscalationResponse)
async def escalate_up(
    escalation_id: UUID, request: EscalateUpRequest
) -> EscalationResponse:
    """Escalate a ticket to a higher-tier reviewer (APEP-145)."""
    ticket = await escalation_manager.escalate_up(
        escalation_id,
        resolved_by=request.resolved_by,
        escalated_to=request.escalated_to,
        comment=request.comment,
    )
    if ticket is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Escalation '{escalation_id}' not found or already resolved",
        )
    return _ticket_response(ticket)


@router.post("/bulk-approve", response_model=list[EscalationResponse])
async def bulk_approve_escalations(request: BulkApproveRequest) -> list[EscalationResponse]:
    """Bulk-approve all PENDING escalations matching a tool pattern (APEP-146)."""
    tickets = await escalation_manager.bulk_approve(
        tool_pattern=request.tool_pattern,
        resolved_by=request.resolved_by,
        comment=request.comment,
    )
    return [_ticket_response(t) for t in tickets]


@router.post("/process-sla")
async def process_sla() -> dict[str, Any]:
    """Manually trigger SLA expiry processing (APEP-147)."""
    resolved = await escalation_manager.process_expired_sla()
    return {
        "processed": len(resolved),
        "tickets": [_ticket_response(t) for t in resolved],
    }
