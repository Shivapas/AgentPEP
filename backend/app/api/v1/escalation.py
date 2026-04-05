"""Escalation API — CRUD for escalation tickets and WebSocket real-time feed.

Sprint 18: APEP-143 (queue), APEP-144 (detail), APEP-145 (actions),
           APEP-146 (bulk approve), APEP-147 (SLA timer).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

from app.models.policy import (
    BulkApproveRequest,
    EscalationAction,
    EscalationStatus,
    EscalationTicket,
)
from app.services.escalation_manager import escalation_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/escalations", tags=["escalations"])


# ---------------------------------------------------------------------------
# Request / response helpers
# ---------------------------------------------------------------------------


class CreateEscalationRequest(BaseModel):
    session_id: str
    agent_id: str
    agent_role: str = ""
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    tool_args_hash: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    taint_flags: list[str] = Field(default_factory=list)
    delegation_chain: list[str] = Field(default_factory=list)
    matched_rule_id: UUID | None = None
    reason: str = ""
    sla_seconds: int | None = None


def _ticket_dict(t: EscalationTicket) -> dict[str, Any]:
    return t.model_dump(mode="json")


# ---------------------------------------------------------------------------
# APEP-143: Escalation queue — list PENDING tickets
# ---------------------------------------------------------------------------


@router.get("/pending")
async def list_pending() -> list[dict[str, Any]]:
    """Return all PENDING escalation tickets, newest first."""
    tickets = escalation_manager.list_pending()
    tickets.sort(key=lambda t: t.created_at, reverse=True)
    return [_ticket_dict(t) for t in tickets]


@router.get("/all")
async def list_all() -> list[dict[str, Any]]:
    """Return all escalation tickets regardless of status."""
    tickets = escalation_manager.list_all()
    tickets.sort(key=lambda t: t.created_at, reverse=True)
    return [_ticket_dict(t) for t in tickets]


# ---------------------------------------------------------------------------
# APEP-144: Escalation detail panel
# ---------------------------------------------------------------------------


@router.get("/{ticket_id}")
async def get_ticket(ticket_id: UUID) -> dict[str, Any]:
    """Return full detail for a single escalation ticket."""
    ticket = escalation_manager.get_ticket(ticket_id)
    if ticket is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Escalation ticket '{ticket_id}' not found",
        )
    return _ticket_dict(ticket)


# ---------------------------------------------------------------------------
# Create (normally called by policy evaluator on ESCALATE decisions)
# ---------------------------------------------------------------------------


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_ticket(request: CreateEscalationRequest) -> dict[str, Any]:
    """Create a new escalation ticket."""
    ticket = escalation_manager.create_ticket(
        session_id=request.session_id,
        agent_id=request.agent_id,
        agent_role=request.agent_role,
        tool_name=request.tool_name,
        tool_args=request.tool_args,
        tool_args_hash=request.tool_args_hash,
        risk_score=request.risk_score,
        taint_flags=request.taint_flags,
        delegation_chain=request.delegation_chain,
        matched_rule_id=request.matched_rule_id,
        reason=request.reason,
        sla_seconds=request.sla_seconds,
    )
    return _ticket_dict(ticket)


# ---------------------------------------------------------------------------
# APEP-145: Approve / deny / escalate-up actions
# ---------------------------------------------------------------------------


@router.post("/{ticket_id}/resolve")
async def resolve_ticket(ticket_id: UUID, body: EscalationAction) -> dict[str, Any]:
    """Approve, deny, or escalate-up a pending ticket."""
    if body.action not in (
        EscalationStatus.APPROVED,
        EscalationStatus.DENIED,
        EscalationStatus.ESCALATED_UP,
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid action '{body.action}'. Must be APPROVED, DENIED, or ESCALATED_UP.",
        )
    ticket = escalation_manager.resolve_ticket(
        ticket_id=ticket_id,
        action=body.action,
        comment=body.comment,
        resolved_by=body.resolved_by,
    )
    if ticket is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Escalation ticket '{ticket_id}' not found",
        )
    return _ticket_dict(ticket)


# ---------------------------------------------------------------------------
# APEP-146: Bulk approve
# ---------------------------------------------------------------------------


@router.post("/bulk-approve")
async def bulk_approve(body: BulkApproveRequest) -> dict[str, Any]:
    """Approve all PENDING tickets matching the given tool pattern."""
    resolved = escalation_manager.bulk_approve(
        tool_pattern=body.tool_pattern,
        comment=body.comment,
        resolved_by=body.resolved_by,
    )
    return {
        "approved_count": len(resolved),
        "ticket_ids": [str(t.ticket_id) for t in resolved],
    }


# ---------------------------------------------------------------------------
# APEP-147: SLA expiration check
# ---------------------------------------------------------------------------


@router.post("/check-sla")
async def check_sla() -> dict[str, Any]:
    """Trigger an SLA expiration check and auto-decide expired tickets."""
    expired = escalation_manager.check_sla_expirations()
    return {
        "expired_count": len(expired),
        "ticket_ids": [str(t.ticket_id) for t in expired],
    }


# ---------------------------------------------------------------------------
# APEP-143: WebSocket — real-time escalation feed
# ---------------------------------------------------------------------------


@router.websocket("/ws")
async def escalation_ws(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time escalation ticket updates.

    Clients connect and receive JSON messages whenever a ticket is created,
    resolved, bulk-approved, or SLA-expired.
    """
    await websocket.accept()
    queue = escalation_manager.subscribe()
    try:
        # Send current pending tickets as initial snapshot
        pending = escalation_manager.list_pending()
        await websocket.send_text(
            json.dumps({
                "type": "snapshot",
                "tickets": [_ticket_dict(t) for t in pending],
            })
        )

        while True:
            message = await queue.get()
            await websocket.send_text(json.dumps(message, default=str))
    except WebSocketDisconnect:
        logger.info("Escalation WebSocket client disconnected")
    except asyncio.CancelledError:
        pass
    finally:
        escalation_manager.unsubscribe(queue)
