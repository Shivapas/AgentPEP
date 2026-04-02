"""Escalation API — human escalation lifecycle endpoints (Sprint 9).

Provides REST endpoints for managing escalation tickets, approver groups,
and a WebSocket endpoint for real-time escalation event streaming.
"""

from uuid import UUID

from fastapi import APIRouter, HTTPException, WebSocket, status

from app.models.policy import (
    ApproverGroup,
    EscalationResolveRequest,
    EscalationState,
    EscalationTicket,
    NotificationConfig,
)
from app.services.escalation_manager import (
    APPROVER_GROUPS,
    escalation_manager,
)
from app.services.escalation_ws import escalation_ws_manager
from app.db import mongodb as db_module

router = APIRouter(prefix="/v1/escalation", tags=["escalation"])


# --- Ticket Endpoints ---


@router.get("/tickets/pending", response_model=list[EscalationTicket])
async def list_pending_tickets() -> list[EscalationTicket]:
    """List all PENDING escalation tickets."""
    return await escalation_manager.list_pending_tickets()


@router.get("/tickets/{ticket_id}", response_model=EscalationTicket)
async def get_ticket(ticket_id: UUID) -> EscalationTicket:
    """Get an escalation ticket by ID."""
    ticket = await escalation_manager.get_ticket(ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@router.post("/tickets/{ticket_id}/resolve", response_model=EscalationTicket)
async def resolve_ticket(ticket_id: UUID, body: EscalationResolveRequest) -> EscalationTicket:
    """Resolve (approve or deny) a PENDING escalation ticket."""
    if body.state not in (EscalationState.APPROVED, EscalationState.DENIED):
        raise HTTPException(
            status_code=400, detail="State must be APPROVED or DENIED"
        )
    # Ensure ticket_id in path matches body
    body.ticket_id = ticket_id
    ticket = await escalation_manager.resolve_ticket(body)
    if ticket is None:
        raise HTTPException(
            status_code=404,
            detail="Ticket not found or not in PENDING state",
        )
    return ticket


# --- Approver Group Endpoints (APEP-076) ---


@router.post("/approver-groups", response_model=ApproverGroup, status_code=201)
async def create_approver_group(group: ApproverGroup) -> ApproverGroup:
    """Create an approver group for escalation routing."""
    db = db_module.get_database()
    existing = await db[APPROVER_GROUPS].find_one({"group_id": group.group_id})
    if existing:
        raise HTTPException(status_code=409, detail="Group already exists")
    await db[APPROVER_GROUPS].insert_one(group.model_dump(mode="json"))
    return group


@router.get("/approver-groups", response_model=list[ApproverGroup])
async def list_approver_groups() -> list[ApproverGroup]:
    """List all approver groups."""
    db = db_module.get_database()
    groups = []
    async for doc in db[APPROVER_GROUPS].find({"enabled": True}):
        doc.pop("_id", None)
        groups.append(ApproverGroup(**doc))
    return groups


@router.delete(
    "/approver-groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_approver_group(group_id: str) -> None:
    """Delete an approver group."""
    db = db_module.get_database()
    result = await db[APPROVER_GROUPS].delete_one({"group_id": group_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Group not found")


# --- Notification Config ---


@router.put("/notifications/config", response_model=NotificationConfig)
async def update_notification_config(config: NotificationConfig) -> NotificationConfig:
    """Update email/Slack notification configuration."""
    escalation_manager.set_notification_config(config)
    return config


# --- WebSocket (APEP-074) ---


@router.websocket("/ws")
async def escalation_websocket(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time escalation event streaming.

    Policy Console clients connect here to receive ESCALATE events pushed
    as JSON messages whenever a ticket is created or resolved.
    """
    await escalation_ws_manager.connect(websocket)
    try:
        await escalation_ws_manager.listen(websocket)
    finally:
        await escalation_ws_manager.disconnect(websocket)
