"""Sprint 9 Escalation API — V1 async endpoints for escalation ticket management.

Routes under /v1/escalation/ for:
- APEP-073: Ticket CRUD (create/resolve/get/list)
- APEP-076: Approver group management
- APEP-078/079: Notification configuration
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.db import mongodb as db_module
from app.db.mongodb import APPROVER_GROUPS
from app.models.policy import (
    ApproverGroup,
    ApproverRoutingStrategy,
    EscalationResolveRequest,
    EscalationState,
    NotificationConfig,
)
from app.services.escalation_manager import escalation_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/escalation", tags=["escalation-v1"])


# --- Ticket endpoints ---


@router.get("/tickets/pending")
async def list_pending_tickets() -> list[dict[str, Any]]:
    """Return all PENDING escalation tickets."""
    tickets = await escalation_manager.list_pending_tickets()
    return [t.model_dump(mode="json") for t in tickets]


@router.get("/tickets/{ticket_id}")
async def get_ticket(ticket_id: UUID) -> dict[str, Any]:
    """Return a single ticket by ID."""
    ticket = await escalation_manager.get_ticket(ticket_id)
    if ticket is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket.model_dump(mode="json")


@router.post("/tickets/{ticket_id}/resolve")
async def resolve_ticket(ticket_id: UUID, body: EscalationResolveRequest) -> dict[str, Any]:
    """Resolve (approve/deny) a ticket."""
    if body.state == EscalationState.PENDING:
        raise HTTPException(status_code=400, detail="Cannot resolve to PENDING")
    resolved = await escalation_manager.resolve_ticket(body)
    if resolved is None:
        raise HTTPException(status_code=404, detail="Ticket not found or already resolved")
    return resolved.model_dump(mode="json")


# --- Approver Group endpoints ---


class ApproverGroupCreate(BaseModel):
    group_id: str
    name: str
    members: list[str] = Field(default_factory=list)
    strategy: ApproverRoutingStrategy = ApproverRoutingStrategy.ROUND_ROBIN
    on_call_user: str | None = None


@router.post("/approver-groups", status_code=201)
async def create_approver_group(body: ApproverGroupCreate) -> dict[str, Any]:
    db = db_module.get_database()
    existing = await db[APPROVER_GROUPS].find_one({"group_id": body.group_id})
    if existing:
        raise HTTPException(status_code=409, detail="Group already exists")
    group = ApproverGroup(**body.model_dump())
    await db[APPROVER_GROUPS].insert_one(group.model_dump(mode="json"))
    return group.model_dump(mode="json")


@router.get("/approver-groups")
async def list_approver_groups() -> list[dict[str, Any]]:
    db = db_module.get_database()
    cursor = db[APPROVER_GROUPS].find({})
    groups = []
    async for doc in cursor:
        doc.pop("_id", None)
        groups.append(doc)
    return groups


@router.delete("/approver-groups/{group_id}", status_code=204)
async def delete_approver_group(group_id: str) -> None:
    db = db_module.get_database()
    result = await db[APPROVER_GROUPS].delete_one({"group_id": group_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Group not found")


# --- Notification config endpoint ---


@router.put("/notifications/config")
async def update_notification_config(body: NotificationConfig) -> dict[str, Any]:
    escalation_manager.set_notification_config(body)
    return body.model_dump(mode="json")
