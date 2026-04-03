"""Escalation ticket manager — CRUD, WebSocket broadcast, SLA auto-decision.

Sprint 18 — APEP-143 through APEP-150.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.db.mongodb import ESCALATION_TICKETS, get_database
from app.models.policy import (
    Decision,
    EscalationStatus,
    EscalationTicket,
)

logger = logging.getLogger(__name__)


class EscalationManager:
    """Manages escalation ticket lifecycle and WebSocket notifications."""

    def __init__(self) -> None:
        self._ws_clients: set[Any] = set()  # active WebSocket connections
        self._sla_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # WebSocket client management
    # ------------------------------------------------------------------

    def register_ws(self, ws: Any) -> None:
        self._ws_clients.add(ws)

    def unregister_ws(self, ws: Any) -> None:
        self._ws_clients.discard(ws)

    async def _broadcast(self, event: str, payload: dict[str, Any]) -> None:
        """Send JSON message to all connected WebSocket clients."""
        import json

        message = json.dumps({"event": event, "data": payload})
        dead: list[Any] = []
        for ws in self._ws_clients:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._ws_clients.discard(ws)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create_ticket(
        self,
        *,
        request_id: UUID,
        session_id: str,
        agent_id: str,
        agent_role: str = "",
        tool_name: str,
        tool_args: dict[str, Any] | None = None,
        risk_score: float = 0.0,
        taint_flags: list[str] | None = None,
        delegation_chain: list[str] | None = None,
        matched_rule_id: UUID | None = None,
        reason: str = "",
        sla_seconds: int = 300,
        auto_decision: Decision = Decision.DENY,
    ) -> EscalationTicket:
        """Create a new PENDING escalation ticket and broadcast to WS clients."""
        ticket = EscalationTicket(
            request_id=request_id,
            session_id=session_id,
            agent_id=agent_id,
            agent_role=agent_role,
            tool_name=tool_name,
            tool_args=tool_args or {},
            risk_score=risk_score,
            taint_flags=taint_flags or [],
            delegation_chain=delegation_chain or [],
            matched_rule_id=matched_rule_id,
            reason=reason,
            sla_deadline=datetime.utcnow() + timedelta(seconds=sla_seconds),
            auto_decision=auto_decision,
        )
        db = get_database()
        await db[ESCALATION_TICKETS].insert_one(
            ticket.model_dump(mode="json")
        )
        await self._broadcast("escalation:created", ticket.model_dump(mode="json"))
        return ticket

    async def get_ticket(self, escalation_id: UUID) -> EscalationTicket | None:
        db = get_database()
        doc = await db[ESCALATION_TICKETS].find_one({"escalation_id": str(escalation_id)})
        if doc is None:
            return None
        doc.pop("_id", None)
        return EscalationTicket(**doc)

    async def list_pending(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EscalationTicket]:
        db = get_database()
        cursor = (
            db[ESCALATION_TICKETS]
            .find({"status": EscalationStatus.PENDING.value})
            .sort("created_at", -1)
            .skip(offset)
            .limit(limit)
        )
        tickets: list[EscalationTicket] = []
        async for doc in cursor:
            doc.pop("_id", None)
            tickets.append(EscalationTicket(**doc))
        return tickets

    async def list_all(
        self,
        *,
        status_filter: EscalationStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[EscalationTicket]:
        db = get_database()
        query: dict[str, Any] = {}
        if status_filter is not None:
            query["status"] = status_filter.value
        cursor = (
            db[ESCALATION_TICKETS]
            .find(query)
            .sort("created_at", -1)
            .skip(offset)
            .limit(limit)
        )
        tickets: list[EscalationTicket] = []
        async for doc in cursor:
            doc.pop("_id", None)
            tickets.append(EscalationTicket(**doc))
        return tickets

    # ------------------------------------------------------------------
    # Actions — approve / deny / escalate-up (APEP-145)
    # ------------------------------------------------------------------

    async def _resolve(
        self,
        escalation_id: UUID,
        new_status: EscalationStatus,
        resolved_by: str,
        comment: str = "",
        escalated_to: str | None = None,
    ) -> EscalationTicket | None:
        db = get_database()
        now = datetime.utcnow()
        update: dict[str, Any] = {
            "status": new_status.value,
            "resolved_by": resolved_by,
            "resolution_comment": comment,
            "resolved_at": now.isoformat(),
        }
        if escalated_to:
            update["escalated_to"] = escalated_to

        result = await db[ESCALATION_TICKETS].find_one_and_update(
            {"escalation_id": str(escalation_id), "status": EscalationStatus.PENDING.value},
            {"$set": update},
            return_document=True,
        )
        if result is None:
            return None
        result.pop("_id", None)
        ticket = EscalationTicket(**result)
        await self._broadcast("escalation:resolved", ticket.model_dump(mode="json"))
        return ticket

    async def approve(
        self, escalation_id: UUID, resolved_by: str, comment: str = ""
    ) -> EscalationTicket | None:
        return await self._resolve(
            escalation_id, EscalationStatus.APPROVED, resolved_by, comment
        )

    async def deny(
        self, escalation_id: UUID, resolved_by: str, comment: str = ""
    ) -> EscalationTicket | None:
        return await self._resolve(
            escalation_id, EscalationStatus.DENIED, resolved_by, comment
        )

    async def escalate_up(
        self,
        escalation_id: UUID,
        resolved_by: str,
        escalated_to: str,
        comment: str = "",
    ) -> EscalationTicket | None:
        return await self._resolve(
            escalation_id,
            EscalationStatus.ESCALATED_UP,
            resolved_by,
            comment,
            escalated_to=escalated_to,
        )

    # ------------------------------------------------------------------
    # Bulk approve (APEP-146)
    # ------------------------------------------------------------------

    async def bulk_approve(
        self,
        tool_pattern: str,
        resolved_by: str,
        comment: str = "",
    ) -> list[EscalationTicket]:
        """Approve all PENDING tickets matching a tool name pattern."""
        db = get_database()
        pending = await db[ESCALATION_TICKETS].find(
            {"status": EscalationStatus.PENDING.value, "tool_name": tool_pattern}
        ).to_list(length=1000)

        resolved: list[EscalationTicket] = []
        for doc in pending:
            doc.pop("_id", None)
            eid = doc["escalation_id"]
            # Parse UUID — it may be stored as string
            uid = UUID(eid) if isinstance(eid, str) else eid
            ticket = await self.approve(uid, resolved_by, comment)
            if ticket:
                resolved.append(ticket)
        return resolved

    # ------------------------------------------------------------------
    # SLA auto-decision (APEP-147)
    # ------------------------------------------------------------------

    async def process_expired_sla(self) -> list[EscalationTicket]:
        """Find PENDING tickets past their SLA deadline and auto-resolve them."""
        db = get_database()
        now = datetime.utcnow().isoformat()
        cursor = db[ESCALATION_TICKETS].find(
            {
                "status": EscalationStatus.PENDING.value,
                "sla_deadline": {"$lte": now},
            }
        )
        resolved: list[EscalationTicket] = []
        async for doc in cursor:
            doc.pop("_id", None)
            eid = doc["escalation_id"]
            uid = UUID(eid) if isinstance(eid, str) else eid
            auto_decision = doc.get("auto_decision", Decision.DENY.value)
            new_status = (
                EscalationStatus.APPROVED
                if auto_decision == Decision.ALLOW.value
                else EscalationStatus.DENIED
            )
            ticket = await self._resolve(
                uid,
                new_status=EscalationStatus.AUTO_DECIDED,
                resolved_by="system:sla_expiry",
                comment=f"SLA expired — auto-decision: {auto_decision}",
            )
            if ticket:
                resolved.append(ticket)
        return resolved

    async def start_sla_watcher(self, interval_s: int = 30) -> None:
        """Background task that checks for expired SLA tickets."""

        async def _loop() -> None:
            while True:
                try:
                    expired = await self.process_expired_sla()
                    if expired:
                        logger.info("Auto-resolved %d expired escalation tickets", len(expired))
                except Exception:
                    logger.exception("Error in SLA watcher loop")
                await asyncio.sleep(interval_s)

        self._sla_task = asyncio.create_task(_loop())

    def stop_sla_watcher(self) -> None:
        if self._sla_task is not None:
            self._sla_task.cancel()
            self._sla_task = None


# Module-level singleton
escalation_manager = EscalationManager()
