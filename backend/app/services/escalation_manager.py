"""Escalation Manager — manages escalation tickets and WebSocket notifications.

Sprint 18: APEP-143 (queue), APEP-145 (approve/deny), APEP-146 (bulk),
           APEP-147 (SLA timer).
"""

from __future__ import annotations

import asyncio
import fnmatch
import logging
import threading
from datetime import datetime, timedelta
from uuid import UUID

from app.models.policy import EscalationStatus, EscalationTicket

logger = logging.getLogger(__name__)


class EscalationManager:
    """In-memory escalation ticket store with WebSocket broadcast support."""

    def __init__(self, default_sla_seconds: int = 300) -> None:
        self._lock = threading.Lock()
        self._tickets: dict[UUID, EscalationTicket] = {}
        self._subscribers: list[asyncio.Queue[dict[str, object]]] = []
        self._default_sla_seconds = default_sla_seconds

    # --- Ticket CRUD ---

    def create_ticket(
        self,
        session_id: str,
        agent_id: str,
        agent_role: str,
        tool_name: str,
        tool_args: dict[str, object],
        tool_args_hash: str,
        risk_score: float,
        taint_flags: list[str],
        delegation_chain: list[str],
        matched_rule_id: UUID | None,
        reason: str,
        sla_seconds: int | None = None,
    ) -> EscalationTicket:
        sla = sla_seconds if sla_seconds is not None else self._default_sla_seconds
        now = datetime.utcnow()
        ticket = EscalationTicket(
            session_id=session_id,
            agent_id=agent_id,
            agent_role=agent_role,
            tool_name=tool_name,
            tool_args=tool_args,
            tool_args_hash=tool_args_hash,
            risk_score=risk_score,
            taint_flags=taint_flags,
            delegation_chain=delegation_chain,
            matched_rule_id=matched_rule_id,
            reason=reason,
            sla_seconds=sla,
            sla_deadline=now + timedelta(seconds=sla),
            created_at=now,
        )
        with self._lock:
            self._tickets[ticket.ticket_id] = ticket
        self._broadcast({"type": "ticket_created", "ticket": ticket.model_dump(mode="json")})
        return ticket

    def get_ticket(self, ticket_id: UUID) -> EscalationTicket | None:
        with self._lock:
            return self._tickets.get(ticket_id)

    def list_pending(self) -> list[EscalationTicket]:
        with self._lock:
            return [
                t for t in self._tickets.values() if t.status == EscalationStatus.PENDING
            ]

    def list_all(self) -> list[EscalationTicket]:
        with self._lock:
            return list(self._tickets.values())

    def resolve_ticket(
        self,
        ticket_id: UUID,
        action: EscalationStatus,
        comment: str = "",
        resolved_by: str = "console_user",
    ) -> EscalationTicket | None:
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                return None
            if ticket.status != EscalationStatus.PENDING:
                return ticket  # already resolved
            ticket.status = action
            ticket.resolution_comment = comment
            ticket.resolved_by = resolved_by
            ticket.resolved_at = datetime.utcnow()
        self._broadcast({
            "type": "ticket_resolved",
            "ticket_id": str(ticket_id),
            "action": action.value,
        })
        return ticket

    def bulk_approve(
        self,
        tool_pattern: str,
        comment: str = "",
        resolved_by: str = "console_user",
    ) -> list[EscalationTicket]:
        """Approve all PENDING tickets whose tool_name matches the glob pattern (APEP-146)."""
        resolved: list[EscalationTicket] = []
        with self._lock:
            for ticket in self._tickets.values():
                if (
                    ticket.status == EscalationStatus.PENDING
                    and fnmatch.fnmatch(ticket.tool_name, tool_pattern)
                ):
                    ticket.status = EscalationStatus.APPROVED
                    ticket.resolution_comment = comment
                    ticket.resolved_by = resolved_by
                    ticket.resolved_at = datetime.utcnow()
                    resolved.append(ticket)
        if resolved:
            self._broadcast({
                "type": "bulk_approved",
                "count": len(resolved),
                "tool_pattern": tool_pattern,
                "ticket_ids": [str(t.ticket_id) for t in resolved],
            })
        return resolved

    def check_sla_expirations(self) -> list[EscalationTicket]:
        """Auto-decide any PENDING tickets whose SLA deadline has passed (APEP-147)."""
        now = datetime.utcnow()
        expired: list[EscalationTicket] = []
        with self._lock:
            for ticket in self._tickets.values():
                if ticket.status == EscalationStatus.PENDING and ticket.sla_deadline <= now:
                    ticket.status = EscalationStatus.AUTO_DECIDED
                    ticket.resolution_comment = "SLA expired — auto-denied"
                    ticket.resolved_by = "system"
                    ticket.resolved_at = now
                    expired.append(ticket)
        for ticket in expired:
            self._broadcast({
                "type": "sla_expired",
                "ticket_id": str(ticket.ticket_id),
            })
        return expired

    # --- WebSocket subscriber management ---

    def subscribe(self) -> asyncio.Queue[dict[str, object]]:
        q: asyncio.Queue[dict[str, object]] = asyncio.Queue()
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, object]]) -> None:
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def _broadcast(self, message: dict[str, object]) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                logger.warning("WebSocket subscriber queue full — dropping message")

    # --- Cleanup ---

    def clear(self) -> None:
        with self._lock:
            self._tickets.clear()
            self._subscribers.clear()


escalation_manager = EscalationManager()
