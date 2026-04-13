"""Escalation Manager — manages escalation tickets and WebSocket notifications.

Sprint 9: APEP-072..APEP-080 (async MongoDB-backed V1 interface)
Sprint 18: APEP-143 (queue), APEP-145 (approve/deny), APEP-146 (bulk),
           APEP-147 (SLA timer).
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import logging
import threading
from datetime import UTC, datetime, timedelta
from uuid import UUID

import httpx

from app.core.observability import ESCALATION_BACKLOG
from app.models.policy import (
    ApprovalMemoryEntry,
    ApproverRoutingStrategy,
    EscalationResolveRequest,
    EscalationState,
    EscalationStatus,
    EscalationTicket,
)
from app.models.policy import (
    EscalationTicketV1 as EscalationTicketV1,
)

logger = logging.getLogger(__name__)


class EscalationManager:
    """In-memory escalation ticket store with WebSocket broadcast support.

    Provides both Sprint-18 sync methods (used by REST API) and Sprint-9 async
    methods (MongoDB-backed, used by the escalation subsystem).
    """

    def __init__(self, default_sla_seconds: int = 300) -> None:
        self._lock = threading.Lock()
        self._tickets: dict[UUID, EscalationTicket] = {}
        self._subscribers: list[asyncio.Queue[dict[str, object]]] = []
        self._default_sla_seconds = default_sla_seconds
        self._websocket_callback = None
        self._notification_config = None
        # Sprint-9 in-memory V1 tickets (keyed by ticket_id)
        self._v1_tickets: dict[UUID, EscalationTicketV1] = {}
        # Sprint-9 resolution events for await_resolution
        self._resolution_events: dict[UUID, asyncio.Event] = {}

    def set_websocket_callback(self, callback) -> None:
        """Set an async callback to invoke when tickets are created/resolved."""
        self._websocket_callback = callback

    def set_notification_config(self, config) -> None:
        """Set notification configuration for escalation alerts."""
        self._notification_config = config

    # --- Sprint 18: Ticket CRUD (sync, in-memory) ---

    def create_ticket_sync(
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
        now = datetime.now(UTC)
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

    # --- Sprint 9: Async MongoDB-backed V1 interface (APEP-072..080) ---

    @staticmethod
    def compute_args_hash(tool_args: dict) -> str:
        """Compute a SHA-256 hash of tool arguments for approval memory matching."""
        canonical = json.dumps(tool_args, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    async def create_ticket(
        self,
        *,
        request_id: UUID,
        session_id: str,
        agent_id: str,
        tool_name: str,
        tool_args: dict | None = None,
        reason: str = "",
        risk_score: float = 0.0,
        taint_flags: list[str] | None = None,
        delegation_chain: list[str] | None = None,
        timeout_seconds: int = 300,
        timeout_action: EscalationState = EscalationState.DENIED,
        approver_group_id: str | None = None,
    ) -> EscalationTicketV1:
        """Create a Sprint-9 escalation ticket, persist to MongoDB, and broadcast."""
        from app.db import mongodb as db_module
        from app.db.mongodb import ESCALATION_TICKETS

        tool_args = tool_args or {}
        taint_flags = taint_flags or []
        delegation_chain = delegation_chain or []
        args_hash = self.compute_args_hash(tool_args)

        # --- APEP-077: Check approval memory ---
        has_memory = await self.check_approval_memory(agent_id, tool_name, args_hash)

        # --- APEP-076: Approver routing ---
        assigned_to: str | None = None
        if approver_group_id:
            assigned_to = await self.route_to_approver(group_id=approver_group_id)

        ticket = EscalationTicketV1(
            request_id=request_id,
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args_hash=args_hash,
            risk_score=risk_score,
            reason=reason,
            taint_flags=taint_flags,
            delegation_chain=delegation_chain,
            timeout_seconds=timeout_seconds,
            timeout_action=timeout_action,
            assigned_to=assigned_to,
        )

        if has_memory:
            ticket.state = EscalationState.APPROVED
            ticket.decided_by = "approval_memory"
            ticket.resolved_at = datetime.now(UTC)

        # Persist to MongoDB
        db = db_module.get_database()
        await db[ESCALATION_TICKETS].insert_one(ticket.model_dump(mode="json"))

        # Store in-memory for await_resolution
        self._v1_tickets[ticket.ticket_id] = ticket
        if ticket.state == EscalationState.PENDING:
            self._resolution_events[ticket.ticket_id] = asyncio.Event()

        # Broadcast via WebSocket callback
        if self._websocket_callback is not None:
            try:
                await self._websocket_callback(ticket)
            except Exception:
                logger.warning("WebSocket broadcast failed during ticket creation", exc_info=True)

        # --- APEP-078/079: Send notifications ---
        await self._send_notifications(ticket)

        return ticket

    async def resolve_ticket(
        self,
        resolve_req: EscalationResolveRequest,
    ) -> EscalationTicketV1 | None:
        """Resolve (approve/deny) a Sprint-9 escalation ticket."""
        from app.db import mongodb as db_module
        from app.db.mongodb import APPROVAL_MEMORY, ESCALATION_TICKETS

        ticket = self._v1_tickets.get(resolve_req.ticket_id)
        if ticket is None:
            # Try loading from DB
            db = db_module.get_database()
            doc = await db[ESCALATION_TICKETS].find_one(
                {"ticket_id": str(resolve_req.ticket_id)}
            )
            if doc is None:
                return None
            ticket = EscalationTicketV1(**{k: v for k, v in doc.items() if k != "_id"})
            self._v1_tickets[ticket.ticket_id] = ticket

        if ticket.state != EscalationState.PENDING:
            return None  # Already resolved

        now = datetime.now(UTC)
        ticket.state = resolve_req.state
        ticket.decided_by = resolve_req.decided_by
        ticket.decision_reason = resolve_req.decision_reason
        ticket.resolved_at = now

        # Update MongoDB
        db = db_module.get_database()
        await db[ESCALATION_TICKETS].update_one(
            {"ticket_id": str(ticket.ticket_id)},
            {"$set": {
                "state": ticket.state.value,
                "decided_by": ticket.decided_by,
                "decision_reason": ticket.decision_reason,
                "resolved_at": now.isoformat(),
            }},
        )

        # APEP-077: Store approval in memory cache
        if resolve_req.state == EscalationState.APPROVED:
            entry = ApprovalMemoryEntry(
                agent_id=ticket.agent_id,
                tool_name=ticket.tool_name,
                tool_args_hash=ticket.tool_args_hash,
                approved_by=resolve_req.decided_by,
                original_ticket_id=ticket.ticket_id,
            )
            await db[APPROVAL_MEMORY].insert_one(entry.model_dump(mode="json"))

        # Signal any waiters
        evt = self._resolution_events.pop(ticket.ticket_id, None)
        if evt is not None:
            evt.set()

        # Broadcast
        if self._websocket_callback is not None:
            try:
                await self._websocket_callback(ticket)
            except Exception:
                logger.warning("WebSocket broadcast failed during ticket resolution", exc_info=True)

        return ticket

    async def get_ticket(self, ticket_id: UUID) -> EscalationTicketV1 | None:
        """Get a Sprint-9 ticket by ID."""
        ticket = self._v1_tickets.get(ticket_id)
        if ticket is not None:
            return ticket

        from app.db import mongodb as db_module
        from app.db.mongodb import ESCALATION_TICKETS

        db = db_module.get_database()
        doc = await db[ESCALATION_TICKETS].find_one({"ticket_id": str(ticket_id)})
        if doc is None:
            return None
        ticket = EscalationTicketV1(**{k: v for k, v in doc.items() if k != "_id"})
        self._v1_tickets[ticket.ticket_id] = ticket
        return ticket

    async def list_pending_tickets(self) -> list[EscalationTicketV1]:
        """List all PENDING Sprint-9 tickets."""
        return [t for t in self._v1_tickets.values() if t.state == EscalationState.PENDING]

    async def await_resolution(self, ticket: EscalationTicketV1) -> EscalationState:
        """Wait for a ticket to be resolved or timeout (APEP-075)."""
        if ticket.state != EscalationState.PENDING:
            return ticket.state

        evt = self._resolution_events.get(ticket.ticket_id)
        if evt is None:
            evt = asyncio.Event()
            self._resolution_events[ticket.ticket_id] = evt

        try:
            await asyncio.wait_for(evt.wait(), timeout=ticket.timeout_seconds)
            # Ticket was resolved externally
            updated = self._v1_tickets.get(ticket.ticket_id, ticket)
            return updated.state
        except TimeoutError:
            # Auto-decide based on timeout_action
            from app.db import mongodb as db_module
            from app.db.mongodb import ESCALATION_TICKETS

            timeout_state = EscalationState(ticket.timeout_action.value)
            now = datetime.now(UTC)
            ticket.state = EscalationState.TIMEOUT
            ticket.resolved_at = now
            outcome = "DENIED" if timeout_state == EscalationState.DENIED else "APPROVED"
            decision_reason = f"SLA expired — auto-{outcome}"
            ticket.decision_reason = decision_reason

            db = db_module.get_database()
            await db[ESCALATION_TICKETS].update_one(
                {"ticket_id": str(ticket.ticket_id)},
                {"$set": {
                    "state": "TIMEOUT",
                    "resolved_at": now.isoformat(),
                    "decision_reason": decision_reason,
                }},
            )
            self._resolution_events.pop(ticket.ticket_id, None)
            return timeout_state

    async def route_to_approver(
        self,
        *,
        group_id: str | None = None,
        specific_user: str | None = None,
    ) -> str | None:
        """Route to an approver based on strategy (APEP-076)."""
        if specific_user:
            return specific_user

        if group_id is None:
            return None

        from app.db import mongodb as db_module
        from app.db.mongodb import APPROVER_GROUPS

        db = db_module.get_database()
        doc = await db[APPROVER_GROUPS].find_one({"group_id": group_id})
        if doc is None:
            return None

        strategy = doc.get("strategy", "ROUND_ROBIN")
        members = doc.get("members", [])

        if not members:
            return None

        if strategy == ApproverRoutingStrategy.ON_CALL:
            return doc.get("on_call_user") or members[0]

        # ROUND_ROBIN
        idx = doc.get("last_assigned_index", 0)
        approver = members[idx % len(members)]
        # Update the index
        await db[APPROVER_GROUPS].update_one(
            {"group_id": group_id},
            {"$set": {"last_assigned_index": (idx + 1) % len(members)}},
        )
        return approver

    async def check_approval_memory(
        self,
        agent_id: str,
        tool_name: str,
        args_hash: str,
    ) -> bool:
        """Check if there's a cached approval for the given agent/tool/args combo (APEP-077)."""
        from app.db import mongodb as db_module
        from app.db.mongodb import APPROVAL_MEMORY

        db = db_module.get_database()
        entry = await db[APPROVAL_MEMORY].find_one({
            "agent_id": agent_id,
            "tool_name": tool_name,
            "tool_args_hash": args_hash,
        })
        return entry is not None

    async def _send_notifications(self, ticket: EscalationTicketV1) -> None:
        """Send email/Slack notifications for new escalation tickets (APEP-078/079)."""
        if self._notification_config is None:
            return
        if not self._notification_config.enabled:
            return

        if self._notification_config.email_webhook_url:
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(
                        self._notification_config.email_webhook_url,
                        json={
                            "event": "ESCALATE",
                            "ticket_id": str(ticket.ticket_id),
                            "agent_id": ticket.agent_id,
                            "tool_name": ticket.tool_name,
                            "risk_score": ticket.risk_score,
                            "reason": ticket.reason,
                            "recipients": self._notification_config.email_recipients,
                        },
                    )
            except Exception:
                logger.warning("Email notification failed", exc_info=True)

        if self._notification_config.slack_webhook_url:
            try:
                async with httpx.AsyncClient() as client:
                    await client.post(
                        self._notification_config.slack_webhook_url,
                        json={
                            "text": (
                                f"AgentPEP Escalation: {ticket.tool_name} "
                                f"by {ticket.agent_id} (risk={ticket.risk_score})"
                            ),
                            "channel": self._notification_config.slack_channel,
                            "ticket_id": str(ticket.ticket_id),
                        },
                    )
            except Exception:
                logger.warning("Slack notification failed", exc_info=True)

    def get_ticket_sync(self, ticket_id: UUID) -> EscalationTicket | None:
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

    def resolve_ticket_sync(
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
            # Atomic check-and-set: only resolve if still PENDING
            if ticket.status != EscalationStatus.PENDING:
                return ticket  # already resolved — no-op
            # Atomically update under the lock (equivalent to findOneAndUpdate
            # with state=PENDING condition for in-memory store)
            ticket.status = action
            ticket.resolution_comment = comment
            ticket.resolved_by = resolved_by
            ticket.resolved_at = datetime.now(UTC)
            # Store the updated ticket back to guarantee atomic visibility
            self._tickets[ticket_id] = ticket
        ESCALATION_BACKLOG.dec()
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
                    ticket.resolved_at = datetime.now(UTC)
                    resolved.append(ticket)
        if resolved:
            ESCALATION_BACKLOG.dec(len(resolved))
            self._broadcast({
                "type": "bulk_approved",
                "count": len(resolved),
                "tool_pattern": tool_pattern,
                "ticket_ids": [str(t.ticket_id) for t in resolved],
            })
        return resolved

    def check_sla_expirations(self) -> list[EscalationTicket]:
        """Auto-decide any PENDING tickets whose SLA deadline has passed (APEP-147)."""
        now = datetime.now(UTC)
        expired: list[EscalationTicket] = []
        with self._lock:
            for ticket in self._tickets.values():
                if ticket.status == EscalationStatus.PENDING and ticket.sla_deadline <= now:
                    ticket.status = EscalationStatus.AUTO_DECIDED
                    ticket.resolution_comment = "SLA expired — auto-denied"
                    ticket.resolved_by = "system"
                    ticket.resolved_at = now
                    expired.append(ticket)
        if expired:
            ESCALATION_BACKLOG.dec(len(expired))
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
            dead: list[asyncio.Queue] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(message)
                except asyncio.QueueFull:
                    logger.warning("WebSocket subscriber queue full — dropping message")
                    dead.append(q)
            for q in dead:
                try:
                    self._subscribers.remove(q)
                except ValueError:
                    pass

    # --- Cleanup ---

    def clear(self) -> None:
        with self._lock:
            self._tickets.clear()
            self._subscribers.clear()
        self._v1_tickets.clear()
        self._resolution_events.clear()


escalation_manager = EscalationManager()
