"""EscalationManager — full escalation lifecycle for human-in-the-loop approval.

Sprint 9 stories:
- APEP-073: Create ticket, block agent, await response
- APEP-075: Configurable timeout with auto-DENY or auto-ALLOW per risk level
- APEP-076: Approver routing (round-robin, specific user, on-call)
- APEP-077: Approval memory — 7-day TTL cache of approved patterns
- APEP-078: Email notification webhook on ESCALATE event
- APEP-079: Slack webhook notification on ESCALATE event
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import httpx

from app.db import mongodb as db_module
from app.models.policy import (
    ApprovalMemoryEntry,
    ApproverGroup,
    ApproverRoutingStrategy,
    EscalationResolveRequest,
    EscalationState,
    EscalationTicket,
    NotificationConfig,
)

logger = logging.getLogger(__name__)

# --- Collection Names ---
ESCALATION_TICKETS = "escalation_tickets"
APPROVER_GROUPS = "approver_groups"
APPROVAL_MEMORY = "approval_memory"

# Approval memory TTL: 7 days
APPROVAL_MEMORY_TTL_DAYS = 7


class EscalationManager:
    """Manages the full escalation lifecycle (APEP-073).

    Creates tickets, routes to approvers, handles timeouts, caches approvals,
    and sends notifications via email/Slack webhooks.
    """

    def __init__(self) -> None:
        self._pending_futures: dict[UUID, asyncio.Future[EscalationState]] = {}
        self._notification_config = NotificationConfig()
        self._websocket_callback: Any = None

    def set_notification_config(self, config: NotificationConfig) -> None:
        self._notification_config = config

    def set_websocket_callback(self, callback: Any) -> None:
        """Register a callback to push ESCALATE events via WebSocket (APEP-074)."""
        self._websocket_callback = callback

    # --- Approval Memory (APEP-077) ---

    @staticmethod
    def compute_args_hash(tool_args: dict[str, Any]) -> str:
        return hashlib.sha256(
            json.dumps(tool_args, sort_keys=True).encode()
        ).hexdigest()

    async def check_approval_memory(
        self, agent_id: str, tool_name: str, tool_args_hash: str
    ) -> bool:
        """Check if a matching approval exists in the 7-day TTL cache (APEP-077)."""
        db = db_module.get_database()
        cutoff = datetime.utcnow() - timedelta(days=APPROVAL_MEMORY_TTL_DAYS)
        entry = await db[APPROVAL_MEMORY].find_one(
            {
                "agent_id": agent_id,
                "tool_name": tool_name,
                "tool_args_hash": tool_args_hash,
                "created_at": {"$gte": cutoff},
            }
        )
        return entry is not None

    async def store_approval_memory(
        self, ticket: EscalationTicket
    ) -> None:
        """Cache an approved pattern for 7-day re-use (APEP-077)."""
        db = db_module.get_database()
        entry = ApprovalMemoryEntry(
            agent_id=ticket.agent_id,
            tool_name=ticket.tool_name,
            tool_args_hash=ticket.tool_args_hash,
            approved_by=ticket.decided_by or "system",
            original_ticket_id=ticket.ticket_id,
        )
        # Use model_dump() (not mode="json") to preserve datetime objects for MongoDB
        doc = entry.model_dump()
        # Convert UUIDs to strings for MongoDB storage
        doc["entry_id"] = str(doc["entry_id"])
        doc["original_ticket_id"] = str(doc["original_ticket_id"])
        await db[APPROVAL_MEMORY].insert_one(doc)

    # --- Approver Routing (APEP-076) ---

    async def get_approver_group(self, group_id: str) -> ApproverGroup | None:
        db = db_module.get_database()
        doc = await db[APPROVER_GROUPS].find_one({"group_id": group_id, "enabled": True})
        if doc is None:
            return None
        doc.pop("_id", None)
        return ApproverGroup(**doc)

    async def route_to_approver(
        self, group_id: str | None = None, specific_user: str | None = None
    ) -> str | None:
        """Select the next approver based on routing strategy (APEP-076).

        Strategies:
        - ROUND_ROBIN: Rotate through group members
        - SPECIFIC_USER: Route to a named user
        - ON_CALL: Route to the on-call user in the group
        """
        if specific_user:
            return specific_user

        if group_id is None:
            return None

        group = await self.get_approver_group(group_id)
        if group is None or not group.members:
            return None

        if group.strategy == ApproverRoutingStrategy.ON_CALL:
            return group.on_call_user or group.members[0]

        if group.strategy == ApproverRoutingStrategy.SPECIFIC_USER:
            return group.members[0] if group.members else None

        # ROUND_ROBIN (default)
        idx = group.last_assigned_index % len(group.members)
        approver = group.members[idx]

        # Advance the round-robin pointer
        db = db_module.get_database()
        await db[APPROVER_GROUPS].update_one(
            {"group_id": group_id},
            {"$set": {"last_assigned_index": idx + 1}},
        )
        return approver

    # --- Ticket Creation (APEP-073) ---

    async def create_ticket(
        self,
        request_id: UUID,
        session_id: str,
        agent_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
        reason: str = "",
        risk_score: float = 0.0,
        taint_flags: list[str] | None = None,
        delegation_chain: list[str] | None = None,
        approver_group_id: str | None = None,
        specific_approver: str | None = None,
        timeout_seconds: int = 300,
        timeout_action: EscalationState = EscalationState.DENIED,
    ) -> EscalationTicket:
        """Create an escalation ticket and persist to MongoDB (APEP-073)."""
        args_hash = self.compute_args_hash(tool_args)

        # Check approval memory first (APEP-077)
        if await self.check_approval_memory(agent_id, tool_name, args_hash):
            logger.info(
                "Approval memory hit for agent=%s tool=%s — skipping escalation",
                agent_id, tool_name,
            )
            ticket = EscalationTicket(
                request_id=request_id,
                session_id=session_id,
                agent_id=agent_id,
                tool_name=tool_name,
                tool_args_hash=args_hash,
                risk_score=risk_score,
                reason="Approval memory hit — previously approved pattern",
                state=EscalationState.APPROVED,
                taint_flags=taint_flags or [],
                delegation_chain=delegation_chain or [],
                timeout_seconds=timeout_seconds,
                timeout_action=timeout_action,
                resolved_at=datetime.utcnow(),
                decided_by="approval_memory",
            )
            db = db_module.get_database()
            await db[ESCALATION_TICKETS].insert_one(ticket.model_dump(mode="json"))
            return ticket

        # Route to approver (APEP-076)
        assigned_to = await self.route_to_approver(
            group_id=approver_group_id, specific_user=specific_approver
        )

        # Determine routing strategy
        if specific_approver:
            strategy = ApproverRoutingStrategy.SPECIFIC_USER
        elif approver_group_id:
            group = await self.get_approver_group(approver_group_id)
            strategy = group.strategy if group else ApproverRoutingStrategy.ROUND_ROBIN
        else:
            strategy = ApproverRoutingStrategy.ROUND_ROBIN

        ticket = EscalationTicket(
            request_id=request_id,
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_args_hash=args_hash,
            risk_score=risk_score,
            reason=reason,
            assigned_to=assigned_to,
            routing_strategy=strategy,
            taint_flags=taint_flags or [],
            delegation_chain=delegation_chain or [],
            timeout_seconds=timeout_seconds,
            timeout_action=timeout_action,
        )

        db = db_module.get_database()
        await db[ESCALATION_TICKETS].insert_one(ticket.model_dump(mode="json"))

        # Push WebSocket event (APEP-074)
        if self._websocket_callback is not None:
            try:
                await self._websocket_callback(ticket)
            except Exception:
                logger.exception("Failed to push WebSocket ESCALATE event")

        # Send notifications (APEP-078, APEP-079)
        await self._send_notifications(ticket)

        return ticket

    # --- Ticket Resolution ---

    async def resolve_ticket(
        self, resolve: EscalationResolveRequest
    ) -> EscalationTicket | None:
        """Resolve a PENDING ticket to APPROVED or DENIED."""
        if resolve.state not in (EscalationState.APPROVED, EscalationState.DENIED):
            return None

        db = db_module.get_database()
        doc = await db[ESCALATION_TICKETS].find_one(
            {"ticket_id": str(resolve.ticket_id), "state": EscalationState.PENDING.value}
        )
        if doc is None:
            return None

        now = datetime.utcnow()
        await db[ESCALATION_TICKETS].update_one(
            {"ticket_id": str(resolve.ticket_id)},
            {
                "$set": {
                    "state": resolve.state.value,
                    "decided_by": resolve.decided_by,
                    "decision_reason": resolve.decision_reason,
                    "resolved_at": now,
                }
            },
        )

        doc.pop("_id", None)
        ticket = EscalationTicket(**doc)
        ticket.state = resolve.state
        ticket.decided_by = resolve.decided_by
        ticket.decision_reason = resolve.decision_reason
        ticket.resolved_at = now

        # Store in approval memory if approved (APEP-077)
        if resolve.state == EscalationState.APPROVED:
            await self.store_approval_memory(ticket)

        # Notify waiting future
        future = self._pending_futures.pop(resolve.ticket_id, None)
        if future is not None and not future.done():
            future.set_result(resolve.state)

        # Push resolution via WebSocket
        if self._websocket_callback is not None:
            try:
                await self._websocket_callback(ticket)
            except Exception:
                logger.exception("Failed to push WebSocket resolution event")

        return ticket

    # --- Blocking Await with Timeout (APEP-073 + APEP-075) ---

    async def await_resolution(
        self, ticket: EscalationTicket
    ) -> EscalationState:
        """Block the agent until the ticket is resolved or times out (APEP-073/075).

        On timeout, applies the ticket's timeout_action (auto-DENY or auto-ALLOW).
        """
        if ticket.state != EscalationState.PENDING:
            return ticket.state

        loop = asyncio.get_event_loop()
        future: asyncio.Future[EscalationState] = loop.create_future()
        self._pending_futures[ticket.ticket_id] = future

        try:
            result = await asyncio.wait_for(
                future, timeout=ticket.timeout_seconds
            )
            return result
        except asyncio.TimeoutError:
            # Auto-resolve on timeout (APEP-075)
            self._pending_futures.pop(ticket.ticket_id, None)
            await self._timeout_ticket(ticket)
            return ticket.timeout_action

    async def _timeout_ticket(self, ticket: EscalationTicket) -> None:
        """Apply timeout action to a ticket (APEP-075)."""
        db = db_module.get_database()
        now = datetime.utcnow()
        await db[ESCALATION_TICKETS].update_one(
            {"ticket_id": str(ticket.ticket_id), "state": EscalationState.PENDING.value},
            {
                "$set": {
                    "state": EscalationState.TIMEOUT.value,
                    "decided_by": "system_timeout",
                    "decision_reason": (
                        f"Timed out after {ticket.timeout_seconds}s — "
                        f"auto-{ticket.timeout_action.value}"
                    ),
                    "resolved_at": now,
                }
            },
        )
        logger.info(
            "Escalation ticket %s timed out — auto-%s",
            ticket.ticket_id, ticket.timeout_action.value,
        )

    # --- Get Ticket ---

    async def get_ticket(self, ticket_id: UUID) -> EscalationTicket | None:
        db = db_module.get_database()
        doc = await db[ESCALATION_TICKETS].find_one({"ticket_id": str(ticket_id)})
        if doc is None:
            return None
        doc.pop("_id", None)
        return EscalationTicket(**doc)

    async def list_pending_tickets(self) -> list[EscalationTicket]:
        db = db_module.get_database()
        cursor = db[ESCALATION_TICKETS].find({"state": EscalationState.PENDING.value})
        tickets = []
        async for doc in cursor:
            doc.pop("_id", None)
            tickets.append(EscalationTicket(**doc))
        return tickets

    # --- Notifications (APEP-078 + APEP-079) ---

    async def _send_notifications(self, ticket: EscalationTicket) -> None:
        """Send email and Slack notifications for a new escalation."""
        config = self._notification_config
        if not config.enabled:
            return

        # Fire both notifications concurrently
        tasks = []
        if config.email_webhook_url:
            tasks.append(self._send_email_notification(ticket, config))
        if config.slack_webhook_url:
            tasks.append(self._send_slack_notification(ticket, config))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_email_notification(
        self, ticket: EscalationTicket, config: NotificationConfig
    ) -> None:
        """Send email notification via webhook (APEP-078)."""
        payload = {
            "event": "ESCALATE",
            "ticket_id": str(ticket.ticket_id),
            "session_id": ticket.session_id,
            "agent_id": ticket.agent_id,
            "tool_name": ticket.tool_name,
            "risk_score": ticket.risk_score,
            "reason": ticket.reason,
            "assigned_to": ticket.assigned_to,
            "recipients": config.email_recipients,
            "timeout_seconds": ticket.timeout_seconds,
            "created_at": ticket.created_at.isoformat(),
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(config.email_webhook_url, json=payload)  # type: ignore[arg-type]
                resp.raise_for_status()
            logger.info("Email notification sent for ticket %s", ticket.ticket_id)
        except Exception:
            logger.exception("Failed to send email notification for ticket %s", ticket.ticket_id)

    async def _send_slack_notification(
        self, ticket: EscalationTicket, config: NotificationConfig
    ) -> None:
        """Send Slack notification via incoming webhook (APEP-079)."""
        text = (
            f":rotating_light: *AgentPEP Escalation*\n"
            f"*Ticket:* `{ticket.ticket_id}`\n"
            f"*Agent:* `{ticket.agent_id}` | *Tool:* `{ticket.tool_name}`\n"
            f"*Risk Score:* {ticket.risk_score:.2f}\n"
            f"*Reason:* {ticket.reason}\n"
            f"*Assigned To:* {ticket.assigned_to or 'unassigned'}\n"
            f"*Timeout:* {ticket.timeout_seconds}s"
        )
        payload: dict[str, Any] = {"text": text}
        if config.slack_channel:
            payload["channel"] = config.slack_channel

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(config.slack_webhook_url, json=payload)  # type: ignore[arg-type]
                resp.raise_for_status()
            logger.info("Slack notification sent for ticket %s", ticket.ticket_id)
        except Exception:
            logger.exception("Failed to send Slack notification for ticket %s", ticket.ticket_id)


# Module-level singleton
escalation_manager = EscalationManager()
