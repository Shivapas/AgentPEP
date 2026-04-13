"""WebSocket server for pushing ESCALATE events to Policy Console sessions (APEP-074).

Connected clients receive real-time notifications when escalation tickets are
created or resolved. The server maintains a set of active connections and
broadcasts events to all connected Policy Console sessions.
"""

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from app.models.policy import EscalationTicket

logger = logging.getLogger(__name__)


class EscalationWebSocketManager:
    """Manages WebSocket connections for escalation event broadcasting (APEP-074)."""

    def __init__(self) -> None:
        self._connections: dict[WebSocket, str | None] = {}  # ws -> session_id
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: WebSocket, session_id: str | None = None) -> None:
        """Accept and register a new WebSocket connection.

        Args:
            websocket: The WebSocket connection.
            session_id: Optional session ID to scope ticket broadcasts.
                        If provided, this client only receives tickets for that session.
        """
        await websocket.accept()
        async with self._lock:
            self._connections[websocket] = session_id
        logger.info(
            "Policy Console WebSocket connected (total=%d, session_id=%s)",
            len(self._connections),
            session_id,
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            self._connections.pop(websocket, None)
        logger.info(
            "Policy Console WebSocket disconnected (total=%d)", len(self._connections)
        )

    async def broadcast_ticket(self, ticket: EscalationTicket) -> None:
        """Push an escalation ticket event to session-scoped connected clients.

        Clients that registered with a session_id only receive tickets matching
        that session. Clients with no session_id (None) receive all tickets.
        """
        if not self._connections:
            return

        payload = self._serialize_ticket(ticket)
        message = json.dumps(payload)

        # Send to matching connections; remove dead ones
        dead: list[WebSocket] = []
        async with self._lock:
            connections = list(self._connections.items())

        for ws, ws_session_id in connections:
            # Filter: only send if client has no session filter or session matches
            if ws_session_id is not None and ws_session_id != ticket.session_id:
                continue
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.pop(ws, None)

    @staticmethod
    def _serialize_ticket(ticket) -> dict[str, Any]:
        # Support both Sprint-18 EscalationTicket (has .status) and
        # Sprint-9 EscalationTicketV1 (has .state)
        state_value = (
            ticket.status.value if hasattr(ticket, "status") else ticket.state.value
        )
        sla = getattr(ticket, "sla_seconds", getattr(ticket, "timeout_seconds", 300))
        return {
            "event": "ESCALATE",
            "ticket_id": str(ticket.ticket_id),
            "session_id": ticket.session_id,
            "agent_id": ticket.agent_id,
            "tool_name": ticket.tool_name,
            "risk_score": ticket.risk_score,
            "reason": getattr(ticket, "reason", ""),
            "state": state_value,
            "sla_seconds": sla,
            "taint_flags": ticket.taint_flags,
            "delegation_chain": ticket.delegation_chain,
            "created_at": ticket.created_at.isoformat(),
            "resolved_at": ticket.resolved_at.isoformat() if ticket.resolved_at else None,
        }

    async def listen(self, websocket: WebSocket) -> None:
        """Keep a WebSocket connection alive, handling incoming messages.

        Policy Console clients may send heartbeat pings or resolve commands.
        This coroutine blocks until the client disconnects.
        """
        try:
            while True:
                # Read messages (heartbeat/pong); we don't act on them
                await websocket.receive_text()
        except WebSocketDisconnect:
            await self.disconnect(websocket)


# Module-level singleton
escalation_ws_manager = EscalationWebSocketManager()
