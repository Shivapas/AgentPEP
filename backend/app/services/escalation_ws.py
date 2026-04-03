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
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        async with self._lock:
            self._connections.add(websocket)
        logger.info(
            "Policy Console WebSocket connected (total=%d)", len(self._connections)
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            self._connections.discard(websocket)
        logger.info(
            "Policy Console WebSocket disconnected (total=%d)", len(self._connections)
        )

    async def broadcast_ticket(self, ticket: EscalationTicket) -> None:
        """Push an escalation ticket event to all connected sessions."""
        if not self._connections:
            return

        payload = self._serialize_ticket(ticket)
        message = json.dumps(payload)

        # Send to all connections; remove dead ones
        dead: list[WebSocket] = []
        async with self._lock:
            connections = list(self._connections)

        for ws in connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)

    @staticmethod
    def _serialize_ticket(ticket: EscalationTicket) -> dict[str, Any]:
        return {
            "event": "ESCALATE",
            "ticket_id": str(ticket.ticket_id),
            "request_id": str(ticket.request_id),
            "session_id": ticket.session_id,
            "agent_id": ticket.agent_id,
            "tool_name": ticket.tool_name,
            "risk_score": ticket.risk_score,
            "reason": ticket.reason,
            "state": ticket.state.value,
            "assigned_to": ticket.assigned_to,
            "timeout_seconds": ticket.timeout_seconds,
            "taint_flags": ticket.taint_flags,
            "delegation_chain": ticket.delegation_chain,
            "created_at": ticket.created_at.isoformat(),
            "resolved_at": ticket.resolved_at.isoformat() if ticket.resolved_at else None,
        }

    async def listen(self, websocket: WebSocket) -> None:
        """Keep a WebSocket connection alive, handling incoming messages.

        Policy Console clients may send heartbeat pings or resolve commands.
        This coroutine blocks until the client disconnects.
        Disconnect cleanup is handled by the caller's finally block.
        """
        try:
            while True:
                # Read messages (heartbeat/pong); we don't act on them
                await websocket.receive_text()
        except WebSocketDisconnect:
            pass


# Module-level singleton
escalation_ws_manager = EscalationWebSocketManager()
