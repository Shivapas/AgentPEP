"""WebSocket server for pushing ESCALATE events to Policy Console sessions (APEP-074).

Connected clients receive real-time notifications when escalation tickets are
created or resolved. The server maintains connections keyed by session_id and
broadcasts events only to clients subscribed to the relevant session.
"""

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from app.models.policy import EscalationTicket

logger = logging.getLogger(__name__)


class EscalationWebSocketManager:
    """Manages WebSocket connections for escalation event broadcasting (APEP-074).

    Connections are scoped by session_id so that escalation ticket events are
    only broadcast to clients subscribed to the relevant session, preventing
    cross-session information leakage.
    """

    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = {}
        self._ws_sessions: dict[WebSocket, str] = {}
        self._lock = asyncio.Lock()

    @property
    def connection_count(self) -> int:
        return sum(len(conns) for conns in self._connections.values())

    async def connect(self, websocket: WebSocket, session_id: str) -> None:
        """Accept and register a new WebSocket connection scoped to a session."""
        await websocket.accept()
        async with self._lock:
            if session_id not in self._connections:
                self._connections[session_id] = set()
            self._connections[session_id].add(websocket)
            self._ws_sessions[websocket] = session_id
        logger.info(
            "Policy Console WebSocket connected session=%s (total=%d)",
            session_id,
            self.connection_count,
        )

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        async with self._lock:
            session_id = self._ws_sessions.pop(websocket, None)
            if session_id and session_id in self._connections:
                self._connections[session_id].discard(websocket)
                if not self._connections[session_id]:
                    del self._connections[session_id]
        logger.info(
            "Policy Console WebSocket disconnected (total=%d)", self.connection_count
        )

    async def broadcast_ticket(self, ticket: EscalationTicket) -> None:
        """Push an escalation ticket event only to clients in the ticket's session."""
        session_id = ticket.session_id
        async with self._lock:
            session_conns = list(self._connections.get(session_id, set()))

        if not session_conns:
            return

        payload = self._serialize_ticket(ticket)
        message = json.dumps(payload)

        # Send to session connections; remove dead ones
        dead: list[WebSocket] = []
        for ws in session_conns:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    sid = self._ws_sessions.pop(ws, None)
                    if sid and sid in self._connections:
                        self._connections[sid].discard(ws)
                        if not self._connections[sid]:
                            del self._connections[sid]

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
