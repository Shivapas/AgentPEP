"""MCP session tracker — maintains taint graph per MCP session.

APEP-101: Each MCP proxy session gets its own taint graph for tracking
data lineage across tool calls within that session. The tracker:
  - Creates a taint graph when an MCP session starts.
  - Labels tool outputs with taint nodes (source = TOOL_OUTPUT).
  - Propagates taint from tool inputs to outputs within the session.
  - Destroys the taint graph when the session ends.
  - Persists the graph to MongoDB on session close for forensic replay.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, UTC
from uuid import UUID

from app.models.policy import TaintLevel, TaintSource
from app.services.taint_graph import session_graph_manager

logger = logging.getLogger(__name__)


class MCPSessionTracker:
    """Manages taint graphs tied to MCP proxy sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, MCPSessionState] = {}

    def start_session(self, session_id: str, agent_id: str) -> None:
        """Initialise a taint graph and tracking state for a new MCP session."""
        session_graph_manager.create_session(session_id)
        self._sessions[session_id] = MCPSessionState(
            session_id=session_id,
            agent_id=agent_id,
            started_at=datetime.now(UTC),
        )
        logger.info("MCP session started: session_id=%s agent_id=%s", session_id, agent_id)

    def get_session(self, session_id: str) -> MCPSessionState | None:
        """Get the session state for a given session ID."""
        return self._sessions.get(session_id)

    def has_session(self, session_id: str) -> bool:
        return session_id in self._sessions

    def label_tool_input(
        self,
        session_id: str,
        tool_name: str,
        arg_name: str,
        value_hash: str | None = None,
        taint_level: TaintLevel = TaintLevel.TRUSTED,
        source: TaintSource = TaintSource.USER_PROMPT,
    ) -> UUID | None:
        """Label a tool call argument as a taint node in the session graph.

        Returns the node_id of the created taint node, or None if session not found.
        """
        graph = session_graph_manager.get_session(session_id)
        if graph is None:
            return None

        state = self._sessions.get(session_id)
        agent_id = state.agent_id if state else None

        node = graph.add_node(
            taint_level=taint_level,
            source=source,
            value=value_hash,
            agent_id=agent_id,
        )
        return node.node_id

    def label_tool_output(
        self,
        session_id: str,
        tool_call_id: str,
        input_node_ids: list[UUID] | None = None,
        value_hash: str | None = None,
    ) -> UUID | None:
        """Label a tool call output, propagating taint from input nodes.

        Returns the output node_id, or None if session not found.
        """
        graph = session_graph_manager.get_session(session_id)
        if graph is None:
            return None

        state = self._sessions.get(session_id)
        agent_id = state.agent_id if state else None

        if input_node_ids:
            node = graph.propagate_tool_chain(
                parent_ids=input_node_ids,
                source=TaintSource.TOOL_OUTPUT,
                tool_call_id=tool_call_id,
                agent_id=agent_id,
                value=value_hash,
            )
        else:
            node = graph.add_node(
                taint_level=TaintLevel.TRUSTED,
                source=TaintSource.TOOL_OUTPUT,
                value=value_hash,
                agent_id=agent_id,
                tool_call_id=tool_call_id,
            )

        if state:
            state.tool_call_count += 1
            state.last_tool_call_id = tool_call_id

        return node.node_id

    def get_taint_node_ids_for_args(
        self, session_id: str, tool_name: str
    ) -> list[UUID]:
        """Get all taint node IDs currently tracked for this session.

        Used to pass into the Intercept API for taint checking.
        """
        state = self._sessions.get(session_id)
        if state is None:
            import logging

            logging.getLogger(__name__).warning(
                "Taint node lookup for unknown session %s (tool=%s) — returning empty",
                session_id,
                tool_name,
            )
            return []
        return list(state.tracked_input_nodes)

    def track_input_nodes(self, session_id: str, node_ids: list[UUID]) -> None:
        """Record input node IDs for the current tool call in this session."""
        state = self._sessions.get(session_id)
        if state is not None:
            state.tracked_input_nodes.extend(node_ids)

    async def end_session(self, session_id: str) -> None:
        """Persist and destroy the taint graph for a closed MCP session."""
        state = self._sessions.pop(session_id, None)
        if state is None:
            return

        # Persist to MongoDB for forensic replay
        try:
            await session_graph_manager.persist_session(session_id)
        except Exception:
            logger.exception(
                "Failed to persist taint graph for MCP session %s", session_id
            )

        session_graph_manager.destroy_session(session_id)
        logger.info(
            "MCP session ended: session_id=%s tool_calls=%d",
            session_id,
            state.tool_call_count,
        )

    def active_session_count(self) -> int:
        return len(self._sessions)

    def list_sessions(self) -> list[str]:
        return list(self._sessions.keys())


class MCPSessionState:
    """In-memory state for a single MCP proxy session."""

    __slots__ = (
        "session_id",
        "agent_id",
        "started_at",
        "tool_call_count",
        "last_tool_call_id",
        "tracked_input_nodes",
    )

    def __init__(self, session_id: str, agent_id: str, started_at: datetime) -> None:
        self.session_id = session_id
        self.agent_id = agent_id
        self.started_at = started_at
        self.tool_call_count: int = 0
        self.last_tool_call_id: str | None = None
        self.tracked_input_nodes: list[UUID] = []


# Module-level singleton
mcp_session_tracker = MCPSessionTracker()
