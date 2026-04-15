"""Session-wide Typed Marker System — Sprint 55 (APEP-437).

Manages per-session typed markers used by CaMeL-lite SEQ rules for
gap-tolerant behavioural sequence detection.  Markers track events
like FILE_READ, EXTERNAL_HTTP, etc., and persist to MongoDB for
cross-request visibility within a session.

Markers are automatically placed by the ToolCallChainDetector when
tool calls match known marker-producing patterns (e.g. file.read → FILE_READ).
SEQ rules then query the marker store to detect dangerous sequences
regardless of gap events between them.
"""

from __future__ import annotations

import fnmatch
import logging
import time
from datetime import UTC, datetime

from app.db import mongodb as db_module
from app.models.camel_seq import (
    MarkerType,
    SessionMarker,
    SessionMarkerListResponse,
    SessionMarkerQuery,
)

logger = logging.getLogger(__name__)

# MongoDB collection for session markers
SESSION_MARKERS_COLLECTION = "session_markers"

# ---------------------------------------------------------------------------
# Tool-to-marker mapping: which tool patterns produce which marker types
# ---------------------------------------------------------------------------

_TOOL_MARKER_MAP: list[tuple[str, MarkerType]] = [
    ("file.read", MarkerType.FILE_READ),
    ("file.read.*", MarkerType.FILE_READ),
    ("*.read", MarkerType.FILE_READ),
    ("db.read*", MarkerType.FILE_READ),
    ("file.write", MarkerType.FILE_WRITE),
    ("file.write.*", MarkerType.FILE_WRITE),
    ("config.read*", MarkerType.CONFIG_READ),
    ("config.get*", MarkerType.CONFIG_READ),
    ("config.write*", MarkerType.CONFIG_WRITE),
    ("config.set*", MarkerType.CONFIG_WRITE),
    ("config.update*", MarkerType.CONFIG_WRITE),
    ("secret.*", MarkerType.SECRET_ACCESS),
    ("credential.*", MarkerType.SECRET_ACCESS),
    ("vault.*", MarkerType.SECRET_ACCESS),
    ("env.read*", MarkerType.ENV_READ),
    ("env.get*", MarkerType.ENV_READ),
    ("env.list*", MarkerType.ENV_READ),
    ("http.post", MarkerType.EXTERNAL_HTTP),
    ("http.put", MarkerType.EXTERNAL_HTTP),
    ("http.get", MarkerType.EXTERNAL_HTTP),
    ("http.*", MarkerType.EXTERNAL_HTTP),
    ("fetch.*", MarkerType.EXTERNAL_HTTP),
    ("curl.*", MarkerType.EXTERNAL_HTTP),
    ("dns.*", MarkerType.DNS_EXFIL),
    ("nslookup*", MarkerType.DNS_EXFIL),
    ("shell.exec", MarkerType.SHELL_EXEC),
    ("exec.*", MarkerType.SHELL_EXEC),
    ("bash.*", MarkerType.SHELL_EXEC),
    ("network.send*", MarkerType.NETWORK_SEND),
    ("socket.send*", MarkerType.NETWORK_SEND),
]


class SessionMarkerService:
    """Manages session-wide typed markers for CaMeL-lite SEQ rules (APEP-437)."""

    def classify_tool(self, tool_name: str) -> list[MarkerType]:
        """Determine which marker types a tool call produces.

        Returns all matching marker types (a tool may produce multiple).
        """
        result: list[MarkerType] = []
        for pattern, marker_type in _TOOL_MARKER_MAP:
            if fnmatch.fnmatch(tool_name, pattern):
                if marker_type not in result:
                    result.append(marker_type)
        return result

    async def place_marker(
        self,
        session_id: str,
        marker_type: MarkerType,
        tool_name: str = "",
        tool_call_id: str = "",
        agent_id: str = "",
        metadata: dict | None = None,
    ) -> SessionMarker:
        """Place a typed marker in the session marker store."""
        marker = SessionMarker(
            session_id=session_id,
            marker_type=marker_type,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            agent_id=agent_id,
            metadata=metadata or {},
        )

        try:
            db = db_module.get_database()
            await db[SESSION_MARKERS_COLLECTION].insert_one(
                marker.model_dump(mode="json")
            )
        except Exception:
            logger.warning(
                "Failed to persist session marker %s for session %s",
                marker.marker_id,
                session_id,
                exc_info=True,
            )

        return marker

    async def place_markers_for_tool(
        self,
        session_id: str,
        tool_name: str,
        tool_call_id: str = "",
        agent_id: str = "",
        metadata: dict | None = None,
    ) -> list[SessionMarker]:
        """Auto-classify a tool call and place all applicable markers."""
        marker_types = self.classify_tool(tool_name)
        markers: list[SessionMarker] = []
        for mt in marker_types:
            m = await self.place_marker(
                session_id=session_id,
                marker_type=mt,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                agent_id=agent_id,
                metadata=metadata,
            )
            markers.append(m)
        return markers

    async def get_markers(
        self,
        query: SessionMarkerQuery,
    ) -> SessionMarkerListResponse:
        """Query session markers from the store."""
        try:
            db = db_module.get_database()
            filt: dict = {"session_id": query.session_id}
            if query.marker_types:
                filt["marker_type"] = {"$in": [mt.value for mt in query.marker_types]}
            if query.since:
                filt["created_at"] = {"$gte": query.since.isoformat()}

            cursor = (
                db[SESSION_MARKERS_COLLECTION]
                .find(filt, {"_id": 0})
                .sort("created_at", 1)
                .limit(query.limit)
            )
            markers: list[SessionMarker] = []
            async for doc in cursor:
                markers.append(SessionMarker.model_validate(doc))

            total = await db[SESSION_MARKERS_COLLECTION].count_documents(filt)
            return SessionMarkerListResponse(
                markers=markers,
                total=total,
                session_id=query.session_id,
            )
        except Exception:
            logger.warning(
                "Failed to query session markers for %s",
                query.session_id,
                exc_info=True,
            )
            return SessionMarkerListResponse(session_id=query.session_id)

    async def has_marker_types(
        self,
        session_id: str,
        required_types: list[MarkerType],
    ) -> dict[MarkerType, bool]:
        """Check which of the required marker types exist in the session.

        Used by SEQ rules for gap-tolerant sequence detection.
        Returns a dict mapping each type to True/False.
        """
        result = {mt: False for mt in required_types}
        try:
            db = db_module.get_database()
            for mt in required_types:
                count = await db[SESSION_MARKERS_COLLECTION].count_documents(
                    {"session_id": session_id, "marker_type": mt.value},
                )
                result[mt] = count > 0
        except Exception:
            logger.warning(
                "Failed to check marker types for session %s",
                session_id,
                exc_info=True,
            )
        return result

    async def get_ordered_markers(
        self,
        session_id: str,
        marker_types: list[MarkerType] | None = None,
    ) -> list[SessionMarker]:
        """Get markers in chronological order, optionally filtered by type."""
        query = SessionMarkerQuery(
            session_id=session_id,
            marker_types=marker_types,
            limit=1000,
        )
        resp = await self.get_markers(query)
        return resp.markers

    async def clear_session(self, session_id: str) -> int:
        """Remove all markers for a session (for cleanup/testing)."""
        try:
            db = db_module.get_database()
            result = await db[SESSION_MARKERS_COLLECTION].delete_many(
                {"session_id": session_id}
            )
            return result.deleted_count
        except Exception:
            logger.warning(
                "Failed to clear markers for session %s",
                session_id,
                exc_info=True,
            )
            return 0


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

session_marker_service = SessionMarkerService()
