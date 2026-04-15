"""Session-wide typed marker store — Sprint 55 (APEP-437).

Manages in-memory per-session markers that record significant tool call
events.  Markers are consumed by the SEQ rule engine to detect behavioural
sequences (e.g. file read followed by external exfiltration).

Markers expire after their TTL and are pruned lazily on access.
"""

from __future__ import annotations

import logging
import time
from typing import Any
from uuid import UUID

from app.models.camel_seq import MarkerType, SessionMarker

logger = logging.getLogger(__name__)


class SessionMarkerManager:
    """Per-session marker store with automatic TTL expiry (APEP-437).

    Each session maintains an ordered list of markers.  The store is
    in-memory and stateless across restarts — suitable for session-scoped
    behavioural detection.
    """

    def __init__(self, max_markers_per_session: int = 500) -> None:
        self._sessions: dict[str, list[SessionMarker]] = {}
        self._max_markers = max_markers_per_session

    def place_marker(
        self,
        session_id: str,
        marker_type: MarkerType,
        tool_name: str = "",
        agent_id: str = "",
        metadata: dict[str, Any] | None = None,
        ttl_seconds: int = 600,
    ) -> SessionMarker:
        """Place a typed marker in the session.

        Returns the created marker.
        """
        marker = SessionMarker(
            session_id=session_id,
            marker_type=marker_type,
            tool_name=tool_name,
            agent_id=agent_id,
            metadata=metadata or {},
            ttl_seconds=ttl_seconds,
        )

        if session_id not in self._sessions:
            self._sessions[session_id] = []

        markers = self._sessions[session_id]
        markers.append(marker)

        # Prune expired and enforce max limit
        self._prune_session(session_id)

        if len(markers) > self._max_markers:
            # Drop oldest markers
            self._sessions[session_id] = markers[-self._max_markers :]

        logger.debug(
            "Marker placed: session=%s type=%s tool=%s",
            session_id,
            marker_type.value,
            tool_name,
        )
        return marker

    def get_markers(
        self,
        session_id: str,
        marker_type: MarkerType | None = None,
        since_seconds: int | None = None,
    ) -> list[SessionMarker]:
        """Get active (non-expired) markers for a session.

        Args:
            session_id: Session to query.
            marker_type: Optional filter by marker type.
            since_seconds: Optional filter — only markers created in the last N seconds.
        """
        self._prune_session(session_id)
        markers = self._sessions.get(session_id, [])

        if marker_type is not None:
            markers = [m for m in markers if m.marker_type == marker_type]

        if since_seconds is not None:
            cutoff = time.time() - since_seconds
            markers = [
                m for m in markers if m.created_at.timestamp() >= cutoff
            ]

        return markers

    def get_all_markers(self, session_id: str) -> list[SessionMarker]:
        """Get all active markers for a session (no filtering)."""
        self._prune_session(session_id)
        return list(self._sessions.get(session_id, []))

    def clear_session(self, session_id: str) -> int:
        """Clear all markers for a session. Returns count removed."""
        markers = self._sessions.pop(session_id, [])
        return len(markers)

    def session_count(self) -> int:
        """Number of sessions with active markers."""
        return len(self._sessions)

    def marker_count(self, session_id: str) -> int:
        """Number of active markers in a session."""
        self._prune_session(session_id)
        return len(self._sessions.get(session_id, []))

    def _prune_session(self, session_id: str) -> None:
        """Remove expired markers from a session."""
        markers = self._sessions.get(session_id)
        if not markers:
            return

        now = time.time()
        active = [
            m
            for m in markers
            if (m.created_at.timestamp() + m.ttl_seconds) > now
        ]

        if len(active) != len(markers):
            logger.debug(
                "Pruned %d expired markers from session %s",
                len(markers) - len(active),
                session_id,
            )

        if active:
            self._sessions[session_id] = active
        else:
            self._sessions.pop(session_id, None)

    def classify_tool_call(self, tool_name: str) -> MarkerType | None:
        """Classify a tool call into a marker type based on tool name patterns.

        Returns None if the tool doesn't map to a marker type.
        """
        import fnmatch

        _TOOL_MARKER_MAP: list[tuple[list[str], MarkerType]] = [
            (
                ["file.read", "*.read", "fs.read*", "db.query", "db.read*"],
                MarkerType.FILE_READ,
            ),
            (
                ["secret.*", "credential.*", "vault.*", "*.get_secret"],
                MarkerType.SECRET_ACCESS,
            ),
            (
                [
                    "http.post",
                    "http.put",
                    "http.patch",
                    "fetch.*",
                    "net.send",
                    "api.post*",
                    "webhook.*",
                    "curl.*",
                ],
                MarkerType.NETWORK_SEND,
            ),
            (
                ["http.*", "net.*", "api.*"],
                MarkerType.EXTERNAL_WRITE,
            ),
            (
                [
                    "file.write",
                    "fs.write*",
                    "config.write",
                    "config.set",
                    "settings.*",
                ],
                MarkerType.CONFIG_WRITE,
            ),
            (
                ["shell.exec", "bash.*", "cmd.*", "exec.*", "subprocess.*"],
                MarkerType.SHELL_EXEC,
            ),
            (
                ["npm.install", "pip.install", "package.*", "*.install"],
                MarkerType.PACKAGE_INSTALL,
            ),
        ]

        tool_lower = tool_name.lower()
        for patterns, marker_type in _TOOL_MARKER_MAP:
            for pattern in patterns:
                if fnmatch.fnmatch(tool_lower, pattern.lower()):
                    return marker_type

        return None


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

session_marker_manager = SessionMarkerManager()
