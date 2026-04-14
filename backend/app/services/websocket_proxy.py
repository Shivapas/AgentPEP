"""WebSocket Proxy — Bidirectional WebSocket proxy with DLP and injection scanning.

Sprint 47 — APEP-377: Implements a bidirectional WebSocket proxy that relays
frames between client and upstream server while scanning each frame for DLP
violations and injection attacks.

APEP-377.c: Core business logic — WebSocket proxy with frame relay.
APEP-377.d: API endpoint and service wiring.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from app.models.forward_proxy import (
    FrameScanResult,
    FrameScanVerdict,
    WebSocketFrameType,
    WebSocketProxyConfig,
    WebSocketProxyRequest,
    WebSocketProxySession,
    WebSocketProxyState,
    WebSocketProxyStats,
)

logger = logging.getLogger(__name__)

# Allowed WebSocket URL schemes
_ALLOWED_WS_SCHEMES = {"ws", "wss"}


class WebSocketProxy:
    """Bidirectional WebSocket proxy with DLP and injection frame scanning.

    For each proxied WebSocket connection:
      1. Validate the target URL (scheme, hostname checks).
      2. Connect to the upstream WebSocket server.
      3. Relay frames bidirectionally.
      4. Scan each text frame for DLP violations and injection patterns.
      5. Block or log frames that trigger security findings.

    Thread-safe: each connection runs as an independent asyncio Task.
    """

    def __init__(self, config: WebSocketProxyConfig | None = None) -> None:
        self._config = config or WebSocketProxyConfig()
        self._sessions: dict[str, WebSocketProxySession] = {}
        self._stats = WebSocketProxyStats()
        self._frame_scanner: Any = None  # set via set_frame_scanner
        self._hostname_checker: Any = None  # set via set_hostname_checker
        self._kafka_producer: Any = None  # set via set_kafka_producer

    # ------------------------------------------------------------------
    # Dependency injection
    # ------------------------------------------------------------------

    def set_frame_scanner(self, scanner: Any) -> None:
        """Inject the WebSocket frame DLP/injection scanner."""
        self._frame_scanner = scanner

    def set_hostname_checker(self, checker: Any) -> None:
        """Inject the hostname blocking service."""
        self._hostname_checker = checker

    def set_kafka_producer(self, producer: Any) -> None:
        """Inject the Kafka producer for network events."""
        self._kafka_producer = producer

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def validate_target(self, target_url: str) -> tuple[bool, str]:
        """Validate a WebSocket target URL.

        Returns (is_valid, error_message).
        """
        try:
            parsed = urlparse(target_url)
        except Exception:
            return False, "Invalid URL"

        if parsed.scheme not in _ALLOWED_WS_SCHEMES:
            return False, f"Invalid scheme: {parsed.scheme} (must be ws or wss)"

        hostname = parsed.hostname or ""
        if not hostname:
            return False, "Empty hostname"

        # Check hostname against blocklist
        if self._hostname_checker:
            blocked, reason = self._hostname_checker.is_blocked(hostname)
            if blocked:
                return False, f"Hostname blocked: {reason}"

        return True, ""

    async def create_session(
        self, request: WebSocketProxyRequest
    ) -> WebSocketProxySession:
        """Create a new WebSocket proxy session.

        Does not establish the connection — call ``proxy_connection()``
        with the returned session to start relaying frames.
        """
        if len(self._sessions) >= self._config.max_connections:
            raise ValueError("Maximum WebSocket proxy connections reached")

        session = WebSocketProxySession(
            target_url=request.target_url,
            session_id=request.session_id,
            agent_id=request.agent_id,
        )
        session_id = str(session.ws_session_id)
        self._sessions[session_id] = session
        self._stats.total_connections += 1
        self._stats.active_connections += 1

        return session

    async def close_session(self, ws_session_id: str) -> None:
        """Close and clean up a WebSocket proxy session."""
        from datetime import UTC, datetime

        session = self._sessions.pop(ws_session_id, None)
        if session:
            session.state = WebSocketProxyState.CLOSED
            session.closed_at = datetime.now(UTC)
            self._stats.active_connections = max(0, self._stats.active_connections - 1)

    async def proxy_websocket(
        self,
        ws_session_id: str,
        client_ws: Any,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        """Proxy a WebSocket connection bidirectionally.

        Args:
            ws_session_id: Session ID from create_session().
            client_ws: The client-facing WebSocket connection (FastAPI WebSocket).
            extra_headers: Additional headers to pass to upstream.
        """
        session = self._sessions.get(ws_session_id)
        if not session:
            raise ValueError(f"Unknown WebSocket session: {ws_session_id}")

        try:
            import websockets
            from websockets.asyncio.client import connect as ws_connect
        except ImportError:
            logger.error("websockets library not installed")
            session.state = WebSocketProxyState.ERROR
            return

        # Connect to upstream
        connect_kwargs: dict[str, Any] = {
            "max_size": self._config.max_frame_size,
        }
        if extra_headers:
            connect_kwargs["additional_headers"] = extra_headers

        try:
            async with ws_connect(
                session.target_url, **connect_kwargs
            ) as upstream_ws:
                session.state = WebSocketProxyState.OPEN

                # Bidirectional relay
                await self._relay_frames(session, client_ws, upstream_ws)

        except Exception as exc:
            logger.error(
                "websocket_proxy_error",
                ws_session_id=ws_session_id,
                error=str(exc),
            )
            session.state = WebSocketProxyState.ERROR
        finally:
            await self.close_session(ws_session_id)

    async def _relay_frames(
        self,
        session: WebSocketProxySession,
        client_ws: Any,
        upstream_ws: Any,
    ) -> None:
        """Relay frames between client and upstream WebSocket connections."""

        async def client_to_upstream() -> None:
            """Relay client frames to upstream, scanning each frame."""
            try:
                async for message in client_ws:
                    if isinstance(message, str):
                        frame_type = WebSocketFrameType.TEXT
                        data = message
                    elif isinstance(message, bytes):
                        frame_type = WebSocketFrameType.BINARY
                        data = message.decode("utf-8", errors="replace")
                    else:
                        continue

                    session.frames_sent += 1
                    session.bytes_sent += len(data)

                    # Scan outbound frame
                    scan_result = await self._scan_frame(
                        data, frame_type, session, direction="outbound"
                    )

                    if scan_result and scan_result.verdict == FrameScanVerdict.BLOCK:
                        session.frames_blocked += 1
                        continue  # Drop the frame

                    if scan_result and scan_result.verdict == FrameScanVerdict.REDACT:
                        data = scan_result.redacted_data or "[REDACTED]"

                    if isinstance(message, bytes):
                        await upstream_ws.send(data.encode("utf-8"))
                    else:
                        await upstream_ws.send(data)

            except Exception:
                pass  # Connection closed

        async def upstream_to_client() -> None:
            """Relay upstream frames to client, scanning each frame."""
            try:
                async for message in upstream_ws:
                    if isinstance(message, str):
                        frame_type = WebSocketFrameType.TEXT
                        data = message
                    elif isinstance(message, bytes):
                        frame_type = WebSocketFrameType.BINARY
                        data = message.decode("utf-8", errors="replace")
                    else:
                        continue

                    session.frames_received += 1
                    session.bytes_received += len(data)

                    # Scan inbound frame
                    scan_result = await self._scan_frame(
                        data, frame_type, session, direction="inbound"
                    )

                    if scan_result and scan_result.verdict == FrameScanVerdict.BLOCK:
                        session.frames_blocked += 1
                        continue  # Drop the frame

                    if scan_result and scan_result.verdict == FrameScanVerdict.REDACT:
                        data = scan_result.redacted_data or "[REDACTED]"

                    if isinstance(message, bytes):
                        await client_ws.send(data.encode("utf-8"))
                    else:
                        await client_ws.send(data)

            except Exception:
                pass  # Connection closed

        # Run both directions concurrently
        task_c2u = asyncio.create_task(client_to_upstream())
        task_u2c = asyncio.create_task(upstream_to_client())

        done, pending = await asyncio.wait(
            {task_c2u, task_u2c},
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def _scan_frame(
        self,
        data: str,
        frame_type: WebSocketFrameType,
        session: WebSocketProxySession,
        direction: str,
    ) -> FrameScanResult | None:
        """Scan a WebSocket frame for DLP and injection findings."""
        if not self._frame_scanner:
            return None

        # Only scan text frames (or binary if configured)
        if frame_type == WebSocketFrameType.TEXT and not self._config.scan_text_frames:
            return None
        if frame_type == WebSocketFrameType.BINARY and not self._config.scan_binary_frames:
            return None

        try:
            result = self._frame_scanner.scan_frame(
                data=data,
                frame_type=frame_type,
                direction=direction,
                session_id=session.session_id,
                agent_id=session.agent_id,
            )

            if result.dlp_findings:
                session.dlp_findings_count += len(result.dlp_findings)
                self._stats.dlp_hit_count += len(result.dlp_findings)
            if result.injection_findings:
                session.injection_findings_count += len(result.injection_findings)
                self._stats.injection_hit_count += len(result.injection_findings)

            self._stats.total_frames_scanned += 1
            if result.verdict == FrameScanVerdict.BLOCK:
                self._stats.total_frames_blocked += 1

            return result
        except Exception:
            logger.exception("Frame scan error")
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_stats(self) -> WebSocketProxyStats:
        """Return current proxy statistics."""
        self._stats.active_connections = len(self._sessions)
        return self._stats.model_copy()

    def get_sessions(self) -> list[WebSocketProxySession]:
        """Return a snapshot of active sessions."""
        return [s.model_copy() for s in self._sessions.values()]

    @property
    def config(self) -> WebSocketProxyConfig:
        return self._config


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

websocket_proxy = WebSocketProxy()
