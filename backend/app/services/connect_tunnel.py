"""Asyncio CONNECT Tunnel Handler — Forward Proxy.

Sprint 47 — APEP-372: Implements an HTTPS_PROXY-compatible forward proxy using
asyncio CONNECT tunneling.  The handler listens for HTTP CONNECT requests,
validates them against hostname policies and DLP rules, then establishes a
bidirectional byte relay between the client and the upstream server.

APEP-372.c: Core logic — asyncio StreamReader/StreamWriter CONNECT tunnel.
APEP-372.e: Pipeline integration — hostname blocking, DLP pre-scan, Kafka events.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any
from uuid import uuid4

from app.models.forward_proxy import (
    ConnectRequest,
    ConnectTunnelConfig,
    TunnelCloseReason,
    TunnelSession,
    TunnelState,
    TunnelStats,
    TLSInterceptionMode,
)
from app.models.network_scan import (
    NetworkEvent,
    NetworkEventType,
    ScanSeverity,
)

logger = logging.getLogger(__name__)

# Maximum size for an HTTP request line (CONNECT host:port HTTP/1.1)
_MAX_REQUEST_LINE = 8192


class ConnectTunnelHandler:
    """Asyncio-based CONNECT tunnel handler for HTTPS_PROXY forwarding.

    Lifecycle:
      1. Client sends ``CONNECT host:port HTTP/1.1``
      2. Handler parses the request, validates hostname against blocklist
      3. If allowed, connects to upstream, replies ``200 Connection Established``
      4. Relays bytes bidirectionally until one side disconnects or a policy
         violation is detected.

    Thread-safe: each tunnel runs as an independent asyncio Task.
    """

    def __init__(self, config: ConnectTunnelConfig | None = None) -> None:
        self._config = config or ConnectTunnelConfig()
        self._active_tunnels: dict[str, TunnelSession] = {}
        self._stats = TunnelStats()
        self._server: asyncio.AbstractServer | None = None
        self._hostname_checker: Any = None  # set via set_hostname_checker
        self._dlp_scanner: Any = None  # set via set_dlp_scanner
        self._kafka_producer: Any = None  # set via set_kafka_producer

    # ------------------------------------------------------------------
    # Dependency injection
    # ------------------------------------------------------------------

    def set_hostname_checker(self, checker: Any) -> None:
        """Inject the hostname blocking service."""
        self._hostname_checker = checker

    def set_dlp_scanner(self, scanner: Any) -> None:
        """Inject the DLP scanner for request body scanning."""
        self._dlp_scanner = scanner

    def set_kafka_producer(self, producer: Any) -> None:
        """Inject the Kafka producer for network events."""
        self._kafka_producer = producer

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the CONNECT tunnel server."""
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self._config.listen_host,
            port=self._config.listen_port,
        )
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        logger.info("connect_tunnel_started", addrs=addrs)

    async def stop(self) -> None:
        """Gracefully stop the tunnel server and close all active tunnels."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        # Close all active tunnels
        for tunnel_id in list(self._active_tunnels.keys()):
            await self._close_tunnel(tunnel_id, TunnelCloseReason.ADMIN_KILL)

        logger.info(
            "connect_tunnel_stopped",
            total_tunnels=self._stats.total_tunnels,
        )

    # ------------------------------------------------------------------
    # Client connection handler
    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single client connection expecting a CONNECT request."""
        client_addr = writer.get_extra_info("peername")
        client_addr_str = f"{client_addr[0]}:{client_addr[1]}" if client_addr else "unknown"

        try:
            # 1. Read the CONNECT request line
            request = await self._read_connect_request(reader)
            if request is None:
                await self._send_error(writer, 400, "Bad Request")
                return

            logger.info(
                "connect_request",
                hostname=request.hostname,
                port=request.port,
                client=client_addr_str,
            )

            # 2. Check concurrent tunnel limit
            if len(self._active_tunnels) >= self._config.max_tunnels:
                await self._send_error(writer, 503, "Too Many Tunnels")
                return

            # 3. Validate port is allowed
            if request.port not in self._config.allowed_ports:
                await self._send_error(writer, 403, "Port Not Allowed")
                return

            # 4. Hostname blocking check (APEP-374)
            if self._config.enable_hostname_blocking and self._hostname_checker:
                is_blocked, reason = self._hostname_checker.is_blocked(request.hostname)
                if is_blocked:
                    logger.info(
                        "connect_blocked_hostname",
                        hostname=request.hostname,
                        reason=reason,
                    )
                    await self._send_error(writer, 403, f"Blocked: {reason}")
                    await self._emit_block_event(request, reason)
                    return

            # 5. Create tunnel session
            session = TunnelSession(
                hostname=request.hostname,
                port=request.port,
                state=TunnelState.PENDING,
                session_id=request.session_id,
                agent_id=request.agent_id,
                client_addr=client_addr_str,
            )
            tunnel_id = str(session.tunnel_id)
            self._active_tunnels[tunnel_id] = session
            self._stats.total_tunnels += 1

            # 6. Connect to upstream
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(request.hostname, request.port),
                    timeout=30.0,
                )
            except (OSError, asyncio.TimeoutError) as exc:
                session.state = TunnelState.ERROR
                session.close_reason = TunnelCloseReason.ERROR
                await self._send_error(writer, 502, f"Cannot connect to upstream: {exc}")
                self._active_tunnels.pop(tunnel_id, None)
                return

            # 7. Send 200 Connection Established
            session.state = TunnelState.ESTABLISHED
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            self._stats.active_tunnels += 1

            # 8. Bidirectional relay
            try:
                await self._relay(
                    tunnel_id,
                    reader,
                    writer,
                    upstream_reader,
                    upstream_writer,
                )
            finally:
                self._stats.active_tunnels = max(0, self._stats.active_tunnels - 1)
                upstream_writer.close()

        except Exception:
            logger.exception("connect_tunnel_error", client=client_addr_str)
        finally:
            writer.close()

    # ------------------------------------------------------------------
    # CONNECT request parsing
    # ------------------------------------------------------------------

    async def _read_connect_request(
        self, reader: asyncio.StreamReader
    ) -> ConnectRequest | None:
        """Parse an HTTP CONNECT request from the client stream.

        Expected format: ``CONNECT host:port HTTP/1.1\\r\\n`` followed by
        optional headers terminated by ``\\r\\n\\r\\n``.
        """
        try:
            request_line = await asyncio.wait_for(
                reader.readline(), timeout=30.0
            )
        except asyncio.TimeoutError:
            return None

        if not request_line:
            return None

        line = request_line.decode("utf-8", errors="replace").strip()
        parts = line.split()

        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            return None

        # Parse host:port
        target = parts[1]
        if ":" in target:
            hostname, port_str = target.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                return None
        else:
            hostname = target
            port = 443

        # Consume remaining headers until blank line
        while True:
            try:
                header_line = await asyncio.wait_for(
                    reader.readline(), timeout=10.0
                )
            except asyncio.TimeoutError:
                break
            if header_line in (b"\r\n", b"\n", b""):
                break

        return ConnectRequest(
            hostname=hostname,
            port=port,
            raw_line=line,
        )

    # ------------------------------------------------------------------
    # Bidirectional relay
    # ------------------------------------------------------------------

    async def _relay(
        self,
        tunnel_id: str,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        """Relay bytes bidirectionally between client and upstream."""
        session = self._active_tunnels.get(tunnel_id)
        if not session:
            return

        buffer_size = self._config.buffer_size

        async def client_to_upstream() -> TunnelCloseReason:
            """Relay from client to upstream server."""
            try:
                while True:
                    data = await asyncio.wait_for(
                        client_reader.read(buffer_size),
                        timeout=self._config.idle_timeout_s,
                    )
                    if not data:
                        return TunnelCloseReason.CLIENT_DISCONNECT
                    # DLP scan on outbound data if TLS interception is active
                    if (
                        self._config.enable_dlp_scan
                        and session.tls_interception_mode == TLSInterceptionMode.INTERCEPT
                        and self._dlp_scanner
                    ):
                        findings = self._dlp_scanner.scan_text(data.decode("utf-8", errors="replace"))
                        if findings:
                            session.dlp_findings_count += len(findings)
                            self._stats.dlp_hit_count += len(findings)
                            await self._emit_dlp_event(session, findings)
                    session.bytes_sent += len(data)
                    upstream_writer.write(data)
                    await upstream_writer.drain()
            except asyncio.TimeoutError:
                return TunnelCloseReason.IDLE_TIMEOUT
            except (ConnectionError, OSError):
                return TunnelCloseReason.CLIENT_DISCONNECT

        async def upstream_to_client() -> TunnelCloseReason:
            """Relay from upstream server to client."""
            try:
                while True:
                    data = await asyncio.wait_for(
                        upstream_reader.read(buffer_size),
                        timeout=self._config.idle_timeout_s,
                    )
                    if not data:
                        return TunnelCloseReason.SERVER_DISCONNECT
                    session.bytes_received += len(data)
                    client_writer.write(data)
                    await client_writer.drain()
            except asyncio.TimeoutError:
                return TunnelCloseReason.IDLE_TIMEOUT
            except (ConnectionError, OSError):
                return TunnelCloseReason.SERVER_DISCONNECT

        # Run both directions concurrently; when one ends, cancel the other
        task_c2u = asyncio.create_task(client_to_upstream())
        task_u2c = asyncio.create_task(upstream_to_client())

        done, pending = await asyncio.wait(
            {task_c2u, task_u2c},
            return_when=asyncio.FIRST_COMPLETED,
        )

        close_reason = TunnelCloseReason.CLIENT_DISCONNECT
        for task in done:
            try:
                close_reason = task.result()
            except Exception:
                close_reason = TunnelCloseReason.ERROR

        for task in pending:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        await self._close_tunnel(tunnel_id, close_reason)

    # ------------------------------------------------------------------
    # Tunnel cleanup
    # ------------------------------------------------------------------

    async def _close_tunnel(
        self, tunnel_id: str, reason: TunnelCloseReason
    ) -> None:
        """Mark a tunnel as closed and update statistics."""
        from datetime import UTC, datetime

        session = self._active_tunnels.pop(tunnel_id, None)
        if session is None:
            return

        session.state = TunnelState.CLOSED
        session.close_reason = reason
        session.closed_at = datetime.now(UTC)

        self._stats.total_bytes_transferred += session.bytes_sent + session.bytes_received

        if session.closed_at and session.started_at:
            duration = (session.closed_at - session.started_at).total_seconds()
            total = self._stats.total_tunnels
            if total > 0:
                self._stats.avg_tunnel_duration_s = (
                    (self._stats.avg_tunnel_duration_s * (total - 1) + duration) / total
                )

        logger.info(
            "tunnel_closed",
            tunnel_id=tunnel_id,
            hostname=session.hostname,
            reason=reason,
            bytes_sent=session.bytes_sent,
            bytes_received=session.bytes_received,
        )

    # ------------------------------------------------------------------
    # Error responses
    # ------------------------------------------------------------------

    @staticmethod
    async def _send_error(
        writer: asyncio.StreamWriter, status: int, message: str
    ) -> None:
        """Send an HTTP error response to the client."""
        response = (
            f"HTTP/1.1 {status} {message}\r\n"
            f"Content-Length: {len(message)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{message}"
        )
        writer.write(response.encode())
        await writer.drain()

    # ------------------------------------------------------------------
    # Event emission
    # ------------------------------------------------------------------

    async def _emit_block_event(
        self, request: ConnectRequest, reason: str
    ) -> None:
        """Emit a Kafka event for a blocked CONNECT request."""
        if not self._kafka_producer:
            return
        event = NetworkEvent(
            session_id=request.session_id,
            agent_id=request.agent_id,
            event_type=NetworkEventType.SSRF_BLOCKED,
            scanner="ConnectTunnelHandler",
            finding_rule_id="CONNECT-BLOCK-001",
            severity=ScanSeverity.HIGH,
            mitre_technique_id="T1090.001",
            url=f"{request.hostname}:{request.port}",
            blocked=True,
        )
        try:
            await self._kafka_producer.send(
                "agentpep.network", event.model_dump(mode="json")
            )
        except Exception:
            logger.exception("Failed to emit connect block event")

    async def _emit_dlp_event(
        self, session: TunnelSession, findings: list[Any]
    ) -> None:
        """Emit Kafka events for DLP findings in tunnel data."""
        if not self._kafka_producer:
            return
        for finding in findings[:5]:  # Limit to 5 events per batch
            event = NetworkEvent(
                session_id=session.session_id,
                agent_id=session.agent_id,
                event_type=NetworkEventType.DLP_HIT,
                scanner="ConnectTunnelHandler",
                finding_rule_id=getattr(finding, "rule_id", "DLP-TUNNEL"),
                severity=ScanSeverity.HIGH,
                mitre_technique_id="T1048",
                url=f"{session.hostname}:{session.port}",
                blocked=False,
            )
            try:
                await self._kafka_producer.send(
                    "agentpep.network", event.model_dump(mode="json")
                )
            except Exception:
                logger.exception("Failed to emit DLP tunnel event")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_stats(self) -> TunnelStats:
        """Return current tunnel statistics."""
        self._stats.active_tunnels = len(self._active_tunnels)
        return self._stats.model_copy()

    def get_active_tunnels(self) -> list[TunnelSession]:
        """Return a snapshot of active tunnel sessions."""
        return [s.model_copy() for s in self._active_tunnels.values()]

    async def kill_tunnel(self, tunnel_id: str) -> bool:
        """Forcefully close a tunnel by ID."""
        if tunnel_id in self._active_tunnels:
            await self._close_tunnel(tunnel_id, TunnelCloseReason.ADMIN_KILL)
            return True
        return False

    @property
    def config(self) -> ConnectTunnelConfig:
        return self._config


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

connect_tunnel_handler = ConnectTunnelHandler()
