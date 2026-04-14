"""Pydantic models for Sprint 47 — Forward Proxy (CONNECT Tunneling) & WebSocket Proxy.

APEP-372: Asyncio CONNECT tunnel handler models.
APEP-374: Hostname-level blocking configuration.
APEP-375: Optional TLS interception (MITM) models.
APEP-376: ToolTrust tls init equivalent models.
APEP-377: WebSocket proxy models.
APEP-378: WebSocket frame DLP + injection scanning models.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TunnelState(StrEnum):
    """Lifecycle state of a CONNECT tunnel."""

    PENDING = "pending"
    ESTABLISHED = "established"
    BLOCKED = "blocked"
    CLOSED = "closed"
    ERROR = "error"


class TunnelCloseReason(StrEnum):
    """Why a tunnel was closed."""

    CLIENT_DISCONNECT = "client_disconnect"
    SERVER_DISCONNECT = "server_disconnect"
    POLICY_BLOCK = "policy_block"
    DLP_VIOLATION = "dlp_violation"
    IDLE_TIMEOUT = "idle_timeout"
    MAX_DURATION = "max_duration"
    ERROR = "error"
    ADMIN_KILL = "admin_kill"


class TLSInterceptionMode(StrEnum):
    """TLS interception mode for CONNECT tunnels."""

    PASSTHROUGH = "passthrough"
    INTERCEPT = "intercept"


class WebSocketProxyState(StrEnum):
    """Lifecycle state of a WebSocket proxy session."""

    CONNECTING = "connecting"
    OPEN = "open"
    CLOSING = "closing"
    CLOSED = "closed"
    ERROR = "error"


class WebSocketFrameType(StrEnum):
    """WebSocket frame types for scanning."""

    TEXT = "text"
    BINARY = "binary"
    PING = "ping"
    PONG = "pong"
    CLOSE = "close"


class FrameScanVerdict(StrEnum):
    """Verdict from WebSocket frame scanning."""

    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    LOG_ONLY = "log_only"


# ---------------------------------------------------------------------------
# CONNECT Tunnel Models (APEP-372)
# ---------------------------------------------------------------------------


class ConnectTunnelConfig(BaseModel):
    """Configuration for the CONNECT tunnel handler."""

    listen_host: str = Field(default="0.0.0.0", description="Address to bind the proxy")
    listen_port: int = Field(default=8889, description="Port for the forward proxy")
    max_tunnels: int = Field(default=1000, description="Maximum concurrent tunnels")
    idle_timeout_s: int = Field(default=300, description="Idle timeout in seconds")
    max_tunnel_duration_s: int = Field(default=3600, description="Max tunnel duration")
    buffer_size: int = Field(default=65536, description="Read buffer size in bytes")
    enable_dlp_scan: bool = Field(default=True, description="Enable DLP scanning on request bodies")
    enable_hostname_blocking: bool = Field(default=True, description="Enable hostname-level blocking")
    enable_tls_interception: bool = Field(default=False, description="Enable TLS interception (MITM)")
    allowed_ports: list[int] = Field(
        default_factory=lambda: [443, 8443],
        description="Ports allowed for CONNECT tunnels",
    )


class ConnectRequest(BaseModel):
    """Parsed CONNECT request from the client."""

    hostname: str = Field(..., description="Target hostname from CONNECT request")
    port: int = Field(default=443, description="Target port from CONNECT request")
    raw_line: str = Field(default="", description="Raw CONNECT request line")
    session_id: str | None = Field(default=None, description="Associated AgentPEP session")
    agent_id: str | None = Field(default=None, description="Associated agent ID")


class TunnelSession(BaseModel):
    """Represents an active or completed CONNECT tunnel session."""

    tunnel_id: UUID = Field(default_factory=uuid4)
    hostname: str
    port: int = 443
    state: TunnelState = TunnelState.PENDING
    session_id: str | None = None
    agent_id: str | None = None
    client_addr: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    closed_at: datetime | None = None
    close_reason: TunnelCloseReason | None = None
    tls_interception_mode: TLSInterceptionMode = TLSInterceptionMode.PASSTHROUGH
    dlp_findings_count: int = 0
    blocked: bool = False
    block_reason: str = ""


class TunnelStats(BaseModel):
    """Aggregate statistics for tunnel handler."""

    active_tunnels: int = 0
    total_tunnels: int = 0
    total_bytes_transferred: int = 0
    blocked_count: int = 0
    dlp_hit_count: int = 0
    avg_tunnel_duration_s: float = 0.0


# ---------------------------------------------------------------------------
# TLS Interception Models (APEP-375)
# ---------------------------------------------------------------------------


class TLSInterceptionConfig(BaseModel):
    """Configuration for optional TLS interception (MITM)."""

    enabled: bool = Field(default=False, description="Enable TLS interception globally")
    ca_cert_path: str = Field(default="", description="Path to CA certificate PEM")
    ca_key_path: str = Field(default="", description="Path to CA private key PEM")
    cert_cache_size: int = Field(default=1000, description="Max cached generated certs")
    cert_ttl_s: int = Field(default=86400, description="Cert TTL in seconds (24h)")
    intercept_hostnames: list[str] = Field(
        default_factory=list,
        description="Hostnames to intercept; empty means intercept all non-excluded",
    )
    exclude_hostnames: list[str] = Field(
        default_factory=list,
        description="Hostnames to never intercept (passthrough)",
    )
    key_algorithm: str = Field(default="ECDSA_P256", description="Key algorithm: ECDSA_P256 or RSA_2048")


class GeneratedCert(BaseModel):
    """A dynamically generated TLS certificate for MITM interception."""

    hostname: str
    cert_pem: str = Field(default="", description="PEM-encoded certificate")
    key_pem: str = Field(default="", description="PEM-encoded private key")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    serial_number: str = ""


class TLSInitConfig(BaseModel):
    """Configuration for ToolTrust tls init equivalent (APEP-376).

    Generates and manages the root CA certificate used for TLS interception.
    """

    organization: str = Field(default="AgentPEP TrustFabric", description="CA organization name")
    common_name: str = Field(default="AgentPEP MITM CA", description="CA common name")
    validity_days: int = Field(default=365, description="CA certificate validity in days")
    key_algorithm: str = Field(default="ECDSA_P256", description="CA key algorithm")
    output_dir: str = Field(default="/tmp/agentpep-tls", description="Output directory for CA files")
    force_regenerate: bool = Field(default=False, description="Force regenerate even if files exist")


class TLSInitResult(BaseModel):
    """Result from ToolTrust tls init equivalent."""

    ca_cert_path: str = ""
    ca_key_path: str = ""
    ca_fingerprint: str = ""
    created: bool = False
    message: str = ""


# ---------------------------------------------------------------------------
# WebSocket Proxy Models (APEP-377)
# ---------------------------------------------------------------------------


class WebSocketProxyConfig(BaseModel):
    """Configuration for the WebSocket proxy."""

    max_connections: int = Field(default=500, description="Maximum concurrent WebSocket connections")
    max_frame_size: int = Field(default=1_048_576, description="Max frame size in bytes (1MB)")
    idle_timeout_s: int = Field(default=300, description="Idle timeout in seconds")
    enable_dlp_scan: bool = Field(default=True, description="Enable DLP scanning on frames")
    enable_injection_scan: bool = Field(default=True, description="Enable injection scanning on frames")
    ping_interval_s: int = Field(default=30, description="Ping interval in seconds")
    fragment_reassembly: bool = Field(default=True, description="Enable fragment reassembly for scanning")
    scan_text_frames: bool = Field(default=True, description="Scan text frames")
    scan_binary_frames: bool = Field(default=False, description="Scan binary frames (base64 decode)")


class WebSocketProxySession(BaseModel):
    """Represents an active or completed WebSocket proxy session."""

    ws_session_id: UUID = Field(default_factory=uuid4)
    target_url: str
    state: WebSocketProxyState = WebSocketProxyState.CONNECTING
    session_id: str | None = None
    agent_id: str | None = None
    client_addr: str = ""
    frames_sent: int = 0
    frames_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    dlp_findings_count: int = 0
    injection_findings_count: int = 0
    frames_blocked: int = 0
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    closed_at: datetime | None = None
    close_code: int | None = None
    close_reason: str = ""


class WebSocketProxyRequest(BaseModel):
    """Request to create a new WebSocket proxy session."""

    target_url: str = Field(..., description="WebSocket URL to proxy to (ws:// or wss://)")
    session_id: str | None = Field(default=None, description="AgentPEP session ID")
    agent_id: str | None = Field(default=None, description="Agent ID")
    headers: dict[str, str] = Field(default_factory=dict, description="Extra headers to forward")


# ---------------------------------------------------------------------------
# WebSocket Frame Scanning Models (APEP-378)
# ---------------------------------------------------------------------------


class FrameScanRequest(BaseModel):
    """A frame submitted for DLP + injection scanning."""

    frame_type: WebSocketFrameType
    data: str = Field(default="", description="Frame payload (text or base64-encoded)")
    ws_session_id: UUID | None = None
    direction: str = Field(default="outbound", description="inbound or outbound")


class FrameScanResult(BaseModel):
    """Result from scanning a single WebSocket frame."""

    verdict: FrameScanVerdict = FrameScanVerdict.ALLOW
    dlp_findings: list[dict[str, Any]] = Field(default_factory=list)
    injection_findings: list[dict[str, Any]] = Field(default_factory=list)
    frame_type: WebSocketFrameType = WebSocketFrameType.TEXT
    scan_latency_us: int = 0
    redacted_data: str | None = None


class WebSocketProxyStats(BaseModel):
    """Aggregate statistics for WebSocket proxy."""

    active_connections: int = 0
    total_connections: int = 0
    total_frames_scanned: int = 0
    total_frames_blocked: int = 0
    dlp_hit_count: int = 0
    injection_hit_count: int = 0


# ---------------------------------------------------------------------------
# Hostname Blocking Config (APEP-374) — extends domain_blocklist
# ---------------------------------------------------------------------------


class ForwardProxyHostnamePolicy(BaseModel):
    """Per-hostname policy for forward proxy access control."""

    hostname: str
    allowed: bool = True
    tls_intercept: bool = False
    max_connections: int = Field(default=10, description="Max concurrent connections")
    rate_limit_rps: int = Field(default=100, description="Requests per second limit")
    notes: str = ""


class ForwardProxyBlocklistEntry(BaseModel):
    """A blocklist/allowlist entry for the forward proxy."""

    pattern: str = Field(..., description="Hostname pattern (exact or wildcard like *.evil.com)")
    is_regex: bool = Field(default=False, description="Treat pattern as regex")
    action: str = Field(default="block", description="block or allow")
    reason: str = ""
    added_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    added_by: str = ""
