"""Forward Proxy & WebSocket Proxy API — Sprint 47.

APEP-372.d: Wire API endpoint and service layer for asyncio CONNECT tunnel handler.
APEP-377.d: Wire API endpoint and service layer for WebSocket proxy.

Endpoints:
  POST /v1/proxy/tunnel/status    — Get CONNECT tunnel handler status and stats.
  POST /v1/proxy/tunnel/kill      — Forcefully close a tunnel by ID.
  POST /v1/proxy/ws/connect       — Create a new WebSocket proxy session.
  GET  /v1/proxy/ws/status        — Get WebSocket proxy status and stats.
  POST /v1/proxy/tls/init         — Initialize the TLS interception CA.
  GET  /v1/proxy/tls/status       — Get TLS interception status.
  POST /v1/proxy/hostname/check   — Check if a hostname is blocked.
  POST /v1/proxy/hostname/block   — Add a hostname to the blocklist.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.models.forward_proxy import (
    ForwardProxyBlocklistEntry,
    TLSInitConfig,
    TLSInitResult,
    TunnelStats,
    WebSocketProxyRequest,
    WebSocketProxyStats,
)
from app.services.connect_tunnel import connect_tunnel_handler
from app.services.hostname_blocker import hostname_blocker
from app.services.tls_init import tls_init_service
from app.services.tls_interception import tls_interception_engine
from app.services.websocket_proxy import websocket_proxy

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/proxy", tags=["proxy"])


# ---------------------------------------------------------------------------
# Request/Response models for API
# ---------------------------------------------------------------------------


class TunnelKillRequest(BaseModel):
    tunnel_id: str = Field(..., description="ID of the tunnel to kill")


class HostnameCheckRequest(BaseModel):
    hostname: str = Field(..., description="Hostname to check")


class HostnameCheckResponse(BaseModel):
    hostname: str
    blocked: bool
    reason: str = ""


class ProxyStatusResponse(BaseModel):
    tunnel_stats: TunnelStats
    websocket_stats: WebSocketProxyStats
    tls_interception_enabled: bool
    tls_interception_initialized: bool
    tls_cert_cache_size: int
    hostname_block_count: int
    hostname_allow_count: int


# ---------------------------------------------------------------------------
# CONNECT Tunnel endpoints (APEP-372.d)
# ---------------------------------------------------------------------------


@router.get("/tunnel/status", response_model=TunnelStats)
async def tunnel_status() -> TunnelStats:
    """Get CONNECT tunnel handler status and statistics."""
    return connect_tunnel_handler.get_stats()


@router.post("/tunnel/kill")
async def tunnel_kill(request: TunnelKillRequest) -> dict:
    """Forcefully close a tunnel by ID."""
    killed = await connect_tunnel_handler.kill_tunnel(request.tunnel_id)
    if killed:
        return {"status": "ok", "tunnel_id": request.tunnel_id}
    return {"status": "not_found", "tunnel_id": request.tunnel_id}


@router.get("/tunnel/active")
async def tunnel_active() -> dict:
    """List active CONNECT tunnels."""
    tunnels = connect_tunnel_handler.get_active_tunnels()
    return {
        "count": len(tunnels),
        "tunnels": [t.model_dump(mode="json") for t in tunnels],
    }


# ---------------------------------------------------------------------------
# WebSocket Proxy endpoints (APEP-377.d)
# ---------------------------------------------------------------------------


@router.get("/ws/status", response_model=WebSocketProxyStats)
async def ws_status() -> WebSocketProxyStats:
    """Get WebSocket proxy status and statistics."""
    return websocket_proxy.get_stats()


@router.post("/ws/validate")
async def ws_validate(request: WebSocketProxyRequest) -> dict:
    """Validate a WebSocket target URL without connecting."""
    is_valid, error = websocket_proxy.validate_target(request.target_url)
    return {
        "target_url": request.target_url,
        "valid": is_valid,
        "error": error,
    }


@router.get("/ws/sessions")
async def ws_sessions() -> dict:
    """List active WebSocket proxy sessions."""
    sessions = websocket_proxy.get_sessions()
    return {
        "count": len(sessions),
        "sessions": [s.model_dump(mode="json") for s in sessions],
    }


# ---------------------------------------------------------------------------
# TLS Interception endpoints (APEP-375, APEP-376)
# ---------------------------------------------------------------------------


@router.post("/tls/init", response_model=TLSInitResult)
async def tls_init(config: TLSInitConfig | None = None) -> TLSInitResult:
    """Initialize the TLS interception CA certificate.

    Equivalent to ``tooltrust tls init``. Generates a self-signed CA
    certificate and private key for MITM TLS interception.
    """
    return tls_init_service.init_ca(config)


@router.get("/tls/status")
async def tls_status() -> dict:
    """Get TLS interception engine status."""
    return {
        "enabled": tls_interception_engine._config.enabled,
        "initialized": tls_interception_engine.is_initialized,
        "cert_cache_size": tls_interception_engine.cache_size,
        "crypto_available": tls_interception_engine._crypto_available,
    }


# ---------------------------------------------------------------------------
# Hostname blocking endpoints (APEP-374)
# ---------------------------------------------------------------------------


@router.post("/hostname/check", response_model=HostnameCheckResponse)
async def hostname_check(request: HostnameCheckRequest) -> HostnameCheckResponse:
    """Check if a hostname is blocked by the forward proxy."""
    blocked, reason = hostname_blocker.is_blocked(request.hostname)
    return HostnameCheckResponse(
        hostname=request.hostname,
        blocked=blocked,
        reason=reason,
    )


@router.post("/hostname/block")
async def hostname_block(entry: ForwardProxyBlocklistEntry) -> dict:
    """Add a hostname pattern to the forward proxy blocklist."""
    if entry.action == "allow":
        hostname_blocker.add_allow(entry)
        return {"status": "ok", "action": "allow", "pattern": entry.pattern}
    else:
        hostname_blocker.add_block(entry)
        return {"status": "ok", "action": "block", "pattern": entry.pattern}


# ---------------------------------------------------------------------------
# Combined status endpoint
# ---------------------------------------------------------------------------


@router.get("/status", response_model=ProxyStatusResponse)
async def proxy_status() -> ProxyStatusResponse:
    """Get combined status for all Sprint 47 proxy services."""
    return ProxyStatusResponse(
        tunnel_stats=connect_tunnel_handler.get_stats(),
        websocket_stats=websocket_proxy.get_stats(),
        tls_interception_enabled=tls_interception_engine._config.enabled,
        tls_interception_initialized=tls_interception_engine.is_initialized,
        tls_cert_cache_size=tls_interception_engine.cache_size,
        hostname_block_count=hostname_blocker.block_count,
        hostname_allow_count=hostname_blocker.allow_count,
    )
