"""MCP proxy API — HTTP endpoints for the MCP tool call intercept proxy.

Sprint 12: Exposes endpoints that MCP-compliant agents can use to proxy
their tool calls through AgentPEP for policy evaluation.

Sprint 48: Enhanced with bidirectional DLP, tool poisoning detection,
rug-pull detection, session DLP budget, and reverse proxy endpoints.

Endpoints:
  POST /v1/mcp/proxy           — Proxy a single MCP JSON-RPC message
  POST /v1/mcp/proxy/batch     — Proxy a batch of MCP JSON-RPC messages
  POST /v1/mcp/session/start   — Explicitly start an MCP proxy session
  POST /v1/mcp/session/end     — Explicitly end an MCP proxy session
  GET  /v1/mcp/session/{id}    — Get session status
  GET  /v1/mcp/sessions        — List active MCP proxy sessions
  POST /v1/mcp/reverse-proxy   — Reverse proxy HTTP request to MCP server (Sprint 48)
  GET  /v1/mcp/session/{id}/dlp-budget — Get session DLP budget (Sprint 48)
  GET  /v1/mcp/session/{id}/security-events — Get session security events (Sprint 48)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.core.config import settings
from app.db import mongodb as db_module
from app.services.kafka_producer import kafka_producer
from app.services.mcp_proxy import MCPProxy
from app.services.mcp_reverse_proxy import MCPReverseProxy
from app.services.mcp_session_dlp_budget import mcp_session_dlp_budget_tracker
from app.services.mcp_session_tracker import mcp_session_tracker

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/mcp", tags=["mcp-proxy"])

# In-memory registry of active proxy instances keyed by session_id
_active_proxies: dict[str, MCPProxy] = {}
# Sprint 48: reverse proxy instances
_reverse_proxies: dict[str, MCPReverseProxy] = {}


# --- Request / Response models ---


class MCPSessionStartRequest(BaseModel):
    agent_id: str = Field(..., description="Agent initiating the MCP session")
    upstream_url: str = Field(..., description="Target MCP server URL")
    session_id: str | None = Field(
        default=None, description="Optional session ID (auto-generated if omitted)"
    )
    # Sprint 48 feature flags
    dlp_scan_enabled: bool | None = Field(
        default=None, description="Enable bidirectional DLP scanning (default: config)"
    )
    poisoning_detection_enabled: bool | None = Field(
        default=None, description="Enable tool poisoning detection (default: config)"
    )
    rug_pull_detection_enabled: bool | None = Field(
        default=None, description="Enable rug-pull detection (default: config)"
    )


class MCPSessionStartResponse(BaseModel):
    session_id: str
    agent_id: str
    upstream_url: str
    status: str = "active"


class MCPSessionEndRequest(BaseModel):
    session_id: str


class MCPSessionStatusResponse(BaseModel):
    session_id: str
    agent_id: str
    status: str
    tool_call_count: int
    started_at: datetime


class MCPProxyRequest(BaseModel):
    session_id: str = Field(..., description="Active MCP proxy session ID")
    message: dict[str, Any] = Field(..., description="MCP JSON-RPC message to proxy")


class MCPProxyBatchRequest(BaseModel):
    session_id: str = Field(..., description="Active MCP proxy session ID")
    messages: list[dict[str, Any]] = Field(..., description="Batch of MCP JSON-RPC messages")


# --- Endpoints ---


@router.post("/session/start", response_model=MCPSessionStartResponse)
async def start_session(request: MCPSessionStartRequest) -> MCPSessionStartResponse:
    """Start a new MCP proxy session for an agent."""
    # Look up agent profile to get MCP config
    db = db_module.get_database()
    profile_doc = await db[db_module.AGENT_PROFILES].find_one(
        {"agent_id": request.agent_id, "enabled": True}
    )
    if profile_doc is None:
        raise HTTPException(status_code=404, detail=f"Agent not found: {request.agent_id}")

    # Check MCP proxy config on profile
    mcp_config = profile_doc.get("mcp_proxy", {})
    if mcp_config.get("enabled") is False and not request.upstream_url:
        raise HTTPException(
            status_code=400,
            detail="MCP proxy not enabled for this agent and no upstream_url provided",
        )

    upstream_url = request.upstream_url or mcp_config.get("upstream_url", "")
    if not upstream_url:
        raise HTTPException(status_code=400, detail="No upstream_url provided or configured")

    # Prevent session ID overwrite and cross-agent hijacking:
    # if the client supplies a session_id, check ownership.
    if request.session_id and request.session_id in _active_proxies:
        existing_proxy = _active_proxies[request.session_id]
        existing_state = mcp_session_tracker.get_session(request.session_id)
        if existing_state is not None:
            # Verify the requesting agent owns this session
            if existing_proxy.agent_id != request.agent_id:
                raise HTTPException(
                    status_code=403,
                    detail=f"Session '{request.session_id}' belongs to a different agent",
                )
            raise HTTPException(
                status_code=409,
                detail=f"Session '{request.session_id}' already exists and is active. "
                "End the existing session first or omit session_id to auto-generate one.",
            )

    proxy = MCPProxy(
        upstream_url=upstream_url,
        agent_id=request.agent_id,
        session_id=request.session_id,
        dlp_scan_enabled=(
            request.dlp_scan_enabled
            if request.dlp_scan_enabled is not None
            else settings.mcp_dlp_scan_enabled
        ),
        poisoning_detection_enabled=(
            request.poisoning_detection_enabled
            if request.poisoning_detection_enabled is not None
            else settings.mcp_poisoning_detection_enabled
        ),
        rug_pull_detection_enabled=(
            request.rug_pull_detection_enabled
            if request.rug_pull_detection_enabled is not None
            else settings.mcp_rug_pull_detection_enabled
        ),
        dlp_budget_enabled=settings.mcp_dlp_budget_enabled,
    )
    await proxy.start()

    _active_proxies[proxy.session_id] = proxy

    # Persist session metadata
    try:
        await db[db_module.MCP_PROXY_SESSIONS].insert_one({
            "session_id": proxy.session_id,
            "agent_id": request.agent_id,
            "upstream_url": upstream_url,
            "status": "active",
            "tool_call_count": 0,
            "started_at": datetime.now(UTC),
        })
    except Exception:
        logger.exception("Failed to persist MCP session metadata")

    return MCPSessionStartResponse(
        session_id=proxy.session_id,
        agent_id=request.agent_id,
        upstream_url=upstream_url,
    )


@router.post("/session/end")
async def end_session(request: MCPSessionEndRequest) -> dict[str, str]:
    """End an active MCP proxy session and persist its taint graph."""
    proxy = _active_proxies.pop(request.session_id, None)
    if proxy is None:
        raise HTTPException(status_code=404, detail=f"Session not found: {request.session_id}")

    await proxy.stop()

    # Update session status in MongoDB
    try:
        db = db_module.get_database()
        await db[db_module.MCP_PROXY_SESSIONS].update_one(
            {"session_id": request.session_id},
            {"$set": {"status": "ended", "ended_at": datetime.now(UTC)}},
        )
    except Exception:
        logger.exception("Failed to update MCP session status")

    return {"status": "ended", "session_id": request.session_id}


@router.get("/session/{session_id}", response_model=MCPSessionStatusResponse)
async def get_session_status(session_id: str) -> MCPSessionStatusResponse:
    """Get the status of an MCP proxy session."""
    state = mcp_session_tracker.get_session(session_id)
    if state is None:
        raise HTTPException(status_code=404, detail=f"Session not found: {session_id}")

    return MCPSessionStatusResponse(
        session_id=state.session_id,
        agent_id=state.agent_id,
        status="active" if session_id in _active_proxies else "unknown",
        tool_call_count=state.tool_call_count,
        started_at=state.started_at,
    )


@router.get("/sessions")
async def list_sessions() -> dict[str, Any]:
    """List all active MCP proxy sessions."""
    sessions = []
    for sid, proxy in _active_proxies.items():
        state = mcp_session_tracker.get_session(sid)
        sessions.append({
            "session_id": sid,
            "agent_id": proxy.agent_id,
            "upstream_url": proxy.upstream_url,
            "tool_call_count": state.tool_call_count if state else 0,
        })
    return {"active_sessions": sessions, "count": len(sessions)}


@router.post("/proxy")
async def proxy_message(request: MCPProxyRequest) -> dict[str, Any]:
    """Proxy a single MCP JSON-RPC message through policy evaluation.

    The message is parsed, evaluated against the policy stack, and either
    forwarded to the upstream MCP server (ALLOW) or returned with an MCP
    error (DENY/ESCALATE).
    """
    proxy = _active_proxies.get(request.session_id)
    if proxy is None:
        raise HTTPException(
            status_code=404,
            detail=f"No active proxy session: {request.session_id}",
        )

    result = await proxy.handle_message(request.message)

    # Update tool call count in MongoDB
    state = mcp_session_tracker.get_session(request.session_id)
    if state:
        try:
            db = db_module.get_database()
            await db[db_module.MCP_PROXY_SESSIONS].update_one(
                {"session_id": request.session_id},
                {"$set": {"tool_call_count": state.tool_call_count}},
            )
        except Exception:
            pass

    # Sprint 48: publish any security events to Kafka
    security_events = proxy.get_security_events()
    for event in security_events:
        try:
            await kafka_producer.publish_mcp_security_event(
                event.model_dump(mode="json")
            )
        except Exception:
            logger.debug("Failed to publish MCP security event (Kafka may be disabled)")

    return result


@router.post("/proxy/batch")
async def proxy_batch(request: MCPProxyBatchRequest) -> list[dict[str, Any]]:
    """Proxy a batch of MCP JSON-RPC messages."""
    proxy = _active_proxies.get(request.session_id)
    if proxy is None:
        raise HTTPException(
            status_code=404,
            detail=f"No active proxy session: {request.session_id}",
        )

    return await proxy.handle_batch(request.messages)


def get_active_proxies() -> dict[str, MCPProxy]:
    """Return the active proxies dict (for testing)."""
    return _active_proxies


def clear_active_proxies() -> None:
    """Clear all active proxies (for testing)."""
    _active_proxies.clear()
    _reverse_proxies.clear()


# ---------------------------------------------------------------------------
# Sprint 48 endpoints
# ---------------------------------------------------------------------------


class MCPReverseProxyRequest(BaseModel):
    """Request to create a reverse proxy session."""

    agent_id: str = Field(..., description="Agent initiating the reverse proxy session")
    upstream_url: str = Field(..., description="Target MCP server URL")
    session_id: str | None = Field(default=None, description="Optional session ID")


@router.post("/reverse-proxy/session/start")
async def start_reverse_proxy_session(
    request: MCPReverseProxyRequest,
) -> dict[str, Any]:
    """Start a reverse proxy session for an MCP server (Sprint 48 — APEP-384)."""
    from app.models.mcp_security import MCPReverseProxyConfig

    config = MCPReverseProxyConfig(
        enabled=True,
        upstream_url=request.upstream_url,
        dlp_scan_enabled=settings.mcp_dlp_scan_enabled,
        poisoning_detection_enabled=settings.mcp_poisoning_detection_enabled,
        rug_pull_detection_enabled=settings.mcp_rug_pull_detection_enabled,
    )

    proxy = MCPReverseProxy(
        upstream_url=request.upstream_url,
        agent_id=request.agent_id,
        session_id=request.session_id,
        config=config,
    )

    # Create DLP budget
    if settings.mcp_dlp_budget_enabled:
        mcp_session_dlp_budget_tracker.create_budget(
            proxy.session_id,
            request.agent_id,
            max_dlp_findings=settings.mcp_dlp_budget_max_findings,
            max_critical_findings=settings.mcp_dlp_budget_max_critical,
            max_outbound_bytes=settings.mcp_dlp_budget_max_outbound_bytes,
            max_inbound_bytes=settings.mcp_dlp_budget_max_inbound_bytes,
        )

    _reverse_proxies[proxy.session_id] = proxy

    return {
        "session_id": proxy.session_id,
        "agent_id": request.agent_id,
        "upstream_url": request.upstream_url,
        "status": "active",
    }


@router.post("/reverse-proxy/{session_id}")
async def reverse_proxy_request(
    session_id: str, request: Request,
) -> Response:
    """Forward an HTTP request through the MCP reverse proxy (Sprint 48 — APEP-384)."""
    proxy = _reverse_proxies.get(session_id)
    if proxy is None:
        raise HTTPException(status_code=404, detail=f"No reverse proxy session: {session_id}")

    body = await request.body()
    status_code, resp_headers, resp_body = await proxy.handle_request(
        body, dict(request.headers)
    )

    # Publish pending security events
    for event in proxy.get_pending_events():
        try:
            await kafka_producer.publish_mcp_security_event(
                event.model_dump(mode="json")
            )
        except Exception:
            pass

    return Response(
        content=resp_body,
        status_code=status_code,
        headers={k: v for k, v in resp_headers.items() if k.lower() != "transfer-encoding"},
    )


@router.get("/session/{session_id}/dlp-budget")
async def get_session_dlp_budget(session_id: str) -> dict[str, Any]:
    """Get the DLP budget for an MCP session (Sprint 48 — APEP-385)."""
    budget = mcp_session_dlp_budget_tracker.get_budget(session_id)
    if budget is None:
        raise HTTPException(status_code=404, detail=f"No DLP budget for session: {session_id}")
    return budget.model_dump(mode="json")


@router.get("/session/{session_id}/security-events")
async def get_session_security_events(session_id: str) -> dict[str, Any]:
    """Get security events for an MCP session (Sprint 48)."""
    db = db_module.get_database()
    cursor = db[db_module.MCP_SECURITY_EVENTS].find(
        {"session_id": session_id}
    ).sort("timestamp", -1).limit(100)

    events = []
    async for doc in cursor:
        doc.pop("_id", None)
        events.append(doc)

    return {"session_id": session_id, "events": events, "count": len(events)}
