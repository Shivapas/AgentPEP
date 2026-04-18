"""MCP HTTP reverse proxy mode — transparent HTTP-level MCP proxy.

Sprint 48 — APEP-384: Provides an HTTP reverse proxy that sits in front of
an MCP server and transparently applies bidirectional DLP scanning, tool
poisoning detection, and rug-pull detection to all MCP traffic.

Unlike the JSON-RPC level proxy (MCPProxy from Sprint 12), the reverse
proxy operates at the HTTP level and can intercept all traffic to/from
the MCP server, including non-JSON-RPC requests.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any
from uuid import uuid4

import httpx

from app.models.mcp_security import (
    MCPReverseProxyConfig,
    MCPReverseProxySession,
    MCPSecurityEvent,
    MCPSecurityEventType,
)
from app.services.mcp_message_parser import (
    MCPMessageType,
    mcp_message_parser,
)
from app.services.mcp_outbound_scanner import mcp_outbound_scanner
from app.services.mcp_response_scanner import mcp_response_scanner
from app.services.mcp_rug_pull_detector import mcp_rug_pull_detector
from app.services.mcp_session_dlp_budget import mcp_session_dlp_budget_tracker
from app.services.mcp_tool_poisoning_detector import mcp_tool_poisoning_detector

logger = logging.getLogger(__name__)


class MCPReverseProxy:
    """HTTP-level reverse proxy for MCP servers with security scanning.

    Intercepts HTTP requests/responses to an upstream MCP server and applies:
      - Outbound DLP scanning on request bodies
      - Inbound DLP + injection scanning on response bodies
      - Tool poisoning detection on tools/list responses
      - Rug-pull detection on subsequent tools/list responses
      - Session DLP budget enforcement
    """

    def __init__(
        self,
        *,
        upstream_url: str,
        agent_id: str,
        session_id: str | None = None,
        config: MCPReverseProxyConfig | None = None,
    ) -> None:
        self.upstream_url = upstream_url.rstrip("/")
        self.agent_id = agent_id
        self.session_id = session_id or f"mcp-rev-{uuid4().hex[:12]}"
        self.config = config or MCPReverseProxyConfig()
        self._session = MCPReverseProxySession(
            session_id=self.session_id,
            agent_id=agent_id,
            upstream_url=self.upstream_url,
        )
        self._events: list[MCPSecurityEvent] = []

    async def handle_request(
        self, request_body: bytes, headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """Handle an HTTP request to the MCP server.

        Args:
            request_body: Raw HTTP request body.
            headers: Optional HTTP headers.

        Returns:
            Tuple of (status_code, response_headers, response_body).
        """
        self._session.request_count += 1

        # Check DLP budget
        if mcp_session_dlp_budget_tracker.is_exceeded(self.session_id):
            return self._budget_exceeded_response()

        # Parse request body
        try:
            request_json = json.loads(request_body) if request_body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Non-JSON request — forward transparently
            return await self._forward_raw(request_body, headers)

        # Check if it's a tools/call request and scan outbound
        if self.config.dlp_scan_enabled and isinstance(request_json, dict):
            method = request_json.get("method", "")
            if method == "tools/call":
                params = request_json.get("params", {})
                tool_name = params.get("name", "")
                tool_args = params.get("arguments", {})

                # Track outbound bytes
                mcp_session_dlp_budget_tracker.record_bytes_scanned(
                    self.session_id, outbound_bytes=len(request_body)
                )

                scan_result = mcp_outbound_scanner.scan_outbound(
                    tool_name=tool_name,
                    tool_args=tool_args,
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                )
                if scan_result.blocked:
                    self._session.dlp_findings_count += len(scan_result.findings)
                    mcp_session_dlp_budget_tracker.record_findings(
                        self.session_id, scan_result.findings
                    )
                    self._emit_event(
                        MCPSecurityEventType.OUTBOUND_DLP_HIT,
                        tool_name=tool_name,
                        severity="CRITICAL",
                        description=f"Outbound DLP blocked: {len(scan_result.findings)} findings",
                        findings_count=len(scan_result.findings),
                        blocked=True,
                    )
                    return self._dlp_blocked_response(
                        request_json.get("id"), "Outbound DLP scan blocked this request"
                    )

        # Forward to upstream
        response_status, response_headers, response_body = await self._forward_raw(
            request_body, headers
        )

        # Scan inbound response
        if self.config.dlp_scan_enabled and response_body:
            try:
                response_json = json.loads(response_body)
                await self._scan_response(request_json, response_json)
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass

        return response_status, response_headers, response_body

    async def _scan_response(
        self, request_json: dict[str, Any], response_json: Any
    ) -> None:
        """Scan the MCP response for injection, DLP, and tool changes."""
        method = request_json.get("method", "") if isinstance(request_json, dict) else ""

        # Track inbound bytes
        response_text = json.dumps(response_json, default=str)
        mcp_session_dlp_budget_tracker.record_bytes_scanned(
            self.session_id, inbound_bytes=len(response_text.encode())
        )

        # 1. Check tools/list responses for poisoning and rug-pulls
        if method == "tools/list" and isinstance(response_json, dict):
            result_data = response_json.get("result", {})
            tools_list = result_data.get("tools", []) if isinstance(result_data, dict) else []

            if self.config.poisoning_detection_enabled and tools_list:
                poisoning_result = mcp_tool_poisoning_detector.scan_tools_list(
                    tools=tools_list,
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                )
                if poisoning_result.findings:
                    self._session.poisoning_findings_count += len(poisoning_result.findings)
                    self._emit_event(
                        MCPSecurityEventType.TOOL_POISONING_DETECTED,
                        severity="CRITICAL",
                        description=f"Tool poisoning: {len(poisoning_result.findings)} findings",
                        findings_count=len(poisoning_result.findings),
                        blocked=poisoning_result.blocked,
                    )

            if self.config.rug_pull_detection_enabled and tools_list:
                rug_result = mcp_rug_pull_detector.detect(
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                    tools=tools_list,
                )
                if rug_result.is_rug_pull:
                    self._session.rug_pull_detections += 1
                    self._emit_event(
                        MCPSecurityEventType.RUG_PULL_DETECTED,
                        severity="CRITICAL",
                        description=f"Rug-pull: {len(rug_result.changes)} changes detected",
                        findings_count=len(rug_result.changes),
                        blocked=rug_result.blocked,
                    )

        # 2. Scan tool call responses for injection
        if isinstance(response_json, dict) and "result" in response_json:
            tool_name = ""
            if isinstance(request_json, dict):
                params = request_json.get("params", {})
                tool_name = params.get("name", "") if isinstance(params, dict) else ""

            resp_scan = mcp_response_scanner.scan_response(
                tool_name=tool_name,
                response_data=response_json.get("result"),
                session_id=self.session_id,
                agent_id=self.agent_id,
            )
            if resp_scan.injection_findings:
                self._emit_event(
                    MCPSecurityEventType.RESPONSE_INJECTION,
                    tool_name=tool_name,
                    severity="CRITICAL",
                    description=f"Response injection: {len(resp_scan.injection_findings)} findings",
                    findings_count=len(resp_scan.injection_findings),
                )
            if resp_scan.dlp_findings:
                mcp_session_dlp_budget_tracker.record_findings(
                    self.session_id, resp_scan.dlp_findings
                )

    async def _forward_raw(
        self, body: bytes, headers: dict[str, str] | None,
    ) -> tuple[int, dict[str, str], bytes]:
        """Forward raw HTTP request to the upstream MCP server."""
        send_headers = {"Content-Type": "application/json"}
        if headers:
            send_headers.update(headers)

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout_s) as client:
                resp = await client.post(
                    self.upstream_url,
                    content=body,
                    headers=send_headers,
                )
                return (
                    resp.status_code,
                    dict(resp.headers),
                    resp.content,
                )
        except httpx.RequestError as exc:
            logger.error(
                "Reverse proxy upstream error: %s url=%s",
                str(exc),
                self.upstream_url,
            )
            error_body = json.dumps({
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32003,
                    "message": f"Upstream MCP server error: {exc}",
                },
            }).encode()
            return 502, {"Content-Type": "application/json"}, error_body

    def _budget_exceeded_response(self) -> tuple[int, dict[str, str], bytes]:
        """Return a JSON-RPC error for budget exceeded."""
        body = json.dumps({
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32001,
                "message": "MCP session DLP budget exceeded",
                "data": {"session_id": self.session_id},
            },
        }).encode()
        return 429, {"Content-Type": "application/json"}, body

    def _dlp_blocked_response(
        self, request_id: Any, message: str
    ) -> tuple[int, dict[str, str], bytes]:
        """Return a JSON-RPC error for DLP block."""
        body = json.dumps({
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32001,
                "message": message,
                "data": {"decision": "BLOCK", "scanner": "MCPOutboundScanner"},
            },
        }).encode()
        return 403, {"Content-Type": "application/json"}, body

    def _emit_event(
        self,
        event_type: MCPSecurityEventType,
        *,
        tool_name: str = "",
        severity: str = "MEDIUM",
        description: str = "",
        findings_count: int = 0,
        blocked: bool = False,
    ) -> None:
        """Emit a security event (collected for Kafka publishing)."""
        event = MCPSecurityEvent(
            event_type=event_type,
            session_id=self.session_id,
            agent_id=self.agent_id,
            tool_name=tool_name,
            severity=severity,
            description=description,
            findings_count=findings_count,
            blocked=blocked,
        )
        self._events.append(event)

    def get_pending_events(self) -> list[MCPSecurityEvent]:
        """Get and clear pending security events."""
        events = list(self._events)
        self._events.clear()
        return events

    @property
    def session_info(self) -> MCPReverseProxySession:
        """Get session metadata."""
        return self._session
