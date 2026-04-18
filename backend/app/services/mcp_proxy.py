"""MCP tool call intercept proxy — transparent proxy between MCP client and server.

APEP-098: Forwards MCP tool call messages to the target MCP server post-approval.
APEP-100: Integrates with the Intercept API so that DENY returns an MCP error
          response and ALLOW forwards the request to the upstream MCP server.

Sprint 48 enhancements (APEP-380..385):
  - Bidirectional DLP: scan outbound args AND inbound responses
  - Tool poisoning detection on tools/list responses
  - Rug-pull detection on mid-session tool description changes
  - Session DLP budget enforcement

The proxy sits between an MCP-compliant agent (client) and an MCP tool server:

    Agent  ──▶  AgentPEP MCP Proxy  ──▶  Target MCP Server
                 │
                 ├─ Parse JSON-RPC envelope (APEP-099)
                 ├─ Evaluate via Intercept API (APEP-100)
                 ├─ Track taint per session (APEP-101)
                 ├─ Bidirectional DLP scan (APEP-380)
                 ├─ Response injection scan (APEP-381)
                 ├─ Tool poisoning detection (APEP-382)
                 ├─ Rug-pull detection (APEP-383)
                 └─ Session DLP budget (APEP-385)
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

import httpx

from app.models.mcp_security import (
    MCPSecurityEvent,
    MCPSecurityEventType,
)
from app.models.policy import Decision, ToolCallRequest
from app.services.mcp_message_parser import (
    MCPMessageType,
    MCPParseError,
    ParsedMCPMessage,
    mcp_message_parser,
)
from app.services.mcp_outbound_scanner import mcp_outbound_scanner
from app.services.mcp_response_scanner import mcp_response_scanner
from app.services.mcp_rug_pull_detector import mcp_rug_pull_detector
from app.services.mcp_session_dlp_budget import mcp_session_dlp_budget_tracker
from app.services.mcp_session_tracker import mcp_session_tracker
from app.services.mcp_tool_poisoning_detector import mcp_tool_poisoning_detector
from app.services.policy_evaluator import policy_evaluator

logger = logging.getLogger(__name__)

# MCP-specific JSON-RPC error codes
MCP_ERROR_POLICY_DENIED = -32001
MCP_ERROR_POLICY_ESCALATED = -32002
MCP_ERROR_UPSTREAM_FAILED = -32003
MCP_ERROR_SESSION_UNKNOWN = -32004
# Sprint 48 error codes
MCP_ERROR_DLP_BLOCKED = -32005
MCP_ERROR_TOOL_POISONING = -32006
MCP_ERROR_RUG_PULL = -32007
MCP_ERROR_DLP_BUDGET_EXCEEDED = -32008


class MCPProxy:
    """Transparent MCP proxy that intercepts tool calls for policy evaluation.

    For each incoming JSON-RPC tools/call request:
      1. Parse the envelope to extract tool name + arguments (APEP-099).
      2. Submit to the Intercept API for ALLOW/DENY/ESCALATE (APEP-100).
      3. If ALLOW — forward the original message to the upstream MCP server.
      4. If DENY — return a JSON-RPC error without contacting upstream.
      5. If ESCALATE — return a JSON-RPC error indicating escalation required.
      6. Track taint for inputs/outputs within the MCP session (APEP-101).

    Non-tool-call messages (tools/list, notifications, responses) are forwarded
    transparently without policy evaluation.
    """

    # Allowed URL schemes for upstream MCP servers
    _ALLOWED_SCHEMES = {"http", "https"}

    def __init__(
        self,
        upstream_url: str,
        agent_id: str,
        session_id: str | None = None,
        *,
        dlp_scan_enabled: bool = True,
        poisoning_detection_enabled: bool = True,
        rug_pull_detection_enabled: bool = True,
        dlp_budget_enabled: bool = True,
    ):
        """
        Args:
            upstream_url: Base URL of the target MCP server (e.g. http://localhost:3000/mcp).
            agent_id: The agent ID for policy evaluation.
            session_id: Optional session ID; auto-generated if not provided.
            dlp_scan_enabled: Enable bidirectional DLP scanning (Sprint 48).
            poisoning_detection_enabled: Enable tool poisoning detection (Sprint 48).
            rug_pull_detection_enabled: Enable rug-pull detection (Sprint 48).
            dlp_budget_enabled: Enable session DLP budget tracking (Sprint 48).
        """
        self._validate_upstream_url(upstream_url)
        self.upstream_url = upstream_url.rstrip("/")
        self.agent_id = agent_id
        self.session_id = session_id or f"mcp-{uuid4().hex[:12]}"
        self._started = False
        # Sprint 48 feature flags
        self._dlp_scan_enabled = dlp_scan_enabled
        self._poisoning_detection_enabled = poisoning_detection_enabled
        self._rug_pull_detection_enabled = rug_pull_detection_enabled
        self._dlp_budget_enabled = dlp_budget_enabled
        self._security_events: list[MCPSecurityEvent] = []

    @classmethod
    def _validate_upstream_url(cls, url: str) -> None:
        """Validate upstream URL to prevent SSRF attacks."""
        import ipaddress
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.scheme not in cls._ALLOWED_SCHEMES:
            raise ValueError(
                f"Upstream URL scheme must be http or https, got '{parsed.scheme}'"
            )
        hostname = parsed.hostname or ""
        if not hostname:
            raise ValueError("Upstream URL must have a hostname")
        # Block private/internal IP ranges
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
                raise ValueError(
                    f"Upstream URL must not point to private/internal IP: {hostname}"
                )
        except ValueError as exc:
            if "private" in str(exc) or "scheme" in str(exc) or "hostname" in str(exc):
                raise
            # hostname is a domain name — that's fine

    async def start(self) -> None:
        """Start the proxy session and initialise taint tracking."""
        if not self._started:
            mcp_session_tracker.start_session(self.session_id, self.agent_id)
            # Sprint 48: initialise session DLP budget
            if self._dlp_budget_enabled:
                mcp_session_dlp_budget_tracker.create_budget(
                    self.session_id, self.agent_id
                )
            self._started = True

    async def stop(self) -> None:
        """End the proxy session and persist taint graph."""
        if self._started:
            await mcp_session_tracker.end_session(self.session_id)
            # Sprint 48: clean up session state
            mcp_rug_pull_detector.clear_session(self.session_id)
            mcp_session_dlp_budget_tracker.remove_budget(self.session_id)
            self._started = False

    async def handle_message(self, message: dict[str, Any]) -> dict[str, Any]:
        """Process a single MCP JSON-RPC message.

        Returns the JSON-RPC response (either from upstream or a policy denial).
        """
        if not self._started:
            await self.start()

        # Sprint 48: check DLP budget before processing
        if self._dlp_budget_enabled and mcp_session_dlp_budget_tracker.is_exceeded(self.session_id):
            budget = mcp_session_dlp_budget_tracker.get_budget(self.session_id)
            return mcp_message_parser.build_jsonrpc_error(
                request_id=message.get("id"),
                code=MCP_ERROR_DLP_BUDGET_EXCEEDED,
                message=f"Session DLP budget exceeded: {budget.exceeded_reason if budget else 'unknown'}",
                data={"decision": "BLOCK", "session_id": self.session_id},
            )

        try:
            parsed = mcp_message_parser.parse(message)
        except MCPParseError as exc:
            return mcp_message_parser.build_jsonrpc_error(
                request_id=message.get("id"),
                code=exc.code,
                message=str(exc),
            )

        # Intercept tools/call requests AND notifications carrying tool calls
        # (notifications without an 'id' field must also be evaluated against
        # policy to prevent notification-based policy bypass).
        is_tool_call = parsed.message_type == MCPMessageType.TOOL_CALL
        if is_tool_call and (parsed.is_request or parsed.is_notification):
            return await self._handle_tool_call(message, parsed)

        # Sprint 48: intercept tools/list for poisoning + rug-pull detection
        if parsed.message_type == MCPMessageType.TOOL_LIST:
            return await self._handle_tools_list(message, parsed)

        # Forward non-tool-call messages transparently
        return await self._forward_to_upstream(message)

    async def handle_batch(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Process a batch of MCP JSON-RPC messages."""
        results = []
        for msg in messages:
            result = await self.handle_message(msg)
            results.append(result)
        return results

    async def _handle_tool_call(
        self, original_message: dict[str, Any], parsed: ParsedMCPMessage
    ) -> dict[str, Any]:
        """Intercept a tools/call request: evaluate policy, then forward or deny."""
        assert parsed.tool_name is not None

        # Sprint 48: outbound DLP scan before policy evaluation
        if self._dlp_scan_enabled and parsed.tool_args:
            outbound_scan = mcp_outbound_scanner.scan_outbound(
                tool_name=parsed.tool_name,
                tool_args=parsed.tool_args,
                session_id=self.session_id,
                agent_id=self.agent_id,
            )
            if outbound_scan.findings:
                mcp_session_dlp_budget_tracker.record_findings(
                    self.session_id, outbound_scan.findings
                )
                self._security_events.append(MCPSecurityEvent(
                    event_type=MCPSecurityEventType.OUTBOUND_DLP_HIT,
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                    tool_name=parsed.tool_name,
                    severity=outbound_scan.findings[0].severity,
                    description=f"Outbound DLP: {len(outbound_scan.findings)} findings",
                    findings_count=len(outbound_scan.findings),
                    blocked=outbound_scan.blocked,
                ))
            if outbound_scan.blocked:
                logger.warning(
                    "MCP outbound DLP BLOCKED: session=%s tool=%s findings=%d",
                    self.session_id,
                    parsed.tool_name,
                    len(outbound_scan.findings),
                )
                return mcp_message_parser.build_jsonrpc_error(
                    request_id=parsed.request_id,
                    code=MCP_ERROR_DLP_BLOCKED,
                    message="Tool call blocked by outbound DLP scan",
                    data={
                        "decision": "BLOCK",
                        "tool_name": parsed.tool_name,
                        "findings_count": len(outbound_scan.findings),
                    },
                )

        # Build an Intercept API request
        intercept_request = ToolCallRequest(
            session_id=self.session_id,
            agent_id=self.agent_id,
            tool_name=parsed.tool_name,
            tool_args=parsed.tool_args,
            taint_node_ids=mcp_session_tracker.get_taint_node_ids_for_args(
                self.session_id, parsed.tool_name
            ),
        )

        # Evaluate against policy stack
        decision_response = await policy_evaluator.evaluate(intercept_request)

        if decision_response.decision == Decision.DENY:
            logger.info(
                "MCP tool call DENIED: session=%s tool=%s reason=%s",
                self.session_id,
                parsed.tool_name,
                decision_response.reason,
            )
            return mcp_message_parser.build_jsonrpc_error(
                request_id=parsed.request_id,
                code=MCP_ERROR_POLICY_DENIED,
                message=f"Tool call denied by policy: {decision_response.reason}",
                data={
                    "decision": "DENY",
                    "tool_name": parsed.tool_name,
                    "matched_rule_id": str(decision_response.matched_rule_id)
                    if decision_response.matched_rule_id
                    else None,
                },
            )

        if decision_response.decision == Decision.ESCALATE:
            logger.info(
                "MCP tool call ESCALATED: session=%s tool=%s reason=%s",
                self.session_id,
                parsed.tool_name,
                decision_response.reason,
            )
            return mcp_message_parser.build_jsonrpc_error(
                request_id=parsed.request_id,
                code=MCP_ERROR_POLICY_ESCALATED,
                message=f"Tool call requires escalation: {decision_response.reason}",
                data={
                    "decision": "ESCALATE",
                    "tool_name": parsed.tool_name,
                    "escalation_id": str(decision_response.escalation_id)
                    if decision_response.escalation_id
                    else None,
                },
            )

        if decision_response.decision == Decision.TIMEOUT:
            logger.warning(
                "MCP tool call TIMEOUT: session=%s tool=%s", self.session_id, parsed.tool_name
            )
            return mcp_message_parser.build_jsonrpc_error(
                request_id=parsed.request_id,
                code=MCP_ERROR_POLICY_DENIED,
                message="Policy evaluation timed out",
                data={"decision": "TIMEOUT", "tool_name": parsed.tool_name},
            )

        # ALLOW or DRY_RUN — forward to upstream
        if decision_response.decision == Decision.DRY_RUN:
            logger.info(
                "MCP tool call DRY_RUN (forwarding): session=%s tool=%s",
                self.session_id,
                parsed.tool_name,
            )

        upstream_response = await self._forward_to_upstream(original_message)

        # Track tool output taint (APEP-101)
        if "result" in upstream_response:
            tool_call_id = f"{parsed.tool_name}-{parsed.request_id}"
            input_nodes = mcp_session_tracker.get_taint_node_ids_for_args(
                self.session_id, parsed.tool_name
            )
            mcp_session_tracker.label_tool_output(
                session_id=self.session_id,
                tool_call_id=tool_call_id,
                input_node_ids=input_nodes if input_nodes else None,
            )

            # Sprint 48: scan inbound response for injection + DLP
            if self._dlp_scan_enabled:
                resp_scan = mcp_response_scanner.scan_response(
                    tool_name=parsed.tool_name,
                    response_data=upstream_response.get("result"),
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                )
                if resp_scan.dlp_findings:
                    mcp_session_dlp_budget_tracker.record_findings(
                        self.session_id, resp_scan.dlp_findings
                    )
                    self._security_events.append(MCPSecurityEvent(
                        event_type=MCPSecurityEventType.INBOUND_DLP_HIT,
                        session_id=self.session_id,
                        agent_id=self.agent_id,
                        tool_name=parsed.tool_name,
                        severity=resp_scan.dlp_findings[0].severity,
                        description=f"Inbound DLP: {len(resp_scan.dlp_findings)} findings",
                        findings_count=len(resp_scan.dlp_findings),
                    ))
                if resp_scan.injection_findings:
                    self._security_events.append(MCPSecurityEvent(
                        event_type=MCPSecurityEventType.RESPONSE_INJECTION,
                        session_id=self.session_id,
                        agent_id=self.agent_id,
                        tool_name=parsed.tool_name,
                        severity="CRITICAL",
                        description=f"Response injection: {len(resp_scan.injection_findings)} findings",
                        findings_count=len(resp_scan.injection_findings),
                    ))

        return upstream_response

    async def _handle_tools_list(
        self, original_message: dict[str, Any], parsed: ParsedMCPMessage
    ) -> dict[str, Any]:
        """Handle tools/list: forward, then scan for poisoning and rug-pulls (Sprint 48)."""
        upstream_response = await self._forward_to_upstream(original_message)

        # Extract tools from the response
        result = upstream_response.get("result", {})
        tools_list = result.get("tools", []) if isinstance(result, dict) else []

        if not tools_list:
            return upstream_response

        # Tool poisoning detection (APEP-382)
        if self._poisoning_detection_enabled:
            poisoning_result = mcp_tool_poisoning_detector.scan_tools_list(
                tools=tools_list,
                session_id=self.session_id,
                agent_id=self.agent_id,
            )
            if poisoning_result.findings:
                logger.warning(
                    "Tool poisoning detected: session=%s findings=%d blocked=%s",
                    self.session_id,
                    len(poisoning_result.findings),
                    poisoning_result.blocked,
                )
                self._security_events.append(MCPSecurityEvent(
                    event_type=MCPSecurityEventType.TOOL_POISONING_DETECTED,
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                    severity="CRITICAL",
                    description=f"Tool poisoning: {len(poisoning_result.findings)} findings",
                    findings_count=len(poisoning_result.findings),
                    blocked=poisoning_result.blocked,
                ))
                if poisoning_result.blocked:
                    return mcp_message_parser.build_jsonrpc_error(
                        request_id=parsed.request_id,
                        code=MCP_ERROR_TOOL_POISONING,
                        message="Tool poisoning detected in tools/list response",
                        data={
                            "findings_count": len(poisoning_result.findings),
                            "tools_scanned": poisoning_result.tools_scanned,
                        },
                    )

        # Rug-pull detection (APEP-383)
        if self._rug_pull_detection_enabled:
            rug_result = mcp_rug_pull_detector.detect(
                session_id=self.session_id,
                agent_id=self.agent_id,
                tools=tools_list,
            )
            if rug_result.is_rug_pull:
                logger.warning(
                    "Rug-pull detected: session=%s changes=%d blocked=%s",
                    self.session_id,
                    len(rug_result.changes),
                    rug_result.blocked,
                )
                self._security_events.append(MCPSecurityEvent(
                    event_type=MCPSecurityEventType.RUG_PULL_DETECTED,
                    session_id=self.session_id,
                    agent_id=self.agent_id,
                    severity="CRITICAL",
                    description=f"Rug-pull: {len(rug_result.changes)} changes",
                    findings_count=len(rug_result.changes),
                    blocked=rug_result.blocked,
                ))
                if rug_result.blocked:
                    return mcp_message_parser.build_jsonrpc_error(
                        request_id=parsed.request_id,
                        code=MCP_ERROR_RUG_PULL,
                        message="Mid-session tool description change (rug-pull) detected",
                        data={
                            "changes_count": len(rug_result.changes),
                            "changes": [
                                {"tool": c.tool_name, "type": c.change_type}
                                for c in rug_result.changes
                            ],
                        },
                    )

        return upstream_response

    def get_security_events(self) -> list[MCPSecurityEvent]:
        """Get and clear pending security events (for Kafka publishing)."""
        events = list(self._security_events)
        self._security_events.clear()
        return events

    async def _forward_to_upstream(self, message: dict[str, Any]) -> dict[str, Any]:
        """Forward a JSON-RPC message to the upstream MCP server via HTTP POST."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    self.upstream_url,
                    json=message,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as exc:
            logger.error(
                "Upstream MCP server HTTP error: status=%d url=%s",
                exc.response.status_code,
                self.upstream_url,
            )
            return mcp_message_parser.build_jsonrpc_error(
                request_id=message.get("id"),
                code=MCP_ERROR_UPSTREAM_FAILED,
                message=f"Upstream MCP server returned HTTP {exc.response.status_code}",
            )
        except httpx.RequestError as exc:
            logger.error(
                "Upstream MCP server connection error: %s url=%s",
                str(exc),
                self.upstream_url,
            )
            return mcp_message_parser.build_jsonrpc_error(
                request_id=message.get("id"),
                code=MCP_ERROR_UPSTREAM_FAILED,
                message=f"Failed to connect to upstream MCP server: {exc}",
            )
