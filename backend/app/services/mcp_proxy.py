"""MCP tool call intercept proxy — transparent proxy between MCP client and server.

APEP-098: Forwards MCP tool call messages to the target MCP server post-approval.
APEP-100: Integrates with the Intercept API so that DENY returns an MCP error
          response and ALLOW forwards the request to the upstream MCP server.

The proxy sits between an MCP-compliant agent (client) and an MCP tool server:

    Agent  ──▶  AgentPEP MCP Proxy  ──▶  Target MCP Server
                 │
                 ├─ Parse JSON-RPC envelope (APEP-099)
                 ├─ Evaluate via Intercept API (APEP-100)
                 ├─ Track taint per session (APEP-101)
                 └─ Forward or deny
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

import httpx

from app.models.policy import Decision, ToolCallRequest
from app.services.mcp_message_parser import (
    MCPMessageParser,
    MCPMessageType,
    MCPParseError,
    ParsedMCPMessage,
    mcp_message_parser,
)
from app.services.mcp_session_tracker import mcp_session_tracker
from app.services.policy_evaluator import policy_evaluator

logger = logging.getLogger(__name__)

# MCP-specific JSON-RPC error codes
MCP_ERROR_POLICY_DENIED = -32001
MCP_ERROR_POLICY_ESCALATED = -32002
MCP_ERROR_UPSTREAM_FAILED = -32003
MCP_ERROR_SESSION_UNKNOWN = -32004


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

    def __init__(self, upstream_url: str, agent_id: str, session_id: str | None = None):
        """
        Args:
            upstream_url: Base URL of the target MCP server (e.g. http://localhost:3000/mcp).
            agent_id: The agent ID for policy evaluation.
            session_id: Optional session ID; auto-generated if not provided.
        """
        self.upstream_url = upstream_url.rstrip("/")
        self.agent_id = agent_id
        self.session_id = session_id or f"mcp-{uuid4().hex[:12]}"
        self._started = False

    async def start(self) -> None:
        """Start the proxy session and initialise taint tracking."""
        if not self._started:
            mcp_session_tracker.start_session(self.session_id, self.agent_id)
            self._started = True

    async def stop(self) -> None:
        """End the proxy session and persist taint graph."""
        if self._started:
            await mcp_session_tracker.end_session(self.session_id)
            self._started = False

    async def handle_message(self, message: dict[str, Any]) -> dict[str, Any]:
        """Process a single MCP JSON-RPC message.

        Returns the JSON-RPC response (either from upstream or a policy denial).
        """
        if not self._started:
            await self.start()

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
        if parsed.message_type == MCPMessageType.TOOL_CALL and (parsed.is_request or parsed.is_notification):
            return await self._handle_tool_call(message, parsed)

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

        # Build an Intercept API request
        # TODO: taint_node_ids should be populated from the session context's
        # taint graph (e.g. tracking which tool outputs fed into this call's
        # arguments).  Currently get_taint_node_ids_for_args may return an
        # empty list if the session taint graph hasn't been wired up, which
        # means taint-based policy checks won't fire.  Wire up the MCP
        # session tracker to propagate taint labels from prior tool outputs.
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

        return upstream_response

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
