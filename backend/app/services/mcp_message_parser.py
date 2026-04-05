"""MCP message parser — extract tool name and arguments from MCP JSON-RPC envelopes.

APEP-099: Parses MCP (Model Context Protocol) JSON-RPC 2.0 messages to extract
tool call information for policy evaluation. Supports:
  - tools/call requests (tool invocation)
  - tools/list requests (tool discovery)
  - Notification messages (no id field)
  - Batch requests (array of messages)
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class MCPMessageType(str, Enum):
    """Classified MCP message types."""

    TOOL_CALL = "tools/call"
    TOOL_LIST = "tools/list"
    TOOL_RESULT = "tools/call/result"
    NOTIFICATION = "notification"
    RESPONSE = "response"
    UNKNOWN = "unknown"


class ParsedMCPMessage(BaseModel):
    """Result of parsing an MCP JSON-RPC envelope."""

    message_type: MCPMessageType
    request_id: str | int | None = None
    method: str | None = None
    tool_name: str | None = None
    tool_args: dict[str, Any] = Field(default_factory=dict)
    is_request: bool = False
    is_response: bool = False
    is_notification: bool = False
    raw_params: dict[str, Any] = Field(default_factory=dict)


class MCPParseError(Exception):
    """Raised when an MCP message cannot be parsed."""

    def __init__(self, message: str, code: int = -32600):
        super().__init__(message)
        self.code = code


class MCPMessageParser:
    """Parses MCP JSON-RPC 2.0 messages and extracts tool call information."""

    def parse(self, message: dict[str, Any]) -> ParsedMCPMessage:
        """Parse a single MCP JSON-RPC message.

        Args:
            message: A JSON-RPC 2.0 message dict.

        Returns:
            ParsedMCPMessage with extracted fields.

        Raises:
            MCPParseError: If the message is malformed.
        """
        if not isinstance(message, dict):
            raise MCPParseError("MCP message must be a JSON object")

        jsonrpc = message.get("jsonrpc")
        if jsonrpc != "2.0":
            raise MCPParseError(
                f"Invalid or missing jsonrpc version: {jsonrpc!r} (expected '2.0')"
            )

        # Determine message category
        has_id = "id" in message
        has_method = "method" in message
        has_result = "result" in message
        has_error = "error" in message

        if has_method and has_id:
            return self._parse_request(message)
        elif has_method and not has_id:
            return self._parse_notification(message)
        elif (has_result or has_error) and has_id:
            return self._parse_response(message)
        else:
            raise MCPParseError("Cannot classify MCP message: missing method/result/error fields")

    def parse_batch(self, messages: list[dict[str, Any]]) -> list[ParsedMCPMessage]:
        """Parse a batch of MCP JSON-RPC messages.

        Args:
            messages: List of JSON-RPC 2.0 message dicts.

        Returns:
            List of ParsedMCPMessage results.

        Raises:
            MCPParseError: If the batch is empty or not a list.
        """
        if not isinstance(messages, list) or len(messages) == 0:
            raise MCPParseError("Batch must be a non-empty array of JSON-RPC messages")
        return [self.parse(msg) for msg in messages]

    def _parse_request(self, message: dict[str, Any]) -> ParsedMCPMessage:
        """Parse a JSON-RPC request (has both 'method' and 'id')."""
        method = message["method"]
        request_id = message["id"]
        params = message.get("params", {})

        if not isinstance(method, str):
            raise MCPParseError("JSON-RPC method must be a string")

        if not isinstance(params, dict):
            raise MCPParseError("JSON-RPC params must be an object for MCP messages")

        message_type = self._classify_method(method)
        tool_name: str | None = None
        tool_args: dict[str, Any] = {}

        if message_type == MCPMessageType.TOOL_CALL:
            tool_name = params.get("name")
            if not tool_name or not isinstance(tool_name, str):
                raise MCPParseError(
                    "tools/call request must include 'name' string in params",
                    code=-32602,
                )
            tool_args = params.get("arguments", {})
            if not isinstance(tool_args, dict):
                raise MCPParseError(
                    "tools/call 'arguments' must be an object",
                    code=-32602,
                )

        return ParsedMCPMessage(
            message_type=message_type,
            request_id=request_id,
            method=method,
            tool_name=tool_name,
            tool_args=tool_args,
            is_request=True,
            raw_params=params,
        )

    def _parse_notification(self, message: dict[str, Any]) -> ParsedMCPMessage:
        """Parse a JSON-RPC notification (has 'method' but no 'id').

        Notifications are also classified and may carry tool call information
        so that policy can be evaluated for notification messages as well,
        not just requests.
        """
        method = message["method"]
        params = message.get("params", {})

        if not isinstance(method, str):
            raise MCPParseError("JSON-RPC method must be a string")

        raw_params = params if isinstance(params, dict) else {}

        # Classify the method so that tool-call notifications are subject
        # to policy evaluation (prevents notification-based policy bypass).
        message_type = self._classify_method(method)
        tool_name: str | None = None
        tool_args: dict[str, Any] = {}

        if message_type == MCPMessageType.TOOL_CALL and isinstance(params, dict):
            tool_name = params.get("name")
            if tool_name and isinstance(tool_name, str):
                tool_args = params.get("arguments", {})
                if not isinstance(tool_args, dict):
                    tool_args = {}

        # Fall back to NOTIFICATION type if the method isn't a known tool method
        if message_type == MCPMessageType.UNKNOWN:
            message_type = MCPMessageType.NOTIFICATION

        return ParsedMCPMessage(
            message_type=message_type,
            method=method,
            tool_name=tool_name,
            tool_args=tool_args,
            is_notification=True,
            raw_params=raw_params,
        )

    def _parse_response(self, message: dict[str, Any]) -> ParsedMCPMessage:
        """Parse a JSON-RPC response (has 'result' or 'error' with 'id').

        Wraps parsing in try/except so that non-object results (e.g. a bare
        string or number in the ``result`` field) do not cause a 500 error.
        """
        try:
            request_id = message["id"]
            is_error = "error" in message
            raw_result = message.get("result", {}) if not is_error else {}

            # Ensure raw_params is always a dict to satisfy the model
            if not isinstance(raw_result, dict):
                raw_result = {"value": raw_result}

            return ParsedMCPMessage(
                message_type=MCPMessageType.RESPONSE,
                request_id=request_id,
                is_response=True,
                raw_params=raw_result,
            )
        except Exception as exc:
            # Return a generic error response rather than letting a 500 propagate
            return ParsedMCPMessage(
                message_type=MCPMessageType.RESPONSE,
                request_id=message.get("id"),
                is_response=True,
                raw_params={"_parse_error": str(exc)},
            )

    @staticmethod
    def _classify_method(method: str) -> MCPMessageType:
        """Classify the MCP method string into a message type."""
        method_map = {
            "tools/call": MCPMessageType.TOOL_CALL,
            "tools/list": MCPMessageType.TOOL_LIST,
        }
        return method_map.get(method, MCPMessageType.UNKNOWN)

    @staticmethod
    def build_jsonrpc_error(
        request_id: str | int | None,
        code: int,
        message: str,
        data: Any = None,
    ) -> dict[str, Any]:
        """Build a JSON-RPC 2.0 error response.

        Args:
            request_id: Original request ID (or None).
            code: JSON-RPC error code.
            message: Human-readable error message.
            data: Optional additional error data.
        """
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": error,
        }

    @staticmethod
    def build_jsonrpc_result(
        request_id: str | int | None,
        result: Any,
    ) -> dict[str, Any]:
        """Build a JSON-RPC 2.0 success response."""
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result,
        }


# Module-level singleton
mcp_message_parser = MCPMessageParser()
