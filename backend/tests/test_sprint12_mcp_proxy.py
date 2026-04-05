"""Integration tests for Sprint 12 — MCP Tool Call Intercept Proxy.

Covers APEP-098 through APEP-104:
  - MCP JSON-RPC message parsing (APEP-099)
  - MCP proxy server forwarding (APEP-098)
  - Intercept API integration: DENY→error, ALLOW→forward (APEP-100)
  - MCP session tracking with taint graph (APEP-101)
  - MCP proxy configuration on AgentProfile (APEP-102)
  - End-to-end integration with MCP-compliant test server (APEP-103)
"""

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.models.policy import (
    AgentProfile,
    MCPProxyConfig,
    TaintLevel,
    TaintSource,
)
from app.services.mcp_message_parser import (
    MCPMessageType,
    MCPParseError,
    mcp_message_parser,
)
from app.services.mcp_session_tracker import mcp_session_tracker


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tool_call_message(
    tool_name: str = "read_file",
    arguments: dict | None = None,
    request_id: str | int | None = 1,
) -> dict:
    """Build a valid MCP JSON-RPC tools/call request."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments or {"path": "/tmp/test.txt"},
        },
    }


def _make_tools_list_message(request_id: str | int = 2) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/list",
        "params": {},
    }


def _make_notification(method: str = "notifications/initialized") -> dict:
    return {
        "jsonrpc": "2.0",
        "method": method,
        "params": {},
    }


def _make_response(request_id: int = 1, result: dict | None = None) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result or {"content": [{"type": "text", "text": "hello"}]},
    }


async def _seed_agent_profile(mock_db, agent_id: str = "test-agent", mcp_enabled: bool = True):
    """Insert an agent profile into the mock database."""
    profile = {
        "agent_id": agent_id,
        "name": "Test Agent",
        "roles": ["reader"],
        "allowed_tools": ["*"],
        "risk_budget": 1.0,
        "max_delegation_depth": 5,
        "session_limit": 100,
        "mcp_proxy": {
            "enabled": mcp_enabled,
            "upstream_url": "http://localhost:9999/mcp",
            "allowed_tools": ["*"],
            "timeout_s": 30.0,
            "max_concurrent_sessions": 10,
            "taint_tracking_enabled": True,
        },
        "enabled": True,
    }
    await mock_db["agent_profiles"].insert_one(profile)
    return profile


async def _seed_allow_rule(mock_db, tool_pattern: str = "*"):
    """Insert a policy rule that ALLOWs the given tool pattern."""
    rule = {
        "rule_id": str(uuid.uuid4()),
        "name": "allow-all",
        "agent_role": ["*"],
        "tool_pattern": tool_pattern,
        "action": "ALLOW",
        "taint_check": False,
        "risk_threshold": 1.0,
        "priority": 10,
        "enabled": True,
        "arg_validators": [],
    }
    await mock_db["policy_rules"].insert_one(rule)
    return rule


async def _seed_deny_rule(mock_db, tool_pattern: str = "dangerous_*"):
    """Insert a policy rule that DENYs the given tool pattern."""
    rule = {
        "rule_id": str(uuid.uuid4()),
        "name": "deny-dangerous",
        "agent_role": ["*"],
        "tool_pattern": tool_pattern,
        "action": "DENY",
        "taint_check": False,
        "risk_threshold": 1.0,
        "priority": 1,
        "enabled": True,
        "arg_validators": [],
    }
    await mock_db["policy_rules"].insert_one(rule)
    return rule


# ===========================================================================
# APEP-099: MCP Message Parsing
# ===========================================================================


class TestMCPMessageParser:
    """Tests for MCP JSON-RPC envelope parsing."""

    def test_parse_tool_call_request(self):
        """tools/call request extracts tool name and arguments."""
        msg = _make_tool_call_message("read_file", {"path": "/etc/hosts"}, request_id=42)
        parsed = mcp_message_parser.parse(msg)

        assert parsed.message_type == MCPMessageType.TOOL_CALL
        assert parsed.tool_name == "read_file"
        assert parsed.tool_args == {"path": "/etc/hosts"}
        assert parsed.request_id == 42
        assert parsed.is_request is True
        assert parsed.is_response is False
        assert parsed.is_notification is False
        assert parsed.method == "tools/call"

    def test_parse_tools_list_request(self):
        """tools/list request is classified correctly."""
        msg = _make_tools_list_message(request_id=5)
        parsed = mcp_message_parser.parse(msg)

        assert parsed.message_type == MCPMessageType.TOOL_LIST
        assert parsed.tool_name is None
        assert parsed.is_request is True
        assert parsed.request_id == 5

    def test_parse_notification(self):
        """Notification (no id) is classified correctly."""
        msg = _make_notification("notifications/progress")
        parsed = mcp_message_parser.parse(msg)

        assert parsed.message_type == MCPMessageType.NOTIFICATION
        assert parsed.is_notification is True
        assert parsed.request_id is None

    def test_parse_response(self):
        """Response (has result + id) is classified correctly."""
        msg = _make_response(request_id=7)
        parsed = mcp_message_parser.parse(msg)

        assert parsed.message_type == MCPMessageType.RESPONSE
        assert parsed.is_response is True
        assert parsed.request_id == 7

    def test_parse_error_response(self):
        """Error response (has error + id) is classified correctly."""
        msg = {"jsonrpc": "2.0", "id": 3, "error": {"code": -32600, "message": "Invalid"}}
        parsed = mcp_message_parser.parse(msg)

        assert parsed.message_type == MCPMessageType.RESPONSE
        assert parsed.is_response is True

    def test_parse_missing_jsonrpc_raises(self):
        """Missing jsonrpc field raises MCPParseError."""
        with pytest.raises(MCPParseError, match="jsonrpc version"):
            mcp_message_parser.parse({"id": 1, "method": "tools/call"})

    def test_parse_wrong_jsonrpc_version_raises(self):
        """Wrong jsonrpc version raises MCPParseError."""
        with pytest.raises(MCPParseError, match="jsonrpc version"):
            mcp_message_parser.parse({"jsonrpc": "1.0", "id": 1, "method": "tools/call"})

    def test_parse_non_dict_raises(self):
        """Non-dict input raises MCPParseError."""
        with pytest.raises(MCPParseError, match="JSON object"):
            mcp_message_parser.parse("not a dict")  # type: ignore

    def test_parse_tool_call_missing_name_raises(self):
        """tools/call without 'name' in params raises MCPParseError."""
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"arguments": {}},
        }
        with pytest.raises(MCPParseError, match="name"):
            mcp_message_parser.parse(msg)

    def test_parse_tool_call_invalid_arguments_raises(self):
        """tools/call with non-dict arguments raises MCPParseError."""
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "foo", "arguments": "not-a-dict"},
        }
        with pytest.raises(MCPParseError, match="arguments"):
            mcp_message_parser.parse(msg)

    def test_parse_unclassifiable_message_raises(self):
        """Message with no method, result, or error raises MCPParseError."""
        with pytest.raises(MCPParseError, match="Cannot classify"):
            mcp_message_parser.parse({"jsonrpc": "2.0", "id": 1})

    def test_parse_batch(self):
        """Batch parsing returns list of parsed messages."""
        messages = [
            _make_tool_call_message("tool_a", request_id=1),
            _make_tools_list_message(request_id=2),
            _make_notification(),
        ]
        results = mcp_message_parser.parse_batch(messages)

        assert len(results) == 3
        assert results[0].message_type == MCPMessageType.TOOL_CALL
        assert results[1].message_type == MCPMessageType.TOOL_LIST
        assert results[2].message_type == MCPMessageType.NOTIFICATION

    def test_parse_empty_batch_raises(self):
        """Empty batch raises MCPParseError."""
        with pytest.raises(MCPParseError, match="non-empty"):
            mcp_message_parser.parse_batch([])

    def test_parse_unknown_method(self):
        """Unknown method string classifies as UNKNOWN."""
        msg = {"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {}}
        parsed = mcp_message_parser.parse(msg)
        assert parsed.message_type == MCPMessageType.UNKNOWN

    def test_build_jsonrpc_error(self):
        """build_jsonrpc_error produces valid JSON-RPC error envelope."""
        err = mcp_message_parser.build_jsonrpc_error(42, -32001, "denied", data={"x": 1})
        assert err["jsonrpc"] == "2.0"
        assert err["id"] == 42
        assert err["error"]["code"] == -32001
        assert err["error"]["message"] == "denied"
        assert err["error"]["data"] == {"x": 1}

    def test_build_jsonrpc_result(self):
        """build_jsonrpc_result produces valid JSON-RPC result envelope."""
        res = mcp_message_parser.build_jsonrpc_result(7, {"tools": []})
        assert res["jsonrpc"] == "2.0"
        assert res["id"] == 7
        assert res["result"] == {"tools": []}

    def test_parse_tool_call_with_empty_arguments(self):
        """tools/call with no arguments field defaults to empty dict."""
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "no_args_tool"},
        }
        parsed = mcp_message_parser.parse(msg)
        assert parsed.tool_args == {}

    def test_parse_params_must_be_dict(self):
        """Non-dict params raises MCPParseError."""
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": [1, 2, 3]}
        with pytest.raises(MCPParseError, match="params must be an object"):
            mcp_message_parser.parse(msg)


# ===========================================================================
# APEP-101: MCP Session Tracking
# ===========================================================================


class TestMCPSessionTracker:
    """Tests for MCP session lifecycle and taint graph tracking."""

    def test_start_and_has_session(self):
        """start_session creates a session that can be queried."""
        mcp_session_tracker.start_session("sess-1", "agent-a")

        assert mcp_session_tracker.has_session("sess-1")
        state = mcp_session_tracker.get_session("sess-1")
        assert state is not None
        assert state.agent_id == "agent-a"
        assert state.tool_call_count == 0

    def test_session_not_found(self):
        assert mcp_session_tracker.has_session("nonexistent") is False
        assert mcp_session_tracker.get_session("nonexistent") is None

    def test_label_tool_input(self):
        """label_tool_input creates a taint node in the session graph."""
        mcp_session_tracker.start_session("sess-2", "agent-b")
        node_id = mcp_session_tracker.label_tool_input(
            "sess-2", "read_file", "path",
            taint_level=TaintLevel.UNTRUSTED,
            source=TaintSource.WEB,
        )
        assert node_id is not None

    def test_label_tool_input_no_session_returns_none(self):
        result = mcp_session_tracker.label_tool_input("no-sess", "tool", "arg")
        assert result is None

    def test_label_tool_output(self):
        """label_tool_output creates a taint node and increments tool call count."""
        mcp_session_tracker.start_session("sess-3", "agent-c")
        node_id = mcp_session_tracker.label_tool_output(
            "sess-3", "read_file-1"
        )
        assert node_id is not None

        state = mcp_session_tracker.get_session("sess-3")
        assert state.tool_call_count == 1
        assert state.last_tool_call_id == "read_file-1"

    def test_label_tool_output_with_propagation(self):
        """label_tool_output propagates taint from input nodes."""
        mcp_session_tracker.start_session("sess-4", "agent-d")

        # Create an input node
        input_id = mcp_session_tracker.label_tool_input(
            "sess-4", "tool", "arg",
            taint_level=TaintLevel.UNTRUSTED,
            source=TaintSource.WEB,
        )

        # Create output propagating from input
        output_id = mcp_session_tracker.label_tool_output(
            "sess-4", "tool-call-1",
            input_node_ids=[input_id],
        )
        assert output_id is not None

    @pytest.mark.asyncio
    async def test_end_session(self):
        """end_session removes the session from the tracker."""
        mcp_session_tracker.start_session("sess-5", "agent-e")
        assert mcp_session_tracker.has_session("sess-5")

        await mcp_session_tracker.end_session("sess-5")
        assert not mcp_session_tracker.has_session("sess-5")

    @pytest.mark.asyncio
    async def test_end_session_nonexistent(self):
        """end_session for unknown session does not raise."""
        await mcp_session_tracker.end_session("nonexistent-sess")

    def test_active_session_count(self):
        mcp_session_tracker.start_session("sess-c1", "agent-1")
        mcp_session_tracker.start_session("sess-c2", "agent-2")
        assert mcp_session_tracker.active_session_count() >= 2

    def test_list_sessions(self):
        mcp_session_tracker.start_session("sess-ls1", "agent-1")
        sessions = mcp_session_tracker.list_sessions()
        assert "sess-ls1" in sessions


# ===========================================================================
# APEP-102: MCP Proxy Configuration on AgentProfile
# ===========================================================================


class TestMCPProxyConfig:
    """Tests for MCP proxy configuration model on AgentProfile."""

    def test_default_mcp_proxy_config(self):
        """AgentProfile has MCP proxy config with sensible defaults."""
        profile = AgentProfile(agent_id="test", name="Test")
        assert profile.mcp_proxy is not None
        assert profile.mcp_proxy.enabled is False
        assert profile.mcp_proxy.upstream_url == ""
        assert profile.mcp_proxy.timeout_s == 30.0
        assert profile.mcp_proxy.max_concurrent_sessions == 10
        assert profile.mcp_proxy.taint_tracking_enabled is True

    def test_mcp_proxy_config_custom(self):
        """AgentProfile accepts custom MCP proxy configuration."""
        config = MCPProxyConfig(
            enabled=True,
            upstream_url="http://mcp-server:3000/mcp",
            allowed_tools=["read_*", "write_*"],
            timeout_s=15.0,
            max_concurrent_sessions=5,
        )
        profile = AgentProfile(
            agent_id="custom-agent",
            name="Custom Agent",
            mcp_proxy=config,
        )
        assert profile.mcp_proxy.enabled is True
        assert profile.mcp_proxy.upstream_url == "http://mcp-server:3000/mcp"
        assert profile.mcp_proxy.allowed_tools == ["read_*", "write_*"]
        assert profile.mcp_proxy.max_concurrent_sessions == 5

    def test_mcp_proxy_config_serialization(self):
        """MCPProxyConfig round-trips through JSON serialization."""
        profile = AgentProfile(
            agent_id="serial-test",
            name="Serial",
            mcp_proxy=MCPProxyConfig(enabled=True, upstream_url="http://x:3000"),
        )
        data = profile.model_dump(mode="json")
        assert data["mcp_proxy"]["enabled"] is True
        assert data["mcp_proxy"]["upstream_url"] == "http://x:3000"

        restored = AgentProfile(**data)
        assert restored.mcp_proxy.enabled is True


# ===========================================================================
# APEP-098 + APEP-100: MCP Proxy Server + Intercept Integration
# ===========================================================================


class TestMCPProxyIntegration:
    """Integration tests for the MCP proxy with Intercept API."""

    @pytest.mark.asyncio
    async def test_proxy_tool_call_denied(self, mock_mongodb):
        """DENY decision returns MCP JSON-RPC error without contacting upstream."""
        from app.services.mcp_proxy import MCPProxy

        # Seed deny rule (no allow rule → deny-by-default)
        proxy = MCPProxy(
            upstream_url="http://localhost:9999/mcp",
            agent_id="test-agent",
            session_id="deny-sess",
        )
        await proxy.start()

        msg = _make_tool_call_message("read_file")
        result = await proxy.handle_message(msg)

        assert "error" in result
        assert result["error"]["code"] == -32001  # MCP_ERROR_POLICY_DENIED
        assert "denied" in result["error"]["message"].lower() or "deny" in result["error"]["message"].lower()
        assert result["id"] == 1

        await proxy.stop()

    @pytest.mark.asyncio
    async def test_proxy_tool_call_allowed_forwards_to_upstream(self, mock_mongodb):
        """ALLOW decision forwards the message to upstream MCP server."""
        from app.services.mcp_proxy import MCPProxy

        await _seed_allow_rule(mock_mongodb, "*")

        upstream_response = _make_response(request_id=1, result={"content": [{"type": "text", "text": "ok"}]})

        proxy = MCPProxy(
            upstream_url="http://fake-upstream:3000/mcp",
            agent_id="test-agent",
            session_id="allow-sess",
        )
        await proxy.start()

        msg = _make_tool_call_message("read_file", request_id=1)

        with patch("app.services.mcp_proxy.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = upstream_response
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            result = await proxy.handle_message(msg)

        assert "result" in result
        assert result["result"]["content"][0]["text"] == "ok"

        await proxy.stop()

    @pytest.mark.asyncio
    async def test_proxy_non_tool_call_forwarded_transparently(self, mock_mongodb):
        """Non-tool-call messages (tools/list) are forwarded without policy check."""
        from app.services.mcp_proxy import MCPProxy

        upstream_response = {"jsonrpc": "2.0", "id": 2, "result": {"tools": []}}

        proxy = MCPProxy(
            upstream_url="http://fake-upstream:3000/mcp",
            agent_id="test-agent",
            session_id="fwd-sess",
        )
        await proxy.start()

        msg = _make_tools_list_message(request_id=2)

        with patch("app.services.mcp_proxy.httpx.AsyncClient") as MockClient:
            mock_response = MagicMock()
            mock_response.json.return_value = upstream_response
            mock_response.raise_for_status = MagicMock()

            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_response
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            result = await proxy.handle_message(msg)

        assert result["result"]["tools"] == []

        await proxy.stop()

    @pytest.mark.asyncio
    async def test_proxy_invalid_message_returns_error(self, mock_mongodb):
        """Malformed JSON-RPC message returns a parse error."""
        from app.services.mcp_proxy import MCPProxy

        proxy = MCPProxy(
            upstream_url="http://localhost:9999/mcp",
            agent_id="test-agent",
            session_id="parse-err-sess",
        )
        await proxy.start()

        result = await proxy.handle_message({"not": "valid"})

        assert "error" in result
        assert result["error"]["code"] == -32600

        await proxy.stop()

    @pytest.mark.asyncio
    async def test_proxy_upstream_connection_error(self, mock_mongodb):
        """Upstream connection failure returns MCP upstream error."""
        from app.services.mcp_proxy import MCPProxy

        await _seed_allow_rule(mock_mongodb, "*")

        proxy = MCPProxy(
            upstream_url="http://nonexistent-host:9999/mcp",
            agent_id="test-agent",
            session_id="conn-err-sess",
        )
        await proxy.start()

        msg = _make_tool_call_message("read_file")

        # The real httpx will fail to connect
        result = await proxy.handle_message(msg)

        assert "error" in result
        assert result["error"]["code"] == -32003  # MCP_ERROR_UPSTREAM_FAILED

        await proxy.stop()

    @pytest.mark.asyncio
    async def test_proxy_batch_handling(self, mock_mongodb):
        """Batch of messages returns list of responses."""
        from app.services.mcp_proxy import MCPProxy

        proxy = MCPProxy(
            upstream_url="http://localhost:9999/mcp",
            agent_id="test-agent",
            session_id="batch-sess",
        )
        await proxy.start()

        # Both will be denied (no allow rules)
        messages = [
            _make_tool_call_message("tool_a", request_id=1),
            _make_tool_call_message("tool_b", request_id=2),
        ]
        results = await proxy.handle_batch(messages)

        assert len(results) == 2
        assert all("error" in r for r in results)

        await proxy.stop()

    @pytest.mark.asyncio
    async def test_proxy_denied_with_specific_rule(self, mock_mongodb):
        """A deny rule for a specific tool returns MCP error for that tool."""
        from app.services.mcp_proxy import MCPProxy

        await _seed_deny_rule(mock_mongodb, "dangerous_*")
        await _seed_allow_rule(mock_mongodb, "*")

        proxy = MCPProxy(
            upstream_url="http://localhost:9999/mcp",
            agent_id="test-agent",
            session_id="deny-rule-sess",
        )
        await proxy.start()

        msg = _make_tool_call_message("dangerous_delete")
        result = await proxy.handle_message(msg)

        assert "error" in result
        assert result["error"]["code"] == -32001
        assert result["error"]["data"]["decision"] == "DENY"

        await proxy.stop()


# ===========================================================================
# APEP-103: End-to-End API Endpoint Tests
# ===========================================================================


class TestMCPAPIEndpoints:
    """Tests for MCP proxy REST API endpoints."""

    @pytest.mark.asyncio
    async def test_start_session_endpoint(self, client: AsyncClient, mock_mongodb):
        """POST /v1/mcp/session/start creates a new proxy session."""
        await _seed_agent_profile(mock_mongodb, "api-agent")

        resp = await client.post("/v1/mcp/session/start", json={
            "agent_id": "api-agent",
            "upstream_url": "http://localhost:9999/mcp",
        })

        assert resp.status_code == 200
        data = resp.json()
        assert data["agent_id"] == "api-agent"
        assert data["status"] == "active"
        assert "session_id" in data

    @pytest.mark.asyncio
    async def test_start_session_agent_not_found(self, client: AsyncClient, mock_mongodb):
        """POST /v1/mcp/session/start returns 404 for unknown agent."""
        resp = await client.post("/v1/mcp/session/start", json={
            "agent_id": "nonexistent",
            "upstream_url": "http://localhost:9999/mcp",
        })
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_end_session_endpoint(self, client: AsyncClient, mock_mongodb):
        """POST /v1/mcp/session/end ends an active session."""
        await _seed_agent_profile(mock_mongodb, "end-agent")

        # Start session
        start_resp = await client.post("/v1/mcp/session/start", json={
            "agent_id": "end-agent",
            "upstream_url": "http://localhost:9999/mcp",
        })
        session_id = start_resp.json()["session_id"]

        # End session
        end_resp = await client.post("/v1/mcp/session/end", json={
            "session_id": session_id,
        })
        assert end_resp.status_code == 200
        assert end_resp.json()["status"] == "ended"

    @pytest.mark.asyncio
    async def test_end_session_not_found(self, client: AsyncClient, mock_mongodb):
        """POST /v1/mcp/session/end returns 404 for unknown session."""
        resp = await client.post("/v1/mcp/session/end", json={
            "session_id": "nonexistent-session",
        })
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_session_status(self, client: AsyncClient, mock_mongodb):
        """GET /v1/mcp/session/{id} returns session status."""
        await _seed_agent_profile(mock_mongodb, "status-agent")

        start_resp = await client.post("/v1/mcp/session/start", json={
            "agent_id": "status-agent",
            "upstream_url": "http://localhost:9999/mcp",
        })
        session_id = start_resp.json()["session_id"]

        status_resp = await client.get(f"/v1/mcp/session/{session_id}")
        assert status_resp.status_code == 200
        data = status_resp.json()
        assert data["session_id"] == session_id
        assert data["agent_id"] == "status-agent"
        assert data["status"] == "active"
        assert data["tool_call_count"] == 0

    @pytest.mark.asyncio
    async def test_list_sessions(self, client: AsyncClient, mock_mongodb):
        """GET /v1/mcp/sessions returns all active sessions."""
        await _seed_agent_profile(mock_mongodb, "list-agent")

        await client.post("/v1/mcp/session/start", json={
            "agent_id": "list-agent",
            "upstream_url": "http://localhost:9999/mcp",
        })

        resp = await client.get("/v1/mcp/sessions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        assert len(data["active_sessions"]) >= 1

    @pytest.mark.asyncio
    async def test_proxy_endpoint_denied(self, client: AsyncClient, mock_mongodb):
        """POST /v1/mcp/proxy returns MCP error when tool call is denied."""
        await _seed_agent_profile(mock_mongodb, "proxy-agent")

        start_resp = await client.post("/v1/mcp/session/start", json={
            "agent_id": "proxy-agent",
            "upstream_url": "http://localhost:9999/mcp",
        })
        session_id = start_resp.json()["session_id"]

        # No allow rule → deny by default
        resp = await client.post("/v1/mcp/proxy", json={
            "session_id": session_id,
            "message": _make_tool_call_message("read_file"),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "error" in data
        assert data["error"]["code"] == -32001

    @pytest.mark.asyncio
    async def test_proxy_endpoint_no_session(self, client: AsyncClient, mock_mongodb):
        """POST /v1/mcp/proxy returns 404 for unknown session."""
        resp = await client.post("/v1/mcp/proxy", json={
            "session_id": "no-session",
            "message": _make_tool_call_message("read_file"),
        })
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_proxy_batch_endpoint(self, client: AsyncClient, mock_mongodb):
        """POST /v1/mcp/proxy/batch processes multiple messages."""
        await _seed_agent_profile(mock_mongodb, "batch-agent")

        start_resp = await client.post("/v1/mcp/session/start", json={
            "agent_id": "batch-agent",
            "upstream_url": "http://localhost:9999/mcp",
        })
        session_id = start_resp.json()["session_id"]

        resp = await client.post("/v1/mcp/proxy/batch", json={
            "session_id": session_id,
            "messages": [
                _make_tool_call_message("tool_a", request_id=1),
                _make_tool_call_message("tool_b", request_id=2),
            ],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    @pytest.mark.asyncio
    async def test_full_session_lifecycle(self, client: AsyncClient, mock_mongodb):
        """Full lifecycle: start → proxy calls → end session."""
        await _seed_agent_profile(mock_mongodb, "lifecycle-agent")
        await _seed_deny_rule(mock_mongodb, "dangerous_*")
        await _seed_allow_rule(mock_mongodb, "*")

        # 1. Start session
        start_resp = await client.post("/v1/mcp/session/start", json={
            "agent_id": "lifecycle-agent",
            "upstream_url": "http://localhost:9999/mcp",
        })
        assert start_resp.status_code == 200
        session_id = start_resp.json()["session_id"]

        # 2. Proxy a denied tool call
        deny_resp = await client.post("/v1/mcp/proxy", json={
            "session_id": session_id,
            "message": _make_tool_call_message("dangerous_delete"),
        })
        assert "error" in deny_resp.json()
        assert deny_resp.json()["error"]["data"]["decision"] == "DENY"

        # 3. Check session status
        status_resp = await client.get(f"/v1/mcp/session/{session_id}")
        assert status_resp.status_code == 200

        # 4. End session
        end_resp = await client.post("/v1/mcp/session/end", json={
            "session_id": session_id,
        })
        assert end_resp.json()["status"] == "ended"

        # 5. Session no longer accessible
        status_resp = await client.get(f"/v1/mcp/session/{session_id}")
        assert status_resp.status_code == 404
