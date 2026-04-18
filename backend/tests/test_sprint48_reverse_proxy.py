"""Unit tests for Sprint 48 — MCP HTTP Reverse Proxy (APEP-384).

Tests the MCPReverseProxy for:
  - Session creation and configuration
  - Request forwarding
  - DLP budget enforcement
  - Event collection
"""

import json

import pytest

from app.models.mcp_security import MCPReverseProxyConfig
from app.services.mcp_reverse_proxy import MCPReverseProxy
from app.services.mcp_session_dlp_budget import mcp_session_dlp_budget_tracker


@pytest.fixture
def config():
    return MCPReverseProxyConfig(
        enabled=True,
        upstream_url="http://test-mcp:3000/mcp",
        dlp_scan_enabled=True,
        poisoning_detection_enabled=True,
        rug_pull_detection_enabled=True,
    )


@pytest.fixture
def proxy(config):
    return MCPReverseProxy(
        upstream_url="http://test-mcp:3000/mcp",
        agent_id="agent-001",
        session_id="rev-sess-001",
        config=config,
    )


class TestReverseProxyCreation:
    def test_create_reverse_proxy(self, config):
        proxy = MCPReverseProxy(
            upstream_url="http://test:3000",
            agent_id="agent-test",
            config=config,
        )
        assert proxy.agent_id == "agent-test"
        assert proxy.upstream_url == "http://test:3000"
        assert proxy.session_id.startswith("mcp-rev-")

    def test_custom_session_id(self, config):
        proxy = MCPReverseProxy(
            upstream_url="http://test:3000",
            agent_id="agent-test",
            session_id="custom-sess",
            config=config,
        )
        assert proxy.session_id == "custom-sess"

    def test_session_info(self, proxy):
        info = proxy.session_info
        assert info.session_id == "rev-sess-001"
        assert info.agent_id == "agent-001"
        assert info.status == "active"
        assert info.request_count == 0


class TestDLPBudgetEnforcement:
    @pytest.mark.anyio
    async def test_budget_exceeded_returns_429(self, proxy):
        """When DLP budget is exceeded, requests should be rejected."""
        # Create a budget that's already exceeded
        mcp_session_dlp_budget_tracker.create_budget(
            proxy.session_id, proxy.agent_id, max_dlp_findings=0
        )
        from app.models.mcp_security import MCPDLPFinding

        mcp_session_dlp_budget_tracker.record_findings(
            proxy.session_id,
            [MCPDLPFinding(rule_id="DLP-001", severity="MEDIUM")],
        )

        body = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "test", "arguments": {}},
        }).encode()

        status, _, resp_body = await proxy.handle_request(body)
        assert status == 429
        resp = json.loads(resp_body)
        assert resp["error"]["code"] == -32001

        # Clean up
        mcp_session_dlp_budget_tracker.remove_budget(proxy.session_id)


class TestEventCollection:
    def test_no_events_initially(self, proxy):
        events = proxy.get_pending_events()
        assert len(events) == 0

    def test_events_cleared_after_get(self, proxy):
        # Internal method to create events
        from app.models.mcp_security import MCPSecurityEventType

        proxy._emit_event(
            MCPSecurityEventType.OUTBOUND_DLP_HIT,
            tool_name="test",
            severity="CRITICAL",
        )
        events = proxy.get_pending_events()
        assert len(events) == 1
        assert events[0].event_type == "OUTBOUND_DLP_HIT"

        # Second call should return empty
        events2 = proxy.get_pending_events()
        assert len(events2) == 0


class TestDLPBlockedResponse:
    def test_dlp_blocked_format(self, proxy):
        status, headers, body = proxy._dlp_blocked_response(42, "Test block")
        assert status == 403
        resp = json.loads(body)
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 42
        assert resp["error"]["code"] == -32001
        assert resp["error"]["data"]["decision"] == "BLOCK"

    def test_budget_exceeded_format(self, proxy):
        status, headers, body = proxy._budget_exceeded_response()
        assert status == 429
        resp = json.loads(body)
        assert resp["error"]["code"] == -32001
        assert "budget exceeded" in resp["error"]["message"].lower()
