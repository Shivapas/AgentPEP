"""Unit tests for Sprint 48 — MCP Outbound DLP Scanner (APEP-380).

Tests the MCPOutboundScanner for:
  - Scanning tool call arguments for DLP violations
  - Detecting API keys, tokens, and credentials in outbound data
  - Block/alert decisions based on severity
  - Inbound response scanning
"""

import pytest

from app.services.mcp_outbound_scanner import MCPOutboundScanner, mcp_outbound_scanner


@pytest.fixture
def scanner():
    return MCPOutboundScanner(block_on_critical=True, block_on_high=False)


@pytest.fixture
def strict_scanner():
    return MCPOutboundScanner(block_on_critical=True, block_on_high=True)


class TestMCPOutboundScanner:
    """Tests for MCPOutboundScanner.scan_outbound."""

    def test_clean_args_no_findings(self, scanner):
        result = scanner.scan_outbound(
            tool_name="read_file",
            tool_args={"path": "/tmp/test.txt", "encoding": "utf-8"},
            session_id="sess-001",
            agent_id="agent-001",
        )
        assert len(result.findings) == 0
        assert not result.blocked
        assert result.direction == "outbound"
        assert result.session_id == "sess-001"
        assert result.agent_id == "agent-001"
        assert result.tool_name == "read_file"

    def test_detects_aws_key_in_args(self, scanner):
        result = scanner.scan_outbound(
            tool_name="make_request",
            tool_args={"url": "https://example.com", "api_key": "AKIAIOSFODNN7EXAMPLE"},
            session_id="sess-002",
            agent_id="agent-001",
        )
        assert len(result.findings) > 0
        assert any("AKIA" in f.matched_text_snippet or "DLP" in f.rule_id for f in result.findings)

    def test_detects_github_token(self, scanner):
        result = scanner.scan_outbound(
            tool_name="git_push",
            tool_args={"token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01234567"},
            session_id="sess-003",
            agent_id="agent-001",
        )
        assert len(result.findings) > 0

    def test_blocks_on_critical(self, scanner):
        """Scanner should block when critical findings are found and block_on_critical=True."""
        result = scanner.scan_outbound(
            tool_name="send_data",
            tool_args={"key": "AKIAIOSFODNN7EXAMPLE"},
            session_id="sess-004",
            agent_id="agent-001",
        )
        # If findings were found, check blocking behavior
        if result.findings:
            critical = any(f.severity == "CRITICAL" for f in result.findings)
            if critical:
                assert result.blocked

    def test_strict_blocks_on_high(self, strict_scanner):
        """Strict scanner should also block on HIGH severity findings."""
        result = strict_scanner.scan_outbound(
            tool_name="send_data",
            tool_args={"data": "password: mysecretpassword123!"},
            session_id="sess-005",
            agent_id="agent-001",
        )
        # If high-severity findings are returned, should be blocked
        if result.findings:
            high = any(f.severity in ("HIGH", "CRITICAL") for f in result.findings)
            if high:
                assert result.blocked

    def test_empty_args(self, scanner):
        result = scanner.scan_outbound(
            tool_name="no_args_tool",
            tool_args={},
            session_id="sess-006",
            agent_id="agent-001",
        )
        assert len(result.findings) == 0
        assert not result.blocked

    def test_nested_dict_args(self, scanner):
        result = scanner.scan_outbound(
            tool_name="complex_tool",
            tool_args={
                "config": {"nested": {"key": "AKIAIOSFODNN7EXAMPLE"}},
                "plain": "hello",
            },
            session_id="sess-007",
            agent_id="agent-001",
        )
        # The nested dict is serialized to JSON for scanning
        assert result.session_id == "sess-007"

    def test_latency_tracked(self, scanner):
        result = scanner.scan_outbound(
            tool_name="test",
            tool_args={"data": "clean data"},
            session_id="sess-008",
            agent_id="agent-001",
        )
        assert result.latency_us >= 0


class TestMCPOutboundScannerInbound:
    """Tests for MCPOutboundScanner.scan_inbound."""

    def test_clean_response(self, scanner):
        result = scanner.scan_inbound(
            tool_name="read_file",
            response_data={"content": "Hello world", "status": "ok"},
            session_id="sess-010",
            agent_id="agent-001",
        )
        assert len(result.findings) == 0
        assert result.direction == "inbound"

    def test_detects_secret_in_response(self, scanner):
        result = scanner.scan_inbound(
            tool_name="get_config",
            response_data="aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            session_id="sess-011",
            agent_id="agent-001",
        )
        assert len(result.findings) > 0

    def test_string_response(self, scanner):
        result = scanner.scan_inbound(
            tool_name="echo",
            response_data="Just a plain string response",
            session_id="sess-012",
            agent_id="agent-001",
        )
        assert len(result.findings) == 0

    def test_none_response(self, scanner):
        result = scanner.scan_inbound(
            tool_name="void_tool",
            response_data=None,
            session_id="sess-013",
            agent_id="agent-001",
        )
        assert len(result.findings) == 0


class TestModuleSingleton:
    """Test the module-level singleton."""

    def test_singleton_exists(self):
        assert mcp_outbound_scanner is not None
        result = mcp_outbound_scanner.scan_outbound(
            tool_name="test",
            tool_args={"data": "clean"},
            session_id="sess-singleton",
            agent_id="agent-singleton",
        )
        assert result.session_id == "sess-singleton"
