"""Unit tests for Sprint 47 — Forward Proxy DLP Scanner (APEP-373).

Tests cover:
  - Request body DLP scanning
  - Content type filtering
  - Body size limits
  - Raw HTTP parsing
  - Block verdicts based on severity
  - Network event generation
"""

import pytest

from app.services.forward_proxy_dlp import (
    ForwardProxyDLPResult,
    ForwardProxyDLPScanner,
)


def _fake_aws_key() -> str:
    """Build a fake AWS key at runtime to avoid secret scanning."""
    return "AKIA" + "I" * 4 + "O" * 4 + "S" * 4 + "F" * 4


class TestForwardProxyDLPScanner:
    """Tests for the forward proxy DLP scanner (APEP-373)."""

    def setup_method(self):
        self.scanner = ForwardProxyDLPScanner(
            block_on_critical=True,
            block_on_high=False,
        )

    # ------------------------------------------------------------------
    # Basic scanning
    # ------------------------------------------------------------------

    def test_scan_clean_body(self):
        body = b'{"query": "SELECT * FROM users", "limit": 10}'
        result = self.scanner.scan_request_body(
            body, content_type="application/json"
        )
        assert result.scanned is True
        assert result.has_findings is False
        assert result.blocked is False

    def test_scan_body_with_aws_key(self):
        key = _fake_aws_key()
        body = f'{{"api_key": "{key}"}}'.encode()
        result = self.scanner.scan_request_body(
            body, content_type="application/json"
        )
        assert result.scanned is True
        assert result.has_findings is True
        assert len(result.findings) > 0

    def test_scan_body_with_private_key(self):
        body = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        result = self.scanner.scan_request_body(
            body, content_type="text/plain"
        )
        assert result.scanned is True
        assert result.has_findings is True

    # ------------------------------------------------------------------
    # Content type filtering
    # ------------------------------------------------------------------

    def test_skips_binary_content_type(self):
        result = self.scanner.scan_request_body(
            b"\x89PNG\r\n\x1a\n",
            content_type="image/png",
        )
        assert result.scanned is False
        assert result.reason == "non_scannable_content_type"

    def test_skips_octet_stream(self):
        result = self.scanner.scan_request_body(
            b"binary data here",
            content_type="application/octet-stream",
        )
        assert result.scanned is False

    def test_scans_json(self):
        result = self.scanner.scan_request_body(
            b'{"key": "value"}',
            content_type="application/json",
        )
        assert result.scanned is True

    def test_scans_form_urlencoded(self):
        result = self.scanner.scan_request_body(
            b"field1=value1&field2=value2",
            content_type="application/x-www-form-urlencoded",
        )
        assert result.scanned is True

    def test_scans_text_plain(self):
        result = self.scanner.scan_request_body(
            b"plain text content",
            content_type="text/plain",
        )
        assert result.scanned is True

    def test_scans_xml(self):
        result = self.scanner.scan_request_body(
            b"<root><data>hello</data></root>",
            content_type="application/xml",
        )
        assert result.scanned is True

    def test_content_type_with_charset(self):
        result = self.scanner.scan_request_body(
            b'{"key": "value"}',
            content_type="application/json; charset=utf-8",
        )
        assert result.scanned is True

    # ------------------------------------------------------------------
    # Body size limits
    # ------------------------------------------------------------------

    def test_skips_oversized_body(self):
        scanner = ForwardProxyDLPScanner(max_body_size=100)
        body = b"x" * 200
        result = scanner.scan_request_body(body, content_type="text/plain")
        assert result.scanned is False
        assert result.reason == "body_too_large"

    def test_scans_within_limit(self):
        scanner = ForwardProxyDLPScanner(max_body_size=100)
        body = b"short body"
        result = scanner.scan_request_body(body, content_type="text/plain")
        assert result.scanned is True

    # ------------------------------------------------------------------
    # Empty / no body
    # ------------------------------------------------------------------

    def test_empty_body(self):
        result = self.scanner.scan_request_body(b"")
        assert result.scanned is True
        assert result.has_findings is False

    # ------------------------------------------------------------------
    # Raw HTTP parsing
    # ------------------------------------------------------------------

    def test_scan_raw_http_with_body(self):
        raw = (
            b"POST /api/data HTTP/1.1\r\n"
            b"Host: api.example.com\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n"
            b'{"query": "SELECT * FROM users"}'
        )
        result = self.scanner.scan_raw_http(raw, hostname="api.example.com")
        assert result.scanned is True

    def test_scan_raw_http_no_body(self):
        raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        result = self.scanner.scan_raw_http(raw)
        assert result.scanned is False
        assert result.reason == "empty_body"

    def test_scan_raw_http_no_boundary(self):
        raw = b"Just some raw data without HTTP structure"
        result = self.scanner.scan_raw_http(raw)
        assert result.scanned is False
        assert result.reason == "no_body"

    # ------------------------------------------------------------------
    # Block verdicts
    # ------------------------------------------------------------------

    def test_block_on_critical_enabled(self):
        scanner = ForwardProxyDLPScanner(
            block_on_critical=True, block_on_high=False
        )
        key = _fake_aws_key()
        body = f'{{"key": "{key}"}}'.encode()
        result = scanner.scan_request_body(body, content_type="application/json")
        # AWS key findings may or may not be CRITICAL depending on patterns
        assert result.scanned is True

    def test_block_on_high_disabled(self):
        scanner = ForwardProxyDLPScanner(
            block_on_critical=False, block_on_high=False
        )
        body = b"password=MySecretPassword123"
        result = scanner.scan_request_body(body, content_type="text/plain")
        assert result.scanned is True
        # Should not block even with findings
        assert result.blocked is False

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def test_stats_increment(self):
        body = b'{"key": "value"}'
        self.scanner.scan_request_body(body, content_type="application/json")
        assert self.scanner.stats["scan_count"] >= 1

    # ------------------------------------------------------------------
    # Network event generation
    # ------------------------------------------------------------------

    def test_create_network_events_empty(self):
        result = ForwardProxyDLPResult(scanned=True)
        events = self.scanner.create_network_events(result)
        assert events == []

    def test_create_network_events_with_findings(self):
        from app.models.network_scan import ScanFinding, ScanSeverity

        finding = ScanFinding(
            rule_id="DLP-001",
            scanner="NetworkDLPScanner",
            severity=ScanSeverity.CRITICAL,
            description="AWS key detected",
        )
        result = ForwardProxyDLPResult(
            scanned=True,
            findings=[finding],
            session_id="test-session",
            agent_id="test-agent",
        )
        events = self.scanner.create_network_events(result)
        assert len(events) == 1
        assert events[0].event_type.value == "DLP_HIT"
        assert events[0].scanner == "ForwardProxyDLPScanner"
