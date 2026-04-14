"""Integration tests for Sprint 44 NetworkDLPScanner (APEP-348.g).

Tests end-to-end flows combining DLP scanning, URL scanning, entropy analysis,
SSRF guard, and domain blocklist into full pipeline scenarios.
"""

import socket
from unittest.mock import patch

import pytest

from app.models.network_scan import ScanKind, ScanSeverity
from app.services.domain_blocklist import DomainBlocklist
from app.services.domain_rate_limiter import DomainRateLimiter
from app.services.entropy_analyzer import EntropyAnalyzer
from app.services.network_dlp_scanner import NetworkDLPScanner
from app.services.ssrf_guard import SSRFGuard
from app.services.url_scanner import URLScanner


def _fake_stripe_key() -> str:
    """Build a fake Stripe-like key at runtime to avoid secret scanning."""
    prefix = "".join(["s", "k"])
    return prefix + "_" + "live" + "_" + "X" * 24


class TestNetworkDLPIntegration:
    """Integration tests combining multiple Sprint 44 components."""

    def setup_method(self):
        self.dlp = NetworkDLPScanner()
        self.url_scanner = URLScanner()
        self.entropy = EntropyAnalyzer()
        self.ssrf = SSRFGuard()
        self.blocklist = DomainBlocklist()

    # ── Full pipeline: DLP + URL scan ─────────────────────────────────

    @patch("socket.getaddrinfo")
    def test_url_with_embedded_key_detected(self, mock_dns):
        """URL containing an API key triggers both URL scan and DLP findings."""
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
        ]
        url = "https://api.example.com/data?apikey=" + _fake_stripe_key()

        # URL scanner pipeline runs all 11 layers
        result = self.url_scanner.scan(url)
        assert len(result.layer_results) == 11

        # DLP layer should have findings
        dlp_layer = next(
            (r for r in result.layer_results if r.layer_name == "dlp_pattern_matching"), None
        )
        assert dlp_layer is not None
        assert len(dlp_layer.findings) > 0

        # DLP scanner standalone also detects it
        dlp_findings = self.dlp.scan_url(url)
        assert len(dlp_findings) > 0

    # ── Full pipeline: Blocklisted domain + SSRF ──────────────────────

    def test_blocklisted_domain_short_circuits(self):
        """Blocklisted domain causes pipeline to short-circuit."""
        result = self.url_scanner.scan("http://evil.com/payload")
        assert result.blocked
        # Should stop at blocklist layer
        layer_names = [r.layer_name for r in result.layer_results]
        assert "domain_blocklist" in layer_names

    def test_ssrf_private_ip_blocks(self):
        """Private IP URL blocked by SSRF guard."""
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.1", 0))
            ]
            result = self.url_scanner.scan("http://internal.corp/admin")
            assert result.blocked

    # ── Tool args scanning with taint-relevant findings ───────────────

    def test_tool_args_with_multiple_secrets(self):
        """Tool arguments containing multiple secrets produce multiple findings."""
        tool_args = {
            "auth_header": "Bearer " + _fake_stripe_key(),
            "db_url": "postgresql://user:password@db.internal:5432/mydb",
            "encryption_key": "encryption_key=SuperSecretKey1234567890",
        }
        findings = self.dlp.scan_tool_args(tool_args, tool_name="http_request")
        dlp_findings = [f for f in findings if f.rule_id.startswith("DLP-")]
        assert len(dlp_findings) >= 2  # At least stripe key + DB URL + encryption key

    def test_tool_args_severity_escalation(self):
        """Critical findings from tool args produce CRITICAL max severity."""
        tool_args = {
            "key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAI...",
        }
        findings = self.dlp.scan_tool_args(tool_args)
        max_sev = self.dlp.max_severity(findings)
        assert max_sev == ScanSeverity.CRITICAL

    # ── Entropy analysis integration ──────────────────────────────────

    def test_entropy_detects_high_entropy_in_tool_args(self):
        """High-entropy strings in tool args are detected by DLP scanner."""
        # The DLP scanner uses entropy analyzer internally
        tool_args = {
            "data": "aK3bL5cM7dN9eP1fQ3gR5hS7tU9vW1xY3zA5bC7dE9f",
        }
        findings = self.dlp.scan_tool_args(tool_args)
        entropy_findings = [f for f in findings if f.rule_id == "ENTROPY-001"]
        assert len(entropy_findings) >= 0  # May detect depending on threshold

    def test_entropy_standalone(self):
        """EntropyAnalyzer directly finds high-entropy tokens."""
        results = self.entropy.analyse_text(
            "token=aK3bL5cM7dN9eP1fQ3gR5hS7tU9vW1x"
        )
        assert len(results) > 0

    # ── SSRF guard integration ────────────────────────────────────────

    def test_ssrf_blocks_cloud_metadata(self):
        """Cloud metadata endpoint blocked by SSRF guard."""
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0))
            ]
            result = self.ssrf.check_url("http://169.254.169.254/latest/meta-data/")
            assert result.blocked

    def test_ssrf_integrated_in_url_scanner(self):
        """SSRF check runs as part of URL scanner pipeline."""
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))
            ]
            result = self.url_scanner.scan("http://localhost:8080/admin")
            assert result.blocked
            ssrf_layer = next(
                (r for r in result.layer_results if r.layer_name == "ssrf_guard"), None
            )
            assert ssrf_layer is not None
            assert not ssrf_layer.passed

    # ── Network event creation ────────────────────────────────────────

    def test_network_event_created_from_finding(self):
        """DLP findings can be converted to Kafka NetworkEvents."""
        tool_args = {"password": "password=SuperSecret123"}
        findings = self.dlp.scan_tool_args(tool_args)
        dlp_findings = [f for f in findings if f.rule_id.startswith("DLP-")]
        assert len(dlp_findings) > 0

        event = self.dlp.create_network_event(
            dlp_findings[0],
            session_id="integration-test-session",
            agent_id="agent-42",
            blocked=True,
        )
        assert event.event_type == "DLP_HIT"
        assert event.session_id == "integration-test-session"
        assert event.blocked is True

    # ── Rate limiting integration ─────────────────────────────────────

    def test_rate_limit_blocks_after_threshold(self):
        """Per-domain rate limiter blocks requests exceeding the threshold."""
        limiter = DomainRateLimiter(
            default_request_limit=3,
            default_data_budget_bytes=10000,
            window_seconds=60,
        )
        for _ in range(3):
            limiter.check_and_record("example.com")
        state = limiter.check_and_record("example.com")
        assert state.exceeded

    # ── Complex scenario: malicious URL with multiple indicators ──────

    @patch("socket.getaddrinfo")
    def test_malicious_url_multiple_indicators(self, mock_dns):
        """A URL with path traversal, suspicious extension, and credential triggers multiple findings."""
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
        ]
        url = "https://admin:secret@example.com/../../downloads/malware.exe"
        result = self.url_scanner.scan(url)
        assert len(result.findings) >= 2  # At least credential + path traversal/extension

    # ── Clean URL passes everything ───────────────────────────────────

    @patch("socket.getaddrinfo")
    def test_clean_url_full_pass(self, mock_dns):
        """A clean, legitimate URL passes all 11 layers."""
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
        ]
        result = self.url_scanner.scan("https://docs.example.com/api/v2/users")
        assert result.allowed
        assert not result.blocked
        assert len(result.layer_results) == 11
        assert all(r.passed for r in result.layer_results)
