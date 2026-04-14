"""Unit tests for Sprint 44 URLScanner 11-layer pipeline (APEP-349)."""

import socket
from unittest.mock import patch

import pytest

from app.services.url_scanner import URLScanner


def _fake_stripe_key() -> str:
    """Build a fake Stripe-like key at runtime to avoid secret scanning."""
    prefix = "".join(["s", "k"])
    return prefix + "_" + "live" + "_" + "X" * 24


class TestURLScanner:
    """Tests for the 11-layer URL scanner pipeline."""

    def setup_method(self):
        self.scanner = URLScanner()

    # ── Layer 1: Scheme validation ────────────────────────────────────

    def test_blocks_ftp_scheme(self):
        result = self.scanner.scan("ftp://attacker.com/exfil")
        assert result.blocked
        scheme_layer = next(
            (r for r in result.layer_results if r.layer_name == "scheme_validation"), None
        )
        assert scheme_layer is not None
        assert not scheme_layer.passed

    def test_blocks_file_scheme(self):
        result = self.scanner.scan("file:///etc/passwd")
        assert result.blocked

    def test_blocks_javascript_scheme(self):
        result = self.scanner.scan("javascript:alert(1)")
        assert result.blocked

    # ── Layer 2: URL parsing ──────────────────────────────────────────

    def test_blocks_empty_hostname(self):
        result = self.scanner.scan("http://")
        assert result.blocked

    # ── Layer 3: Domain blocklist ─────────────────────────────────────

    @patch("socket.getaddrinfo")
    def test_blocks_blocklisted_domain(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.2.3.4", 0))
        ]
        result = self.scanner.scan("http://evil.com/malware")
        assert result.blocked
        blocklist_layer = next(
            (r for r in result.layer_results if r.layer_name == "domain_blocklist"), None
        )
        assert blocklist_layer is not None
        assert not blocklist_layer.passed

    # ── Layer 4: SSRF guard ───────────────────────────────────────────

    @patch("socket.getaddrinfo")
    def test_blocks_private_ip(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))
        ]
        result = self.scanner.scan("http://internal.corp/api")
        assert result.blocked

    # ── Layer 6: DLP pattern matching ─────────────────────────────────

    @patch("socket.getaddrinfo")
    def test_detects_dlp_in_url(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
        ]
        url = "https://example.com/callback?api_key=" + _fake_stripe_key()
        result = self.scanner.scan(url)
        dlp_layer = next(
            (r for r in result.layer_results if r.layer_name == "dlp_pattern_matching"), None
        )
        assert dlp_layer is not None
        assert len(dlp_layer.findings) > 0

    # ── Layer 10: Path traversal ──────────────────────────────────────

    @patch("socket.getaddrinfo")
    def test_detects_path_traversal(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
        ]
        result = self.scanner.scan("https://example.com/../../../etc/passwd")
        traversal_layer = next(
            (r for r in result.layer_results if r.layer_name == "path_traversal"), None
        )
        assert traversal_layer is not None
        assert len(traversal_layer.findings) > 0

    @patch("socket.getaddrinfo")
    def test_detects_suspicious_extension(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
        ]
        result = self.scanner.scan("https://example.com/download/payload.exe")
        traversal_layer = next(
            (r for r in result.layer_results if r.layer_name == "path_traversal"), None
        )
        assert traversal_layer is not None
        assert len(traversal_layer.findings) > 0

    # ── Layer 11: Credential in URL ───────────────────────────────────

    @patch("socket.getaddrinfo")
    def test_detects_credential_in_url(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
        ]
        result = self.scanner.scan("https://admin:password123@example.com/api")
        cred_layer = next(
            (r for r in result.layer_results if r.layer_name == "credential_in_url"), None
        )
        assert cred_layer is not None
        assert len(cred_layer.findings) > 0

    @patch("socket.getaddrinfo")
    def test_detects_password_in_query(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
        ]
        result = self.scanner.scan("https://example.com/login?password=secret123")
        cred_layer = next(
            (r for r in result.layer_results if r.layer_name == "credential_in_url"), None
        )
        assert cred_layer is not None
        assert len(cred_layer.findings) > 0

    # ── Clean URL passes all layers ───────────────────────────────────

    @patch("socket.getaddrinfo")
    def test_clean_url_passes(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
        ]
        result = self.scanner.scan("https://example.com/page")
        assert result.allowed
        assert not result.blocked
        assert len(result.layer_results) == 11

    # ── Pipeline behaviour ────────────────────────────────────────────

    def test_short_circuits_on_blocking_layer(self):
        result = self.scanner.scan("ftp://attacker.com/exfil")
        assert result.blocked
        # Pipeline should stop after scheme_validation (layer 1)
        assert len(result.layer_results) == 1

    @patch("socket.getaddrinfo")
    def test_all_11_layers_run_for_clean_url(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
        ]
        result = self.scanner.scan("https://example.com/page")
        assert len(result.layer_results) == 11

    @patch("socket.getaddrinfo")
    def test_findings_accumulated_across_layers(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
        ]
        url = "https://admin:pass@example.com/../../download.exe?api_key=" + _fake_stripe_key()
        result = self.scanner.scan(url)
        assert len(result.findings) > 0

    def test_scan_quick_clean_url(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
            ]
            assert self.scanner.scan_quick("https://example.com") is True

    def test_scan_quick_bad_scheme(self):
        assert self.scanner.scan_quick("ftp://evil.com") is False

    # ── Total latency is recorded ─────────────────────────────────────

    @patch("socket.getaddrinfo")
    def test_latency_recorded(self, mock_dns):
        mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
        ]
        result = self.scanner.scan("https://example.com")
        assert result.total_latency_us >= 0
