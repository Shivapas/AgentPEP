"""Unit tests for Sprint 44 SSRFGuard (APEP-353)."""

import socket
from unittest.mock import patch

import pytest

from app.services.ssrf_guard import SSRFGuard


class TestSSRFGuard:
    """Tests for SSRF detection and prevention."""

    def setup_method(self):
        self.guard = SSRFGuard()

    def test_blocks_file_scheme(self):
        result = self.guard.check_url("file:///etc/passwd")
        assert result.blocked
        assert "Dangerous scheme" in result.reason

    def test_blocks_ftp_scheme(self):
        result = self.guard.check_url("ftp://attacker.com/exfil")
        assert result.blocked

    def test_blocks_gopher_scheme(self):
        result = self.guard.check_url("gopher://evil.com")
        assert result.blocked

    def test_blocks_javascript_scheme(self):
        result = self.guard.check_url("javascript:alert(1)")
        assert result.blocked

    def test_allows_http(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
            ]
            result = self.guard.check_url("http://example.com")
            assert not result.blocked

    def test_allows_https(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
            ]
            result = self.guard.check_url("https://example.com")
            assert not result.blocked

    def test_blocks_loopback(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 0))
            ]
            result = self.guard.check_url("http://localhost")
            assert result.blocked
            assert result.is_loopback

    def test_blocks_private_10_range(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))
            ]
            result = self.guard.check_url("http://internal.corp")
            assert result.blocked
            assert result.is_private

    def test_blocks_private_172_range(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("172.16.0.1", 0))
            ]
            result = self.guard.check_url("http://internal.corp")
            assert result.blocked
            assert result.is_private

    def test_blocks_private_192_range(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.1.1", 0))
            ]
            result = self.guard.check_url("http://router.local")
            assert result.blocked
            assert result.is_private

    def test_blocks_cloud_metadata(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 0))
            ]
            result = self.guard.check_url("http://169.254.169.254/latest/meta-data/")
            assert result.blocked
            assert "Cloud metadata" in result.reason

    def test_blocks_link_local(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.1.1", 0))
            ]
            result = self.guard.check_url("http://link-local.test")
            assert result.blocked
            assert result.is_link_local

    def test_blocks_dns_failure(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("DNS failed")):
            result = self.guard.check_url("http://nonexistent.example.test")
            assert result.blocked
            assert "DNS resolution failed" in result.reason

    def test_blocks_empty_hostname(self):
        result = self.guard.check_url("http://")
        assert result.blocked

    def test_allow_private_flag(self):
        guard = SSRFGuard(allow_private=True)
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0))
            ]
            result = guard.check_url("http://internal.corp")
            assert not result.blocked

    def test_allowlisted_hosts(self):
        guard = SSRFGuard(allowed_hosts={"trusted.internal"})
        result = guard.check_url("http://trusted.internal/api")
        assert not result.blocked

    def test_scan_returns_findings(self):
        result = self.guard.scan("file:///etc/passwd")
        assert len(result) == 1
        assert result[0].rule_id == "SSRF-001"
        assert result[0].severity == "CRITICAL"

    def test_scan_clean_url(self):
        with patch("socket.getaddrinfo") as mock_dns:
            mock_dns.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))
            ]
            result = self.guard.scan("https://example.com")
            assert len(result) == 0
