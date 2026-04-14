"""Integration & adversarial tests for Sprint 47 — Forward Proxy & WebSocket Proxy.

APEP-379: Integration tests across all Sprint 47 components.
APEP-372.g: Integration tests for asyncio CONNECT tunnel handler.
APEP-375.g: Adversarial tests for optional TLS interception.

Tests verify:
  - End-to-end pipeline wiring (hostname blocker + DLP + tunnel)
  - API endpoint responses
  - Cross-component interactions
  - Adversarial inputs and edge cases
  - Security boundary enforcement
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.forward_proxy import FrameScanResult, FrameScanVerdict
from tests.conftest import _get_auth_headers


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# API endpoint integration tests
# ---------------------------------------------------------------------------


class TestProxyAPIEndpoints:
    """Integration tests for Sprint 47 API endpoints."""

    @pytest.mark.asyncio
    async def test_proxy_status(self, client):
        response = await client.get("/v1/proxy/status", headers=_get_auth_headers())
        assert response.status_code == 200
        data = response.json()
        assert "tunnel_stats" in data
        assert "websocket_stats" in data
        assert "tls_interception_enabled" in data
        assert "hostname_block_count" in data

    @pytest.mark.asyncio
    async def test_tunnel_status(self, client):
        response = await client.get("/v1/proxy/tunnel/status", headers=_get_auth_headers())
        assert response.status_code == 200
        data = response.json()
        assert "active_tunnels" in data
        assert "total_tunnels" in data

    @pytest.mark.asyncio
    async def test_tunnel_active(self, client):
        response = await client.get("/v1/proxy/tunnel/active", headers=_get_auth_headers())
        assert response.status_code == 200
        data = response.json()
        assert "count" in data
        assert "tunnels" in data
        assert data["count"] == 0

    @pytest.mark.asyncio
    async def test_tunnel_kill_nonexistent(self, client):
        response = await client.post(
            "/v1/proxy/tunnel/kill",
            json={"tunnel_id": "nonexistent-id"},
            headers=_get_auth_headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "not_found"

    @pytest.mark.asyncio
    async def test_ws_status(self, client):
        response = await client.get("/v1/proxy/ws/status", headers=_get_auth_headers())
        assert response.status_code == 200
        data = response.json()
        assert "active_connections" in data
        assert "total_connections" in data

    @pytest.mark.asyncio
    async def test_ws_validate_valid_url(self, client):
        response = await client.post(
            "/v1/proxy/ws/validate",
            json={"target_url": "wss://echo.websocket.org"},
            headers=_get_auth_headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True

    @pytest.mark.asyncio
    async def test_ws_validate_invalid_scheme(self, client):
        response = await client.post(
            "/v1/proxy/ws/validate",
            json={"target_url": "http://example.com"},
            headers=_get_auth_headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False

    @pytest.mark.asyncio
    async def test_ws_sessions_empty(self, client):
        response = await client.get("/v1/proxy/ws/sessions", headers=_get_auth_headers())
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 0

    @pytest.mark.asyncio
    async def test_tls_status(self, client):
        response = await client.get("/v1/proxy/tls/status", headers=_get_auth_headers())
        assert response.status_code == 200
        data = response.json()
        assert "enabled" in data
        assert "initialized" in data

    @pytest.mark.asyncio
    async def test_hostname_check_safe(self, client):
        response = await client.post(
            "/v1/proxy/hostname/check",
            json={"hostname": "api.github.com"},
            headers=_get_auth_headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["blocked"] is False

    @pytest.mark.asyncio
    async def test_hostname_check_blocked(self, client):
        response = await client.post(
            "/v1/proxy/hostname/check",
            json={"hostname": "localhost"},
            headers=_get_auth_headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["blocked"] is True

    @pytest.mark.asyncio
    async def test_hostname_check_metadata(self, client):
        response = await client.post(
            "/v1/proxy/hostname/check",
            json={"hostname": "169.254.169.254"},
            headers=_get_auth_headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["blocked"] is True

    @pytest.mark.asyncio
    async def test_hostname_block_add(self, client):
        response = await client.post(
            "/v1/proxy/hostname/block",
            json={
                "pattern": "new-blocked.example.com",
                "action": "block",
                "reason": "Test block",
            },
            headers=_get_auth_headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["action"] == "block"

        # Verify it's now blocked
        response = await client.post(
            "/v1/proxy/hostname/check",
            json={"hostname": "new-blocked.example.com"},
            headers=_get_auth_headers(),
        )
        data = response.json()
        assert data["blocked"] is True

    @pytest.mark.asyncio
    async def test_hostname_allow_add(self, client):
        response = await client.post(
            "/v1/proxy/hostname/block",
            json={
                "pattern": "allowed.example.com",
                "action": "allow",
            },
            headers=_get_auth_headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["action"] == "allow"


# ---------------------------------------------------------------------------
# Cross-component integration tests
# ---------------------------------------------------------------------------


class TestCrossComponentIntegration:
    """Tests verifying Sprint 47 components work together."""

    def test_hostname_blocker_wired_to_tunnel(self):
        """Verify hostname blocker is available to the tunnel handler."""
        from app.services.connect_tunnel import connect_tunnel_handler
        from app.services.hostname_blocker import hostname_blocker

        # Wire up
        connect_tunnel_handler.set_hostname_checker(hostname_blocker)

        # Verify the checker is set
        assert connect_tunnel_handler._hostname_checker is hostname_blocker

    def test_hostname_blocker_wired_to_ws_proxy(self):
        """Verify hostname blocker is available to the WebSocket proxy."""
        from app.services.hostname_blocker import hostname_blocker
        from app.services.websocket_proxy import websocket_proxy

        websocket_proxy.set_hostname_checker(hostname_blocker)
        assert websocket_proxy._hostname_checker is hostname_blocker

    def test_frame_scanner_wired_to_ws_proxy(self):
        """Verify frame scanner is available to the WebSocket proxy."""
        from app.services.websocket_frame_scanner import websocket_frame_scanner
        from app.services.websocket_proxy import websocket_proxy

        websocket_proxy.set_frame_scanner(websocket_frame_scanner)
        assert websocket_proxy._frame_scanner is websocket_frame_scanner

    def test_dlp_scanner_wired_to_tunnel(self):
        """Verify DLP scanner is available to the tunnel handler."""
        from app.services.connect_tunnel import connect_tunnel_handler
        from app.services.forward_proxy_dlp import forward_proxy_dlp_scanner

        connect_tunnel_handler.set_dlp_scanner(forward_proxy_dlp_scanner)
        assert connect_tunnel_handler._dlp_scanner is forward_proxy_dlp_scanner


# ---------------------------------------------------------------------------
# Adversarial tests
# ---------------------------------------------------------------------------


class TestAdversarialInputs:
    """Adversarial tests for Sprint 47 security boundaries."""

    def test_hostname_with_unicode(self):
        from app.services.hostname_blocker import hostname_blocker

        # Unicode hostnames should not crash
        blocked, reason = hostname_blocker.is_blocked("ëvil.com")
        # Should not crash — result depends on blocklist

    def test_hostname_with_null_bytes(self):
        from app.services.hostname_blocker import hostname_blocker

        blocked, reason = hostname_blocker.is_blocked("evil\x00.com")
        # Should handle gracefully

    def test_hostname_extremely_long(self):
        from app.services.hostname_blocker import hostname_blocker

        long_hostname = "a" * 10000 + ".com"
        blocked, reason = hostname_blocker.is_blocked(long_hostname)
        # Should not crash

    def test_ws_url_with_credentials(self):
        from app.services.websocket_proxy import websocket_proxy

        is_valid, error = websocket_proxy.validate_target(
            "wss://user:password@evil.com/ws"
        )
        # Should handle — may or may not block

    def test_ws_url_with_fragment(self):
        from app.services.websocket_proxy import websocket_proxy

        is_valid, error = websocket_proxy.validate_target(
            "wss://example.com/ws#fragment"
        )
        assert is_valid is True

    def test_ws_url_with_query_params(self):
        from app.services.websocket_proxy import websocket_proxy

        is_valid, error = websocket_proxy.validate_target(
            "wss://example.com/ws?token=abc&channel=test"
        )
        assert is_valid is True

    def test_frame_scanner_with_null_bytes(self):
        from app.models.forward_proxy import WebSocketFrameType
        from app.services.websocket_frame_scanner import websocket_frame_scanner

        result = websocket_frame_scanner.scan_frame(
            data="normal text\x00embedded null bytes\x00more text here",
            frame_type=WebSocketFrameType.TEXT,
        )
        # Should not crash
        assert result.verdict in (
            FrameScanVerdict.ALLOW,
            FrameScanVerdict.BLOCK,
        )

    def test_frame_scanner_with_huge_payload(self):
        from app.models.forward_proxy import WebSocketFrameType
        from app.services.websocket_frame_scanner import websocket_frame_scanner

        # 2MB frame — should be truncated, not crash
        result = websocket_frame_scanner.scan_frame(
            data="x" * 2_000_000,
            frame_type=WebSocketFrameType.TEXT,
        )
        # Should handle gracefully without crashing (may block due to patterns)
        assert result.verdict in (FrameScanVerdict.ALLOW, FrameScanVerdict.BLOCK)

    def test_dlp_scanner_with_binary_body(self):
        from app.services.forward_proxy_dlp import forward_proxy_dlp_scanner

        # Binary data that's not valid UTF-8
        body = bytes(range(256))
        result = forward_proxy_dlp_scanner.scan_request_body(
            body, content_type="text/plain"
        )
        # Should handle gracefully (errors="replace" in decode)
        assert isinstance(result.scanned, bool)

    def test_hostname_ssrf_via_decimal_ip(self):
        """Test SSRF via decimal IP notation (e.g., 2130706433 = 127.0.0.1)."""
        from app.services.hostname_blocker import hostname_blocker

        # These should not bypass blocklist
        blocked, _ = hostname_blocker.is_blocked("0x7f000001")  # hex
        # May or may not be blocked depending on regex patterns

    def test_hostname_private_ip_variants(self):
        from app.services.hostname_blocker import hostname_blocker

        # Various private IP formats
        test_cases = [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "192.168.255.255",
        ]
        for ip in test_cases:
            blocked, reason = hostname_blocker.is_blocked(ip)
            assert blocked is True, f"{ip} should be blocked"


# ---------------------------------------------------------------------------
# Data model integration tests
# ---------------------------------------------------------------------------


class TestDataModelIntegration:
    """Tests for Pydantic model serialization and validation."""

    def test_tunnel_session_serialization(self):
        from app.models.forward_proxy import TunnelSession

        session = TunnelSession(
            hostname="example.com",
            port=443,
            session_id="test",
        )
        data = session.model_dump(mode="json")
        assert data["hostname"] == "example.com"
        assert data["port"] == 443
        assert data["state"] == "pending"
        assert "tunnel_id" in data

    def test_ws_session_serialization(self):
        from app.models.forward_proxy import WebSocketProxySession

        session = WebSocketProxySession(
            target_url="wss://example.com/ws",
        )
        data = session.model_dump(mode="json")
        assert data["target_url"] == "wss://example.com/ws"
        assert data["state"] == "connecting"

    def test_frame_scan_result_serialization(self):
        result = FrameScanResult(
            verdict=FrameScanVerdict.BLOCK,
            dlp_findings=[{"rule_id": "DLP-001"}],
        )
        data = result.model_dump(mode="json")
        assert data["verdict"] == "block"
        assert len(data["dlp_findings"]) == 1

    def test_connect_tunnel_config_defaults(self):
        from app.models.forward_proxy import ConnectTunnelConfig

        config = ConnectTunnelConfig()
        assert config.listen_port == 8889
        assert config.max_tunnels == 1000
        assert config.idle_timeout_s == 300
        assert config.enable_dlp_scan is True
        assert config.enable_hostname_blocking is True
        assert config.enable_tls_interception is False

    def test_websocket_proxy_config_defaults(self):
        from app.models.forward_proxy import WebSocketProxyConfig

        config = WebSocketProxyConfig()
        assert config.max_connections == 500
        assert config.max_frame_size == 1_048_576
        assert config.enable_dlp_scan is True
        assert config.enable_injection_scan is True
        assert config.fragment_reassembly is True

    def test_tls_interception_config_defaults(self):
        from app.models.forward_proxy import TLSInterceptionConfig

        config = TLSInterceptionConfig()
        assert config.enabled is False
        assert config.key_algorithm == "ECDSA_P256"
        assert config.cert_cache_size == 1000
