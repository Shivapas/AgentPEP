"""Unit tests for Sprint 47 — WebSocket Proxy (APEP-377).

Tests cover:
  - Target URL validation
  - Session lifecycle management
  - Connection limit enforcement
  - Hostname blocking integration
  - Statistics tracking
"""

import pytest

from app.models.forward_proxy import (
    WebSocketProxyConfig,
    WebSocketProxyRequest,
    WebSocketProxyState,
)
from app.services.websocket_proxy import WebSocketProxy


class TestWebSocketProxy:
    """Tests for the WebSocket proxy service (APEP-377)."""

    def setup_method(self):
        self.config = WebSocketProxyConfig(
            max_connections=5,
            max_frame_size=1024,
        )
        self.proxy = WebSocketProxy(config=self.config)

    # ------------------------------------------------------------------
    # Target URL validation
    # ------------------------------------------------------------------

    def test_validate_ws_url(self):
        is_valid, error = self.proxy.validate_target("ws://echo.websocket.org")
        assert is_valid is True
        assert error == ""

    def test_validate_wss_url(self):
        is_valid, error = self.proxy.validate_target("wss://echo.websocket.org")
        assert is_valid is True

    def test_reject_http_url(self):
        is_valid, error = self.proxy.validate_target("http://example.com")
        assert is_valid is False
        assert "scheme" in error.lower()

    def test_reject_https_url(self):
        is_valid, error = self.proxy.validate_target("https://example.com")
        assert is_valid is False

    def test_reject_empty_hostname(self):
        is_valid, error = self.proxy.validate_target("ws://")
        assert is_valid is False

    def test_reject_ftp_url(self):
        is_valid, error = self.proxy.validate_target("ftp://files.example.com")
        assert is_valid is False

    # ------------------------------------------------------------------
    # Hostname blocking integration
    # ------------------------------------------------------------------

    def test_validate_blocked_hostname(self):
        class FakeChecker:
            def is_blocked(self, hostname):
                return hostname == "evil.com", "Blocked domain"

        self.proxy.set_hostname_checker(FakeChecker())

        is_valid, error = self.proxy.validate_target("ws://evil.com/ws")
        assert is_valid is False
        assert "blocked" in error.lower()

        is_valid, error = self.proxy.validate_target("ws://good.com/ws")
        assert is_valid is True

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_create_session(self):
        request = WebSocketProxyRequest(
            target_url="wss://echo.websocket.org",
            session_id="test-session",
            agent_id="test-agent",
        )
        session = await self.proxy.create_session(request)
        assert session.target_url == "wss://echo.websocket.org"
        assert session.state == WebSocketProxyState.CONNECTING
        assert session.session_id == "test-session"
        assert session.agent_id == "test-agent"

    @pytest.mark.asyncio
    async def test_max_connections_enforced(self):
        for i in range(5):
            request = WebSocketProxyRequest(target_url=f"wss://host{i}.com/ws")
            await self.proxy.create_session(request)

        with pytest.raises(ValueError, match="Maximum"):
            request = WebSocketProxyRequest(target_url="wss://extra.com/ws")
            await self.proxy.create_session(request)

    @pytest.mark.asyncio
    async def test_close_session(self):
        request = WebSocketProxyRequest(target_url="wss://echo.websocket.org")
        session = await self.proxy.create_session(request)
        ws_id = str(session.ws_session_id)

        await self.proxy.close_session(ws_id)

        # Session should be removed
        sessions = self.proxy.get_sessions()
        assert all(str(s.ws_session_id) != ws_id for s in sessions)

    @pytest.mark.asyncio
    async def test_close_nonexistent_session(self):
        # Should not raise
        await self.proxy.close_session("nonexistent-id")

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def test_initial_stats(self):
        stats = self.proxy.get_stats()
        assert stats.active_connections == 0
        assert stats.total_connections == 0
        assert stats.total_frames_scanned == 0

    @pytest.mark.asyncio
    async def test_stats_after_session_create(self):
        request = WebSocketProxyRequest(target_url="wss://echo.websocket.org")
        await self.proxy.create_session(request)

        stats = self.proxy.get_stats()
        assert stats.total_connections == 1
        assert stats.active_connections == 1

    @pytest.mark.asyncio
    async def test_stats_after_session_close(self):
        request = WebSocketProxyRequest(target_url="wss://echo.websocket.org")
        session = await self.proxy.create_session(request)
        ws_id = str(session.ws_session_id)

        await self.proxy.close_session(ws_id)

        stats = self.proxy.get_stats()
        assert stats.total_connections == 1
        assert stats.active_connections == 0

    # ------------------------------------------------------------------
    # Session listing
    # ------------------------------------------------------------------

    @pytest.mark.asyncio
    async def test_get_sessions(self):
        for i in range(3):
            request = WebSocketProxyRequest(target_url=f"wss://host{i}.com/ws")
            await self.proxy.create_session(request)

        sessions = self.proxy.get_sessions()
        assert len(sessions) == 3

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def test_default_config(self):
        proxy = WebSocketProxy()
        assert proxy.config.max_connections == 500
        assert proxy.config.max_frame_size == 1_048_576
        assert proxy.config.enable_dlp_scan is True
        assert proxy.config.enable_injection_scan is True
