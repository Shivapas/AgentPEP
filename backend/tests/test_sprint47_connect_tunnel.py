"""Unit tests for Sprint 47 — CONNECT Tunnel Handler (APEP-372).

Tests cover:
  - CONNECT request parsing
  - Hostname blocking integration (APEP-374)
  - Tunnel session management
  - Port validation
  - Error handling
  - Statistics tracking
"""

import asyncio
import pytest

from app.models.forward_proxy import (
    ConnectTunnelConfig,
    TunnelCloseReason,
    TunnelState,
)
from app.services.connect_tunnel import ConnectTunnelHandler


class TestConnectTunnelHandler:
    """Tests for the CONNECT tunnel handler (APEP-372)."""

    def setup_method(self):
        self.config = ConnectTunnelConfig(
            listen_port=0,  # ephemeral port for tests
            max_tunnels=5,
            idle_timeout_s=10,
            allowed_ports=[443, 8443],
            enable_hostname_blocking=True,
            enable_dlp_scan=False,
        )
        self.handler = ConnectTunnelHandler(config=self.config)

    def test_default_config(self):
        handler = ConnectTunnelHandler()
        assert handler.config.listen_port == 8889
        assert handler.config.max_tunnels == 1000
        assert 443 in handler.config.allowed_ports

    def test_custom_config(self):
        assert self.handler.config.listen_port == 0
        assert self.handler.config.max_tunnels == 5
        assert self.handler.config.enable_hostname_blocking is True

    def test_initial_stats(self):
        stats = self.handler.get_stats()
        assert stats.active_tunnels == 0
        assert stats.total_tunnels == 0
        assert stats.total_bytes_transferred == 0
        assert stats.blocked_count == 0

    def test_no_active_tunnels_initially(self):
        tunnels = self.handler.get_active_tunnels()
        assert tunnels == []

    @pytest.mark.asyncio
    async def test_kill_nonexistent_tunnel(self):
        killed = await self.handler.kill_tunnel("nonexistent-id")
        assert killed is False

    def test_set_hostname_checker(self):
        class FakeChecker:
            def is_blocked(self, hostname):
                return hostname == "evil.com", "blocked"

        checker = FakeChecker()
        self.handler.set_hostname_checker(checker)
        assert self.handler._hostname_checker is checker

    def test_set_dlp_scanner(self):
        class FakeScanner:
            pass

        scanner = FakeScanner()
        self.handler.set_dlp_scanner(scanner)
        assert self.handler._dlp_scanner is scanner

    def test_set_kafka_producer(self):
        class FakeProducer:
            pass

        producer = FakeProducer()
        self.handler.set_kafka_producer(producer)
        assert self.handler._kafka_producer is producer


class TestConnectRequestParsing:
    """Tests for CONNECT request line parsing."""

    def setup_method(self):
        self.handler = ConnectTunnelHandler()

    @pytest.mark.asyncio
    async def test_parse_valid_connect(self):
        # Simulate a CONNECT request with StreamReader
        data = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        request = await self.handler._read_connect_request(reader)
        assert request is not None
        assert request.hostname == "example.com"
        assert request.port == 443

    @pytest.mark.asyncio
    async def test_parse_connect_custom_port(self):
        data = b"CONNECT api.example.com:8443 HTTP/1.1\r\n\r\n"
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        request = await self.handler._read_connect_request(reader)
        assert request is not None
        assert request.hostname == "api.example.com"
        assert request.port == 8443

    @pytest.mark.asyncio
    async def test_parse_connect_no_port(self):
        data = b"CONNECT example.com HTTP/1.1\r\n\r\n"
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        request = await self.handler._read_connect_request(reader)
        assert request is not None
        assert request.hostname == "example.com"
        assert request.port == 443  # default

    @pytest.mark.asyncio
    async def test_parse_non_connect_request(self):
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        request = await self.handler._read_connect_request(reader)
        assert request is None

    @pytest.mark.asyncio
    async def test_parse_empty_request(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"")
        reader.feed_eof()

        request = await self.handler._read_connect_request(reader)
        assert request is None

    @pytest.mark.asyncio
    async def test_parse_invalid_port(self):
        data = b"CONNECT example.com:abc HTTP/1.1\r\n\r\n"
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        reader.feed_eof()

        request = await self.handler._read_connect_request(reader)
        assert request is None


class TestTunnelSessionModel:
    """Tests for TunnelSession data model."""

    def test_default_values(self):
        from app.models.forward_proxy import TunnelSession

        session = TunnelSession(hostname="example.com")
        assert session.hostname == "example.com"
        assert session.port == 443
        assert session.state == TunnelState.PENDING
        assert session.bytes_sent == 0
        assert session.bytes_received == 0
        assert session.closed_at is None
        assert session.close_reason is None
        assert session.blocked is False

    def test_tunnel_stats_model(self):
        from app.models.forward_proxy import TunnelStats

        stats = TunnelStats()
        assert stats.active_tunnels == 0
        assert stats.total_tunnels == 0
        assert stats.avg_tunnel_duration_s == 0.0
