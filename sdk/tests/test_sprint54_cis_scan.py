"""Sprint 54 — APEP-434.c: Tests for SDK cis_scan(path_or_text) helper.

Tests the SDK client cis_scan and cis_scan_sync methods, plus the
CLI cis-scan command.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from agentpep.client import AgentPEPClient


class TestCISScanHelper:
    """Tests for AgentPEPClient.cis_scan and cis_scan_sync."""

    def test_cis_scan_sync_text_detection(self) -> None:
        """Text without path separators should call scan-text endpoint."""
        client = AgentPEPClient(base_url="http://test:8000")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": True,
            "findings": [],
            "scan_mode": "STRICT",
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(client, "_get_sync_client") as mock_get:
            mock_http = MagicMock()
            mock_http.post.return_value = mock_response
            mock_get.return_value = mock_http

            result = client.cis_scan_sync("Hello world, this is clean text")

        mock_http.post.assert_called_once()
        call_args = mock_http.post.call_args
        assert "/v1/cis/scan-text" in call_args[0][0]

    def test_cis_scan_sync_path_detection(self) -> None:
        """Paths with separators should call scan-file endpoint."""
        client = AgentPEPClient(base_url="http://test:8000")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "allowed": True,
            "findings": [],
            "file_path": "/tmp/test.py",
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(client, "_get_sync_client") as mock_get:
            mock_http = MagicMock()
            mock_http.post.return_value = mock_response
            mock_get.return_value = mock_http

            result = client.cis_scan_sync("/tmp/test.py")

        mock_http.post.assert_called_once()
        call_args = mock_http.post.call_args
        assert "/v1/cis/scan-file" in call_args[0][0]

    def test_cis_scan_sync_passes_scan_mode(self) -> None:
        """Scan mode should be forwarded to the server."""
        client = AgentPEPClient(base_url="http://test:8000")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"allowed": True, "findings": []}
        mock_response.raise_for_status = MagicMock()

        with patch.object(client, "_get_sync_client") as mock_get:
            mock_http = MagicMock()
            mock_http.post.return_value = mock_response
            mock_get.return_value = mock_http

            client.cis_scan_sync("test text", scan_mode="LENIENT")

        call_args = mock_http.post.call_args
        payload = call_args[1]["json"]
        assert payload["scan_mode"] == "LENIENT"

    def test_cis_scan_sync_fail_open(self) -> None:
        """When fail_open=True and server is unreachable, return clean result."""
        import httpx

        client = AgentPEPClient(base_url="http://test:8000", fail_open=True)

        with patch.object(client, "_get_sync_client") as mock_get:
            mock_http = MagicMock()
            mock_http.post.side_effect = httpx.ConnectError("Connection refused")
            mock_get.return_value = mock_http

            result = client.cis_scan_sync("test text")

        assert result["allowed"] is True
        assert result["fail_open"] is True

    def test_cis_scan_sync_fail_closed(self) -> None:
        """When fail_open=False and server is unreachable, raise error."""
        import httpx

        from agentpep.exceptions import AgentPEPConnectionError

        client = AgentPEPClient(base_url="http://test:8000", fail_open=False)

        with patch.object(client, "_get_sync_client") as mock_get:
            mock_http = MagicMock()
            mock_http.post.side_effect = httpx.ConnectError("Connection refused")
            mock_get.return_value = mock_http

            with pytest.raises(AgentPEPConnectionError):
                client.cis_scan_sync("test text")


class TestCISScanCLI:
    """Tests for the agentpep cis-scan CLI command."""

    def test_cli_parser_accepts_cis_scan(self) -> None:
        from agentpep.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["cis-scan", "test content", "--scan-mode", "STRICT"])
        assert args.command == "cis-scan"
        assert args.target == "test content"
        assert args.scan_mode == "STRICT"

    def test_cli_parser_accepts_json_flag(self) -> None:
        from agentpep.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["cis-scan", "/tmp/file.py", "--json"])
        assert args.json is True

    def test_cli_parser_accepts_all_scan_modes(self) -> None:
        from agentpep.cli import build_parser

        parser = build_parser()
        for mode in ["STRICT", "STANDARD", "LENIENT"]:
            args = parser.parse_args(["cis-scan", "text", "--scan-mode", mode])
            assert args.scan_mode == mode
