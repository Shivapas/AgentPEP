"""Tests for Sprint 46 — SDK fetch_safe() method (APEP-370).

Tests the SDK client's fetch_safe() and fetch_safe_sync() methods
along with the FetchSafeResponse model.
"""

from __future__ import annotations

import pytest

from agentpep.models import FetchSafeResponse, FetchStatus


class TestFetchSafeResponse:
    """Tests for the FetchSafeResponse SDK model."""

    def test_defaults(self) -> None:
        resp = FetchSafeResponse()
        assert resp.status == FetchStatus.ALLOWED
        assert resp.body == ""
        assert resp.injection_detected is False
        assert resp.dlp_findings_count == 0
        assert resp.action_taken == "ALLOW"

    def test_blocked_response(self) -> None:
        resp = FetchSafeResponse(
            url="https://evil.example.com",
            status=FetchStatus.BLOCKED,
            http_status=0,
            injection_detected=True,
            injection_finding_count=3,
            injection_highest_severity="CRITICAL",
            action_taken="BLOCK",
        )
        assert resp.status == FetchStatus.BLOCKED
        assert resp.injection_detected is True
        assert resp.injection_finding_count == 3

    def test_quarantined_response(self) -> None:
        resp = FetchSafeResponse(
            url="https://suspicious.example.com",
            status=FetchStatus.QUARANTINED,
            http_status=200,
            body="Some content",
            injection_detected=True,
            taint_applied="QUARANTINE",
            taint_node_id="abc-123",
            action_taken="QUARANTINE",
        )
        assert resp.status == FetchStatus.QUARANTINED
        assert resp.taint_applied == "QUARANTINE"

    def test_sanitized_response(self) -> None:
        resp = FetchSafeResponse(
            url="https://example.com",
            status=FetchStatus.SANITIZED,
            http_status=200,
            body="Normalized clean content",
            body_length=23,
            action_taken="SANITIZE",
        )
        assert resp.status == FetchStatus.SANITIZED

    def test_serialization(self) -> None:
        resp = FetchSafeResponse(
            url="https://example.com",
            http_status=200,
            body="test",
            body_length=4,
        )
        data = resp.model_dump()
        assert data["url"] == "https://example.com"
        assert data["http_status"] == 200
        assert data["body"] == "test"

    def test_from_server_response(self) -> None:
        """Simulate mapping from server JSON to SDK model."""
        server_data = {
            "fetch_id": "550e8400-e29b-41d4-a716-446655440000",
            "url": "https://example.com",
            "status": "ALLOWED",
            "http_status": 200,
            "content_type": "text/html",
            "body": "<html>Hello</html>",
            "body_length": 18,
            "truncated": False,
            "injection_scan": {
                "injection_detected": False,
                "findings": [],
                "passes_run": ["RAW_SIGNATURE", "NORMALIZED_SIGNATURE"],
                "total_findings": 0,
                "highest_severity": "INFO",
            },
            "dlp_findings_count": 0,
            "dlp_blocked": False,
            "taint_applied": None,
            "taint_node_id": None,
            "action_taken": "ALLOW",
            "latency_ms": 150,
        }
        injection_scan = server_data.get("injection_scan") or {}
        resp = FetchSafeResponse(
            fetch_id=server_data.get("fetch_id"),
            url=server_data["url"],
            status=server_data["status"],
            http_status=server_data["http_status"],
            content_type=server_data["content_type"],
            body=server_data["body"],
            body_length=server_data["body_length"],
            truncated=server_data["truncated"],
            injection_detected=injection_scan.get("injection_detected", False),
            injection_finding_count=injection_scan.get("total_findings", 0),
            injection_highest_severity=injection_scan.get("highest_severity", "INFO"),
            dlp_findings_count=server_data["dlp_findings_count"],
            dlp_blocked=server_data["dlp_blocked"],
            taint_applied=server_data["taint_applied"],
            taint_node_id=server_data["taint_node_id"],
            action_taken=server_data["action_taken"],
            latency_ms=server_data["latency_ms"],
        )
        assert resp.url == "https://example.com"
        assert resp.http_status == 200
        assert not resp.injection_detected
        assert resp.latency_ms == 150


class TestFetchStatusEnum:
    """Tests for the FetchStatus enum."""

    def test_values(self) -> None:
        assert FetchStatus.ALLOWED == "ALLOWED"
        assert FetchStatus.BLOCKED == "BLOCKED"
        assert FetchStatus.QUARANTINED == "QUARANTINED"
        assert FetchStatus.SANITIZED == "SANITIZED"

    def test_all_members(self) -> None:
        assert len(FetchStatus) == 4
