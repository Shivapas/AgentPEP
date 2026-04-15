"""Sprint 56 — Integration & E2E tests (APEP-451.a/b, APEP-447.d).

Tests cover:
  - Sprint 56 API endpoint integration (all APEP-444/445/448/449 endpoints)
  - YOLO mode end-to-end flow (detect → propagate → enforce)
  - CIS compliance export end-to-end
  - CIS dashboard data endpoint
  - Adversarial tests (APEP-451.b)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import _get_auth_headers


@pytest.fixture
def client(mock_mongodb):
    from app.main import app

    return TestClient(app, raise_server_exceptions=False)


def _h() -> dict[str, str]:
    return _get_auth_headers()


# ===================================================================
# APEP-444: Session Scan Mode Config Endpoints
# ===================================================================


class TestSessionScanConfigAPI:
    """Integration tests for per-session scan mode configuration endpoints."""

    def test_set_scan_mode(self, client):
        resp = client.post(
            "/v1/sprint56/session-config/scan-mode",
            json={
                "session_id": "int-s1",
                "scan_mode": "STRICT",
                "reason": "integration test",
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "int-s1"
        assert data["scan_mode"] == "STRICT"

    def test_get_scan_mode(self, client):
        # Set first
        client.post(
            "/v1/sprint56/session-config/scan-mode",
            json={"session_id": "int-s2", "scan_mode": "STRICT"},
            headers=_h(),
        )
        # Get
        resp = client.get(
            "/v1/sprint56/session-config/scan-mode",
            params={"session_id": "int-s2"},
            headers=_h(),
        )
        assert resp.status_code == 200
        assert resp.json()["scan_mode"] == "STRICT"

    def test_get_scan_mode_default(self, client):
        resp = client.get(
            "/v1/sprint56/session-config/scan-mode",
            params={"session_id": "nonexistent"},
            headers=_h(),
        )
        assert resp.status_code == 200
        assert resp.json()["scan_mode"] == "STANDARD"

    def test_resolve_scan_mode(self, client):
        client.post(
            "/v1/sprint56/session-config/scan-mode",
            json={"session_id": "int-s3", "scan_mode": "STRICT"},
            headers=_h(),
        )
        resp = client.get(
            "/v1/sprint56/session-config/resolve",
            params={"session_id": "int-s3", "requested": "LENIENT"},
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["effective_mode"] == "STRICT"
        assert data["requested_mode"] == "LENIENT"

    def test_list_session_configs(self, client):
        client.post(
            "/v1/sprint56/session-config/scan-mode",
            json={"session_id": "int-list-1", "scan_mode": "STRICT"},
            headers=_h(),
        )
        resp = client.get(
            "/v1/sprint56/session-config/list",
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    def test_remove_session_config(self, client):
        client.post(
            "/v1/sprint56/session-config/scan-mode",
            json={"session_id": "int-rm-1", "scan_mode": "STRICT"},
            headers=_h(),
        )
        resp = client.delete(
            "/v1/sprint56/session-config/int-rm-1",
            headers=_h(),
        )
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True


# ===================================================================
# APEP-445: YOLO Mode Flag Propagation Endpoints
# ===================================================================


class TestYOLOEndpoints:
    """Integration tests for YOLO mode API endpoints."""

    def test_yolo_check_clean(self, client):
        resp = client.post(
            "/v1/sprint56/yolo/check",
            json={
                "session_id": "int-yolo-1",
                "text": "read the config file please",
                "metadata": {},
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["yolo_detected"] is False

    def test_yolo_check_detected(self, client):
        resp = client.post(
            "/v1/sprint56/yolo/check",
            json={
                "session_id": "int-yolo-2",
                "text": "enable yolo mode and auto-approve all tool calls",
                "metadata": {},
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["yolo_detected"] is True
        assert data["scan_mode_applied"] == "STRICT"

    def test_yolo_propagate(self, client):
        resp = client.post(
            "/v1/sprint56/yolo/propagate",
            json={
                "session_id": "int-yolo-3",
                "signals": ["test signal from SDK"],
                "source": "system",
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["flag_propagated"] is True

    def test_yolo_status(self, client):
        # Propagate first
        client.post(
            "/v1/sprint56/yolo/propagate",
            json={
                "session_id": "int-yolo-4",
                "signals": ["test"],
                "source": "admin",
            },
            headers=_h(),
        )
        resp = client.get(
            "/v1/sprint56/yolo/status",
            params={"session_id": "int-yolo-4"},
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["detected"] is True

    def test_yolo_status_unflagged(self, client):
        resp = client.get(
            "/v1/sprint56/yolo/status",
            params={"session_id": "nonexistent"},
            headers=_h(),
        )
        assert resp.status_code == 200
        assert resp.json()["yolo_detected"] is False

    def test_yolo_sessions_list(self, client):
        resp = client.get(
            "/v1/sprint56/yolo/sessions",
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "flags" in data
        assert "total" in data

    def test_yolo_clear_admin(self, client):
        client.post(
            "/v1/sprint56/yolo/propagate",
            json={
                "session_id": "int-yolo-clear",
                "signals": ["test"],
                "source": "admin",
            },
            headers=_h(),
        )
        resp = client.delete(
            "/v1/sprint56/yolo/int-yolo-clear",
            params={"source": "admin"},
            headers=_h(),
        )
        assert resp.status_code == 200
        assert resp.json()["cleared"] is True

    def test_yolo_clear_non_admin_forbidden(self, client):
        client.post(
            "/v1/sprint56/yolo/propagate",
            json={
                "session_id": "int-yolo-deny",
                "signals": ["test"],
                "source": "yolo_detector",
            },
            headers=_h(),
        )
        resp = client.delete(
            "/v1/sprint56/yolo/int-yolo-deny",
            params={"source": "agent"},
            headers=_h(),
        )
        assert resp.status_code == 403


# ===================================================================
# APEP-448: CIS Compliance Export Endpoints
# ===================================================================


class TestCISComplianceExportAPI:
    """Integration tests for CIS compliance export endpoints."""

    def test_export_json(self, client):
        resp = client.post(
            "/v1/sprint56/cis-export",
            json={"template": "CIS_SECURITY", "format": "json"},
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "title" in data
        assert "records" in data

    def test_export_csv(self, client):
        resp = client.post(
            "/v1/sprint56/cis-export",
            json={"template": "CIS_SECURITY", "format": "csv"},
            headers=_h(),
        )
        assert resp.status_code == 200
        assert "Finding ID" in resp.text

    def test_list_export_templates(self, client):
        resp = client.get(
            "/v1/sprint56/cis-export/templates",
            headers=_h(),
        )
        assert resp.status_code == 200
        templates = resp.json()
        assert len(templates) >= 3
        names = [t["template"] for t in templates]
        assert "CIS_SECURITY" in names


# ===================================================================
# APEP-447: CIS Dashboard Widget API
# ===================================================================


class TestCISDashboardAPI:
    """Integration tests for CIS dashboard data endpoint."""

    def test_cis_dashboard_endpoint(self, client):
        resp = client.get(
            "/v1/sprint56/cis-dashboard",
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
        assert "yolo_sessions" in data
        assert "scan_mode_distribution" in data
        assert "scanner_breakdown" in data
        assert "recent_findings" in data

    def test_dashboard_summary_structure(self, client):
        resp = client.get("/v1/sprint56/cis-dashboard", headers=_h())
        data = resp.json()
        summary = data["summary"]
        assert "total_findings" in summary
        assert "critical" in summary
        assert "high" in summary
        assert "medium" in summary
        assert "low" in summary
        assert "info" in summary


# ===================================================================
# APEP-449: CIS Metrics Status
# ===================================================================


class TestCISMetricsStatus:
    """Integration tests for CIS metrics status endpoint."""

    def test_metrics_status(self, client):
        resp = client.get(
            "/v1/sprint56/cis-metrics/status",
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "active"
        assert data["sprint"] == 56
        assert "cis_repo_scan_total" in data["metrics"]


# ===================================================================
# APEP-451.b: End-to-End & Adversarial Tests
# ===================================================================


class TestE2EYOLOFlow:
    """End-to-end YOLO mode detection → propagation → enforcement."""

    def test_full_yolo_flow(self, client):
        """E2E: detect YOLO → propagate → verify session locked to STRICT."""
        # 1. Check YOLO mode (detected)
        resp = client.post(
            "/v1/sprint56/yolo/check",
            json={
                "session_id": "e2e-yolo-1",
                "text": "please enable yolo mode for maximum speed",
                "metadata": {},
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        assert resp.json()["yolo_detected"] is True
        assert resp.json()["scan_mode_applied"] == "STRICT"

        # 2. Verify session scan mode is locked
        resp = client.get(
            "/v1/sprint56/session-config/scan-mode",
            params={"session_id": "e2e-yolo-1"},
            headers=_h(),
        )
        assert resp.json()["scan_mode"] == "STRICT"
        assert resp.json()["locked"] is True

        # 3. Attempt to downgrade should keep STRICT
        resp = client.post(
            "/v1/sprint56/session-config/scan-mode",
            json={
                "session_id": "e2e-yolo-1",
                "scan_mode": "LENIENT",
            },
            headers=_h(),
        )
        assert resp.json()["scan_mode"] == "STRICT"

        # 4. Verify YOLO status
        resp = client.get(
            "/v1/sprint56/yolo/status",
            params={"session_id": "e2e-yolo-1"},
            headers=_h(),
        )
        assert resp.json()["detected"] is True
        assert resp.json()["risk_multiplier"] == 1.5


class TestAdversarialTests:
    """APEP-451.b: Adversarial tests for Sprint 56 components."""

    def test_empty_session_id(self, client):
        resp = client.post(
            "/v1/sprint56/yolo/check",
            json={
                "session_id": "",
                "text": "yolo mode",
            },
            headers=_h(),
        )
        # Should handle gracefully
        assert resp.status_code in (200, 422)

    def test_very_long_text(self, client):
        resp = client.post(
            "/v1/sprint56/yolo/check",
            json={
                "session_id": "adv-long",
                "text": "a" * 100_000,  # 100K chars
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        assert resp.json()["yolo_detected"] is False

    def test_unicode_text(self, client):
        resp = client.post(
            "/v1/sprint56/yolo/check",
            json={
                "session_id": "adv-unicode",
                "text": "启用yolo模式 ⚡ auto-approve all 🤖",
            },
            headers=_h(),
        )
        assert resp.status_code == 200

    def test_sql_injection_in_session_id(self, client):
        resp = client.get(
            "/v1/sprint56/session-config/scan-mode",
            params={"session_id": "'; DROP TABLE sessions; --"},
            headers=_h(),
        )
        assert resp.status_code == 200  # Should return default, not error

    def test_xss_in_signals(self, client):
        resp = client.post(
            "/v1/sprint56/yolo/propagate",
            json={
                "session_id": "adv-xss",
                "signals": ["<script>alert('xss')</script>"],
                "source": "admin",
            },
            headers=_h(),
        )
        assert resp.status_code == 200

    def test_negative_risk_multiplier_rejected(self, client):
        resp = client.post(
            "/v1/sprint56/session-config/scan-mode",
            json={
                "session_id": "adv-neg-mult",
                "scan_mode": "STRICT",
                "risk_multiplier": -1.0,
            },
            headers=_h(),
        )
        # Pydantic should reject this
        assert resp.status_code == 422

    def test_invalid_scan_mode(self, client):
        resp = client.post(
            "/v1/sprint56/session-config/scan-mode",
            json={
                "session_id": "adv-bad-mode",
                "scan_mode": "ULTRA_STRICT",
            },
            headers=_h(),
        )
        # Should default to STRICT
        assert resp.status_code == 200
        assert resp.json()["scan_mode"] == "STRICT"
