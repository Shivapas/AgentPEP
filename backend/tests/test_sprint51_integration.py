"""Integration tests for Sprint 51 — Rule Bundles, Security Assessment & Network Audit Events.

APEP-406.g: Integration tests for security assessment engine.
APEP-409.d: E2E tests for TFN events to Policy Console — Network Events tab.
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from tests.conftest import _get_auth_headers


# ---------------------------------------------------------------------------
# APEP-407: GET /v1/network/assess integration tests
# ---------------------------------------------------------------------------


class TestNetworkAssessEndpoint:
    """Integration tests for the security assessment REST endpoints."""

    @pytest.mark.asyncio
    async def test_get_assessment(self, mock_mongodb):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/v1/network/assess",
                headers=_get_auth_headers(),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "assessment_id" in data
        assert "overall_score" in data
        assert "grade" in data
        assert "findings" in data
        assert "total_checks" in data
        assert "passed_checks" in data
        assert "failed_checks" in data
        assert data["overall_score"] >= 0.0
        assert data["overall_score"] <= 100.0
        assert data["grade"] in ("A", "B", "C", "D", "F")

    @pytest.mark.asyncio
    async def test_post_assessment_config_only(self, mock_mongodb):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/network/assess",
                headers=_get_auth_headers(),
                json={
                    "phases": ["CONFIG_AUDIT"],
                    "include_passed": True,
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "CONFIG_AUDIT" in data["phases_run"]
        assert "ATTACK_SIMULATION" not in data["phases_run"]

    @pytest.mark.asyncio
    async def test_post_assessment_specific_categories(self, mock_mongodb):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/network/assess",
                headers=_get_auth_headers(),
                json={
                    "phases": ["CONFIG_AUDIT"],
                    "categories": ["AUTH_CONFIG", "KILL_SWITCH"],
                    "include_passed": True,
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        categories = {f["category"] for f in data["findings"]}
        assert categories <= {"AUTH_CONFIG", "KILL_SWITCH"}

    @pytest.mark.asyncio
    async def test_assessment_exclude_passed(self, mock_mongodb):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/v1/network/assess?include_passed=false",
                headers=_get_auth_headers(),
            )
        assert resp.status_code == 200
        data = resp.json()
        for finding in data["findings"]:
            assert finding["passed"] is False


# ---------------------------------------------------------------------------
# APEP-404/405: Rule Bundle integration tests
# ---------------------------------------------------------------------------


class TestRuleBundleEndpoints:
    """Integration tests for rule bundle REST endpoints."""

    @pytest.mark.asyncio
    async def test_list_bundles_empty(self, mock_mongodb):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/v1/network/bundles",
                headers=_get_auth_headers(),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "bundles" in data
        assert "total" in data

    @pytest.mark.asyncio
    async def test_load_bundle_from_yaml(self, mock_mongodb):
        transport = ASGITransport(app=app)
        yaml_content = """
manifest:
  name: test-api-bundle
  version: 1.0.0
rules:
  - rule_id: R1
    rule_type: DLP
    pattern: "test-pattern"
    severity: HIGH
"""
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/network/bundles",
                headers=_get_auth_headers(),
                json={
                    "yaml_content": yaml_content,
                    "verify_signature": False,
                    "activate": True,
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["rules_loaded"] == 1
        assert data["bundle"]["manifest"]["name"] == "test-api-bundle"
        assert data["bundle"]["status"] == "ACTIVE"

    @pytest.mark.asyncio
    async def test_load_bundle_no_content_returns_400(self, mock_mongodb):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/network/bundles",
                headers=_get_auth_headers(),
                json={},
            )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_get_bundle_not_found(self, mock_mongodb):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/v1/network/bundles/00000000-0000-0000-0000-000000000000",
                headers=_get_auth_headers(),
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_activate_deactivate_bundle(self, mock_mongodb):
        transport = ASGITransport(app=app)
        yaml_content = "manifest:\n  name: toggle-test\nrules: []"
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Load
            resp = await client.post(
                "/v1/network/bundles",
                headers=_get_auth_headers(),
                json={"yaml_content": yaml_content, "verify_signature": False},
            )
            bundle_id = resp.json()["bundle"]["bundle_id"]

            # Activate
            resp = await client.post(
                f"/v1/network/bundles/{bundle_id}/activate",
                headers=_get_auth_headers(),
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "ACTIVE"

            # Deactivate
            resp = await client.post(
                f"/v1/network/bundles/{bundle_id}/deactivate",
                headers=_get_auth_headers(),
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "INACTIVE"

    @pytest.mark.asyncio
    async def test_remove_bundle(self, mock_mongodb):
        transport = ASGITransport(app=app)
        yaml_content = "manifest:\n  name: remove-test\nrules: []"
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/network/bundles",
                headers=_get_auth_headers(),
                json={"yaml_content": yaml_content, "verify_signature": False},
            )
            bundle_id = resp.json()["bundle"]["bundle_id"]

            resp = await client.delete(
                f"/v1/network/bundles/{bundle_id}",
                headers=_get_auth_headers(),
            )
            assert resp.status_code == 200
            assert resp.json()["status"] == "removed"


# ---------------------------------------------------------------------------
# APEP-408: MITRE ATT&CK Mapping integration tests
# ---------------------------------------------------------------------------


class TestMitreEndpoints:
    """Integration tests for MITRE ATT&CK REST endpoints."""

    @pytest.mark.asyncio
    async def test_get_mitre_map(self, mock_mongodb):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/v1/network/mitre",
                headers=_get_auth_headers(),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "techniques" in data
        assert "event_type_mappings" in data
        assert len(data["techniques"]) > 0

    @pytest.mark.asyncio
    async def test_get_mitre_stats(self, mock_mongodb):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/v1/network/mitre/stats",
                headers=_get_auth_headers(),
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["techniques"] > 0
        assert data["event_type_mappings"] > 0


# ---------------------------------------------------------------------------
# APEP-406.g: Security Assessment Engine pipeline integration
# ---------------------------------------------------------------------------


class TestAssessmentPipelineIntegration:
    """Integration tests verifying assessment engine wiring."""

    @pytest.mark.asyncio
    async def test_assessment_findings_have_mitre_tags(self, mock_mongodb):
        """Verify assessment findings are enriched with MITRE ATT&CK technique IDs."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/v1/network/assess",
                headers=_get_auth_headers(),
            )
        data = resp.json()
        mitre_tagged = [f for f in data["findings"] if f.get("mitre_technique_id")]
        # At least some findings should have MITRE tags
        assert len(mitre_tagged) > 0

    @pytest.mark.asyncio
    async def test_assessment_covers_all_12_categories(self, mock_mongodb):
        """Verify the config audit phase covers all 12 categories."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.post(
                "/v1/network/assess",
                headers=_get_auth_headers(),
                json={"phases": ["CONFIG_AUDIT"], "include_passed": True},
            )
        data = resp.json()
        categories_found = {f["category"] for f in data["findings"]}
        expected_categories = {
            "DLP_COVERAGE",
            "INJECTION_PROTECTION",
            "SSRF_PREVENTION",
            "RATE_LIMITING",
            "AUTH_CONFIG",
            "TAINT_TRACKING",
            "KILL_SWITCH",
            "CHAIN_DETECTION",
            "FILESYSTEM_SENTINEL",
            "TLS_CONFIG",
            "AUDIT_INTEGRITY",
            "NETWORK_EGRESS",
        }
        # All 12 categories should have at least one finding
        assert categories_found == expected_categories

    @pytest.mark.asyncio
    async def test_assessment_latency_under_5_seconds(self, mock_mongodb):
        """Verify assessment completes within performance budget."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/v1/network/assess",
                headers=_get_auth_headers(),
            )
        data = resp.json()
        assert data["latency_ms"] < 5000, f"Assessment took {data['latency_ms']}ms"

    @pytest.mark.asyncio
    async def test_bundle_load_and_assess_integration(self, mock_mongodb):
        """Verify loading a bundle then running assessment works end-to-end."""
        transport = ASGITransport(app=app)
        yaml_content = """
manifest:
  name: integration-test-bundle
  version: 1.0.0
rules:
  - rule_id: INT-001
    rule_type: DLP
    pattern: "test"
    severity: HIGH
"""
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Load bundle
            resp = await client.post(
                "/v1/network/bundles",
                headers=_get_auth_headers(),
                json={
                    "yaml_content": yaml_content,
                    "verify_signature": False,
                    "activate": True,
                },
            )
            assert resp.status_code == 200

            # Run assessment
            resp = await client.get(
                "/v1/network/assess",
                headers=_get_auth_headers(),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_checks"] > 0
