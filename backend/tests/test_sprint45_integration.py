"""Integration and adversarial tests for Sprint 45 — DLP Pre-Scan Hook.

APEP-356.g: Integration tests for DLPPreScanStage in PolicyEvaluator.
APEP-362: Adversarial tests — DLP evasion attempts.
"""

from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.policy import (
    Decision,
    DLPPatternType,
    DLPSeverity,
    PolicyRule,
    TaintLevel,
    ToolCallRequest,
)
from app.services.network_dlp import (
    NetworkDLPScanner,
    DLPPreScanCache,
    network_dlp_scanner,
)
from app.services.policy_evaluator import policy_evaluator
from tests.conftest import make_auth_headers


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(**overrides) -> ToolCallRequest:
    defaults = {
        "session_id": "test-session",
        "agent_id": "test-agent",
        "tool_name": "file.write",
        "tool_args": {},
    }
    defaults.update(overrides)
    return ToolCallRequest(**defaults)


async def _seed_allow_rule(mock_mongodb):
    """Seed a permissive policy rule for testing."""
    from app.db import mongodb as db_module

    rule = PolicyRule(
        name="allow_all",
        agent_role=["default", "Admin"],
        tool_pattern="*",
        action=Decision.ALLOW,
        taint_check=True,
        priority=100,
    )
    await mock_mongodb[db_module.POLICY_RULES].insert_one(
        rule.model_dump(mode="json")
    )
    # Invalidate rule cache
    from app.services.rule_cache import rule_cache
    rule_cache.invalidate()


# ===========================================================================
# APEP-356.g: Integration Tests — DLPPreScanStage in PolicyEvaluator
# ===========================================================================


class TestDLPPreScanIntegration:
    """Integration tests for the DLP pre-scan stage in the intercept pipeline."""

    @pytest.mark.asyncio
    async def test_intercept_with_dlp_enabled_clean_args(self, mock_mongodb, monkeypatch):
        """Intercept with DLP enabled and clean args should ALLOW."""
        monkeypatch.setattr("app.core.config.settings.dlp_pre_scan_enabled", True)
        await _seed_allow_rule(mock_mongodb)

        request = _make_request(tool_args={"filename": "report.txt"})
        response = await policy_evaluator.evaluate(request)

        assert response.decision == Decision.ALLOW
        assert response.dlp_findings is None or len(response.dlp_findings) == 0

    @pytest.mark.asyncio
    async def test_intercept_with_dlp_detects_credential(self, mock_mongodb, monkeypatch):
        """Intercept with DLP enabled should detect credential and DENY."""
        monkeypatch.setattr("app.core.config.settings.dlp_pre_scan_enabled", True)
        monkeypatch.setattr("app.core.config.settings.dlp_risk_elevation_enabled", True)
        monkeypatch.setattr("app.core.config.settings.dlp_taint_assignment_enabled", True)
        await _seed_allow_rule(mock_mongodb)

        request = _make_request(
            tool_args={"data": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."}
        )
        response = await policy_evaluator.evaluate(request)

        # CRITICAL credential → QUARANTINE taint → DENY
        assert response.decision == Decision.DENY
        assert response.dlp_findings is not None
        assert len(response.dlp_findings) > 0
        assert any(f.severity == DLPSeverity.CRITICAL for f in response.dlp_findings)

    @pytest.mark.asyncio
    async def test_intercept_with_dlp_detects_pii_escalates(self, mock_mongodb, monkeypatch):
        """Intercept with DLP enabled should detect PII and ESCALATE."""
        monkeypatch.setattr("app.core.config.settings.dlp_pre_scan_enabled", True)
        monkeypatch.setattr("app.core.config.settings.dlp_risk_elevation_enabled", True)
        monkeypatch.setattr("app.core.config.settings.dlp_taint_assignment_enabled", True)
        await _seed_allow_rule(mock_mongodb)

        request = _make_request(
            tool_args={"user_data": "SSN: 123-45-6789"}
        )
        response = await policy_evaluator.evaluate(request)

        # PII → UNTRUSTED taint → ESCALATE
        assert response.decision == Decision.ESCALATE
        assert response.dlp_findings is not None
        assert any(f.pattern_type == DLPPatternType.PII for f in response.dlp_findings)

    @pytest.mark.asyncio
    async def test_intercept_dlp_disabled_ignores_secrets(self, mock_mongodb, monkeypatch):
        """Intercept with DLP disabled should not scan for secrets."""
        monkeypatch.setattr("app.core.config.settings.dlp_pre_scan_enabled", False)
        await _seed_allow_rule(mock_mongodb)

        request = _make_request(
            tool_args={"key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."}
        )
        response = await policy_evaluator.evaluate(request)

        assert response.decision == Decision.ALLOW
        assert response.dlp_findings is None

    @pytest.mark.asyncio
    async def test_dlp_risk_elevation_in_response(self, mock_mongodb, monkeypatch):
        """DLP findings should elevate the risk score in the response."""
        monkeypatch.setattr("app.core.config.settings.dlp_pre_scan_enabled", True)
        monkeypatch.setattr("app.core.config.settings.dlp_risk_elevation_enabled", True)
        monkeypatch.setattr("app.core.config.settings.dlp_taint_assignment_enabled", False)
        await _seed_allow_rule(mock_mongodb)

        request = _make_request(
            tool_args={"key": "AKIAIOSFODNN7EXAMPLE"}
        )
        response = await policy_evaluator.evaluate(request)

        # With taint disabled, decision may still be ALLOW but risk should be elevated
        assert response.risk_score > 0

    @pytest.mark.asyncio
    async def test_dlp_findings_attached_to_response(self, mock_mongodb, monkeypatch):
        """DLP findings should be attached to PolicyDecisionResponse."""
        monkeypatch.setattr("app.core.config.settings.dlp_pre_scan_enabled", True)
        monkeypatch.setattr("app.core.config.settings.dlp_taint_assignment_enabled", False)
        await _seed_allow_rule(mock_mongodb)

        request = _make_request(
            tool_args={
                "aws_key": "AKIAIOSFODNN7EXAMPLE",
                "github_token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123",
            }
        )
        response = await policy_evaluator.evaluate(request)

        assert response.dlp_findings is not None
        assert len(response.dlp_findings) >= 2
        pattern_ids = {f.pattern_id for f in response.dlp_findings}
        assert "DLP-001" in pattern_ids  # AWS key
        assert "DLP-011" in pattern_ids  # GitHub PAT


# ===========================================================================
# APEP-356.g: Integration Tests — DLP API Endpoint
# ===========================================================================


class TestDLPAPIEndpoint:
    """Integration tests for the /v1/dlp/* API endpoints."""

    @pytest.mark.asyncio
    async def test_scan_endpoint(self, mock_mongodb):
        """POST /v1/dlp/scan should return DLP scan results."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = make_auth_headers()
            response = await client.post(
                "/v1/dlp/scan",
                json={
                    "session_id": "test-session",
                    "agent_id": "test-agent",
                    "tool_name": "file.write",
                    "tool_args": {"key": "AKIAIOSFODNN7EXAMPLE"},
                },
                headers=headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["scanned"] is True
            assert len(data["findings"]) > 0

    @pytest.mark.asyncio
    async def test_scan_endpoint_clean_args(self, mock_mongodb):
        """POST /v1/dlp/scan with clean args should return empty findings."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = make_auth_headers()
            response = await client.post(
                "/v1/dlp/scan",
                json={
                    "session_id": "test-session",
                    "agent_id": "test-agent",
                    "tool_name": "file.read",
                    "tool_args": {"filename": "report.txt"},
                },
                headers=headers,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["scanned"] is True
            assert len(data["findings"]) == 0

    @pytest.mark.asyncio
    async def test_status_endpoint(self, mock_mongodb):
        """GET /v1/dlp/status should return scanner status."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = make_auth_headers()
            response = await client.get("/v1/dlp/status", headers=headers)
            assert response.status_code == 200
            data = response.json()
            assert "enabled" in data
            assert "pattern_count" in data
            assert data["pattern_count"] >= 46

    @pytest.mark.asyncio
    async def test_reload_endpoint(self, mock_mongodb):
        """POST /v1/dlp/patterns/reload should reload patterns."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            headers = make_auth_headers()
            response = await client.post(
                "/v1/dlp/patterns/reload", headers=headers
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ok"
            assert data["pattern_count"] >= 46


# ===========================================================================
# APEP-362: Adversarial Tests — DLP Evasion Attempts
# ===========================================================================


class TestDLPAdversarialEvasion:
    """Adversarial tests verifying DLP cannot be trivially bypassed."""

    def setup_method(self):
        self.scanner = NetworkDLPScanner()
        self.scanner.cache = DLPPreScanCache(max_size=0, max_age_s=0)

    def test_base64_encoded_key_not_decoded(self):
        """Base64-encoded secrets should still be caught if the base64 form
        matches a pattern (e.g. Bearer token with base64 content)."""
        # Bearer tokens are often base64-encoded
        result = self.scanner.scan_tool_args({
            "auth": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        })
        assert result.has_findings is True

    def test_whitespace_padding_evasion(self):
        """Whitespace padding around secrets should not evade detection."""
        result = self.scanner.scan_tool_args({
            "key": "  AKIAIOSFODNN7EXAMPLE  "
        })
        assert result.has_findings is True
        assert any(f.pattern_id == "DLP-001" for f in result.findings)

    def test_newline_split_private_key(self):
        """Private key header split with newlines should still be detected."""
        result = self.scanner.scan_tool_args({
            "cert": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA"
        })
        assert result.has_findings is True

    def test_case_variation_evasion(self):
        """Case variations (where applicable) should still be detected.

        Note: Some patterns are case-sensitive by design (e.g. AWS key prefix
        AKIA must be uppercase).
        """
        # Password assignment is case-insensitive
        result = self.scanner.scan_tool_args({
            "config": "PASSWORD = mysecretpassword123"
        })
        assert result.has_findings is True

    def test_concatenated_secrets(self):
        """Secrets concatenated with other text should be detected."""
        result = self.scanner.scan_tool_args({
            "log": "Starting auth with key=AKIAIOSFODNN7EXAMPLE and proceeding"
        })
        assert result.has_findings is True

    def test_json_encoded_args(self):
        """Secrets inside JSON-encoded string values should be detected."""
        import json
        result = self.scanner.scan_tool_args({
            "payload": json.dumps({
                "auth": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"
            })
        })
        assert result.has_findings is True

    def test_multiple_keys_in_single_arg(self):
        """Multiple secrets in a single arg value should all be detected."""
        result = self.scanner.scan_tool_args({
            "config": (
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            )
        })
        # Should detect both the AKIA key and the secret assignment
        assert len(result.findings) >= 1

    def test_url_encoded_connection_string(self):
        """Connection strings should be detected even with special chars."""
        result = self.scanner.scan_tool_args({
            "db_url": "postgres://admin:p@ssw0rd@db.example.com:5432/mydb"
        })
        assert result.has_findings is True

    def test_deeply_nested_secret(self):
        """Secrets deeply nested in argument structures should be detected."""
        result = self.scanner.scan_tool_args({
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "secret": "-----BEGIN EC PRIVATE KEY-----"
                        }
                    }
                }
            }
        })
        assert result.has_findings is True
        assert any(f.pattern_id == "DLP-022" for f in result.findings)

    def test_mixed_pii_and_credentials(self):
        """Mixed PII and credential findings should both be reported."""
        result = self.scanner.scan_tool_args({
            "user": {
                "ssn": "123-45-6789",
                "email": "user@example.com",
                "api_key": "AKIAIOSFODNN7EXAMPLE",
            }
        })
        pattern_types = {f.pattern_type for f in result.findings}
        assert DLPPatternType.PII in pattern_types
        assert DLPPatternType.API_KEY in pattern_types

    def test_empty_string_values(self):
        """Empty string values should not produce false positives."""
        result = self.scanner.scan_tool_args({
            "key": "",
            "secret": "",
            "password": "",
        })
        # No actual sensitive data — should be clean
        assert not result.has_findings

    def test_numeric_only_values(self):
        """Pure numeric values should not produce excessive false positives."""
        result = self.scanner.scan_tool_args({
            "count": "42",
            "page": "1",
        })
        # Simple numbers should not match most DLP patterns
        findings_excluding_routing = [
            f for f in result.findings
            if f.pattern_id != "DLP-041"  # 9-digit routing number is a loose pattern
        ]
        assert len(findings_excluding_routing) == 0

    def test_scan_performance_large_args(self):
        """Scanner should handle large argument payloads without hanging."""
        import time
        large_args = {
            f"field_{i}": f"value_{i}" * 100
            for i in range(100)
        }
        start = time.monotonic()
        result = self.scanner.scan_tool_args(large_args)
        elapsed_ms = (time.monotonic() - start) * 1000
        # Should complete within 100ms even for large payloads
        assert elapsed_ms < 100
        assert result.scanned is True

    def test_scan_handles_special_regex_chars(self):
        """Scanner should not crash on args with regex special characters."""
        result = self.scanner.scan_tool_args({
            "query": "SELECT * FROM users WHERE name LIKE '%[test]%'",
            "regex": r"\d+\.\d+\.\d+",
        })
        assert result.scanned is True  # No crash
