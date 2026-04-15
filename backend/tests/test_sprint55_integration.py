"""Sprint 55 — Integration & Adversarial Tests.

APEP-438.f: Integration tests for ToolTrust → AgentPEP Intercept bridge.
APEP-442.b: Integration and adversarial tests for self-protection.
APEP-443.b: Integration and adversarial tests for ToolTrust bridge.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.models.camel_seq import (
    BridgeVerdictLevel,
    MarkerType,
    SelfProtectionAction,
    SelfProtectionCheckRequest,
    SessionMarker,
    ToolTrustBridgeRequest,
)
from tests.conftest import _get_auth_headers


# ===================================================================
# Helper
# ===================================================================


@pytest.fixture
def client(mock_mongodb):
    from app.main import app

    return TestClient(app, raise_server_exceptions=False)


def _h() -> dict[str, str]:
    """Shorthand for auth headers."""
    return _get_auth_headers()


# ===================================================================
# APEP-438.f: ToolTrust bridge integration tests
# ===================================================================


class TestToolTrustBridgeIntegration:
    """Integration tests for ToolTrust → AgentPEP bridge API endpoints."""

    def test_bridge_endpoint_clean(self, client):
        resp = client.post(
            "/v1/sprint55/bridge/tooltrust",
            json={
                "session_id": "int-s1",
                "tool_name": "file.read",
                "verdict": "CLEAN",
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] is True
        assert data["taint_applied"] is None
        assert data["intercept_decision"] == "ALLOW"

    def test_bridge_endpoint_suspicious(self, client):
        resp = client.post(
            "/v1/sprint55/bridge/tooltrust",
            json={
                "session_id": "int-s2",
                "tool_name": "file.write",
                "verdict": "SUSPICIOUS",
                "verdict_details": "Pattern match in output",
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["taint_applied"] == "UNTRUSTED"
        assert data["intercept_decision"] == "ESCALATE"

    def test_bridge_endpoint_malicious(self, client):
        resp = client.post(
            "/v1/sprint55/bridge/tooltrust",
            json={
                "session_id": "int-s3",
                "tool_name": "shell.exec",
                "verdict": "MALICIOUS",
                "findings": [{"rule_id": "INJ-042", "severity": "CRITICAL"}],
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["taint_applied"] == "QUARANTINE"
        assert data["intercept_decision"] == "DENY"

    def test_bridge_events_endpoint(self, client):
        # Submit a verdict first
        client.post(
            "/v1/sprint55/bridge/tooltrust",
            json={
                "session_id": "int-ev1",
                "tool_name": "file.read",
                "verdict": "SUSPICIOUS",
            },
            headers=_h(),
        )
        # Query events
        resp = client.get(
            "/v1/sprint55/bridge/tooltrust/events",
            params={"session_id": "int-ev1"},
            headers=_h(),
        )
        assert resp.status_code == 200
        events = resp.json()
        assert len(events) >= 1

    def test_bridge_invalid_verdict_rejected(self, client):
        resp = client.post(
            "/v1/sprint55/bridge/tooltrust",
            json={
                "session_id": "int-bad",
                "tool_name": "file.read",
                "verdict": "INVALID_VERDICT",
            },
            headers=_h(),
        )
        assert resp.status_code == 422

    def test_bridge_missing_session_id_rejected(self, client):
        resp = client.post(
            "/v1/sprint55/bridge/tooltrust",
            json={
                "tool_name": "file.read",
                "verdict": "CLEAN",
            },
            headers=_h(),
        )
        assert resp.status_code == 422

    def test_bridge_latency_under_50ms(self, client):
        """Bridge must add <50ms latency."""
        resp = client.post(
            "/v1/sprint55/bridge/tooltrust",
            json={
                "session_id": "int-perf",
                "tool_name": "file.read",
                "verdict": "CLEAN",
            },
            headers=_h(),
        )
        data = resp.json()
        assert data["bridge_latency_ms"] < 50


# ===================================================================
# CIS verdict taint integration tests
# ===================================================================


class TestCISVerdictTaintIntegration:
    """Integration tests for CIS verdict taint API."""

    def test_cis_verdict_clean(self, client):
        resp = client.post(
            "/v1/sprint55/cis-verdict/taint",
            json={
                "session_id": "cis-int1",
                "verdict": "CLEAN",
                "source_path": "README.md",
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["applied"] is False

    def test_cis_verdict_malicious(self, client):
        resp = client.post(
            "/v1/sprint55/cis-verdict/taint",
            json={
                "session_id": "cis-int2",
                "verdict": "MALICIOUS",
                "source_path": ".cursorrules",
                "findings_count": 5,
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["applied"] is True
        assert data["taint_level"] == "QUARANTINE"


# ===================================================================
# Session marker & SEQ rule integration tests
# ===================================================================


class TestSessionMarkerIntegration:
    """Integration tests for session markers and SEQ rule evaluation."""

    def test_list_markers_endpoint(self, client):
        resp = client.get(
            "/v1/sprint55/markers",
            params={"session_id": "mk-int1"},
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "markers" in data

    def test_evaluate_seq_rules_endpoint(self, client):
        resp = client.post(
            "/v1/sprint55/markers/evaluate",
            params={"session_id": "seq-int1"},
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "matches" in data

    def test_clear_markers_endpoint(self, client):
        resp = client.delete("/v1/sprint55/markers/mk-int-del", headers=_h())
        assert resp.status_code == 200
        data = resp.json()
        assert "deleted" in data


# ===================================================================
# SEQ rules listing endpoint
# ===================================================================


class TestSEQRulesListEndpoint:
    """Integration tests for the SEQ rules listing endpoint."""

    def test_list_seq_rules(self, client):
        resp = client.get("/v1/sprint55/seq-rules", headers=_h())
        assert resp.status_code == 200
        rules = resp.json()
        assert len(rules) == 5
        rule_ids = {r["pattern_id"] for r in rules}
        assert rule_ids == {"SEQ-001", "SEQ-002", "SEQ-003", "SEQ-004", "SEQ-005"}


# ===================================================================
# Protected path integration tests
# ===================================================================


class TestProtectedPathIntegration:
    """Integration tests for protected path guard API."""

    def test_list_protected_paths(self, client):
        resp = client.get("/v1/sprint55/protected-paths", headers=_h())
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 10

    def test_check_protected_path_denied(self, client):
        resp = client.post(
            "/v1/sprint55/protected-paths/check",
            params={"tool_name": "file.write", "path": "project/CLAUDE.md"},
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["blocked"] is True
        assert data["action"] == "DENY"

    def test_check_normal_path_allowed(self, client):
        resp = client.post(
            "/v1/sprint55/protected-paths/check",
            params={"tool_name": "file.write", "path": "src/main.py"},
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["blocked"] is False

    def test_add_custom_pattern(self, client):
        resp = client.post(
            "/v1/sprint55/protected-paths",
            json={
                "pattern_id": "PP-TEST-001",
                "path_glob": "**/my_secret.yaml",
                "description": "Test pattern",
                "action": "DENY",
                "applies_to_tools": ["file.write"],
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        # Verify it works
        check = client.post(
            "/v1/sprint55/protected-paths/check",
            params={"tool_name": "file.write", "path": "config/my_secret.yaml"},
            headers=_h(),
        )
        assert check.json()["blocked"] is True
        # Cleanup
        client.delete("/v1/sprint55/protected-paths/PP-TEST-001", headers=_h())

    def test_delete_builtin_fails(self, client):
        resp = client.delete("/v1/sprint55/protected-paths/PP-BUILTIN-001", headers=_h())
        assert resp.status_code == 404


# ===================================================================
# Self-protection integration tests
# ===================================================================


class TestSelfProtectionIntegration:
    """Integration tests for self-protection guard API."""

    def test_check_agent_blocked(self, client):
        resp = client.post(
            "/v1/sprint55/self-protection/check",
            json={
                "caller_type": "agent",
                "operation": "policy.create",
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is False

    def test_check_human_allowed(self, client):
        resp = client.post(
            "/v1/sprint55/self-protection/check",
            json={
                "caller_type": "human",
                "operation": "policy.create",
                "is_tty": True,
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is True

    def test_check_command_blocked(self, client):
        resp = client.post(
            "/v1/sprint55/self-protection/check-command",
            params={
                "command": "tooltrust allow file.write",
                "caller_type": "agent",
            },
            headers=_h(),
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is False

    def test_events_endpoint(self, client):
        # Trigger an event
        client.post(
            "/v1/sprint55/self-protection/check",
            json={
                "caller_type": "agent",
                "operation": "policy.delete",
            },
            headers=_h(),
        )
        resp = client.get(
            "/v1/sprint55/self-protection/events",
            params={"blocked_only": True},
            headers=_h(),
        )
        assert resp.status_code == 200


# ===================================================================
# APEP-442.b: Self-protection adversarial tests
# ===================================================================


class TestSelfProtectionAdversarial:
    """Adversarial tests ensuring 0 agent-initiated policy modifications succeed.

    These tests simulate various attack vectors an agent might use to
    bypass self-protection and modify policies.
    """

    def test_agent_cannot_create_policy(self):
        """Direct agent policy creation must be blocked."""
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="policy.create",
            api_key_id="agent-key-001",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False
        assert resp.action == SelfProtectionAction.BLOCK

    def test_agent_cannot_update_policy(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="policy.update",
            api_key_id="agent-key-002",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_agent_cannot_delete_policy(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="policy.delete",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_agent_cannot_modify_rules(self):
        from app.services.self_protection import self_protection_guard

        for op in ("rule.create", "rule.update", "rule.delete"):
            req = SelfProtectionCheckRequest(
                caller_type="agent", operation=op,
            )
            resp = self_protection_guard.check(req)
            assert resp.allowed is False, f"Agent must be blocked from {op}"

    def test_agent_cannot_modify_roles(self):
        from app.services.self_protection import self_protection_guard

        for op in ("role.create", "role.update", "role.delete"):
            req = SelfProtectionCheckRequest(
                caller_type="agent", operation=op,
            )
            resp = self_protection_guard.check(req)
            assert resp.allowed is False, f"Agent must be blocked from {op}"

    def test_agent_cannot_modify_config(self):
        from app.services.self_protection import self_protection_guard

        for op in ("config.modify", "config.security.modify"):
            req = SelfProtectionCheckRequest(
                caller_type="agent", operation=op,
            )
            resp = self_protection_guard.check(req)
            assert resp.allowed is False

    def test_agent_cannot_modify_allowlist(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="allowlist.modify",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_agent_cannot_disable_self_protection(self):
        """Agent must not be able to disable the self-protection mechanism itself."""
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="self_protection.disable",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_agent_cannot_deactivate_kill_switch(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="kill_switch.deactivate",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_agent_api_key_non_tty_blocked(self):
        """API key without TTY must be blocked from policy modification."""
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="api_key",
            api_key_id="automated-key-001",
            operation="policy.create",
            is_tty=False,
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_agent_tooltrust_allow_command_blocked(self):
        """Agent must not be able to run 'tooltrust allow' commands."""
        from app.services.self_protection import self_protection_guard

        commands = [
            "tooltrust allow file.write",
            "TOOLTRUST ALLOW shell.exec",
            "tooltrust   allow  http.post",
        ]
        for cmd in commands:
            resp = self_protection_guard.check_command(cmd, "agent")
            assert resp.allowed is False, f"Command '{cmd}' must be blocked for agent"

    def test_agent_agentpep_policy_command_blocked(self):
        from app.services.self_protection import self_protection_guard

        commands = [
            "agentpep policy create --name evil",
            "agentpep policy update --id abc123",
            "agentpep policy delete --id abc123",
            "agentpep policy modify --file new.yaml",
            "agentpep rule create --name bypass",
            "agentpep rule update --id abc",
            "agentpep rule delete --id abc",
            "agentpep config set evil_mode=true",
            "agentpep allowlist add malicious.com",
            "agentpep allowlist remove safe.com",
            "agentpep allowlist clear",
        ]
        for cmd in commands:
            resp = self_protection_guard.check_command(cmd, "agent")
            assert resp.allowed is False, f"Command '{cmd}' must be blocked for agent"

    def test_all_protected_ops_blocked_for_agent(self):
        """Exhaustive test: every protected operation blocked for agents."""
        from app.services.self_protection import (
            _PROTECTED_OPERATIONS,
            self_protection_guard,
        )

        for op in _PROTECTED_OPERATIONS:
            req = SelfProtectionCheckRequest(
                caller_type="agent", operation=op,
            )
            resp = self_protection_guard.check(req)
            assert resp.allowed is False, (
                f"SECURITY VIOLATION: agent allowed to perform '{op}'"
            )

    def test_bypass_rate_zero(self):
        """Meta-test: verify that exactly 0 agent-initiated modifications succeed.

        This is the key success metric from the PRD (APEP-442).
        """
        from app.services.self_protection import (
            _PROTECTED_OPERATIONS,
            self_protection_guard,
        )

        successes = 0
        total = 0
        for op in _PROTECTED_OPERATIONS:
            req = SelfProtectionCheckRequest(
                caller_type="agent", operation=op,
            )
            resp = self_protection_guard.check(req)
            total += 1
            if resp.allowed:
                successes += 1

        assert successes == 0, (
            f"SECURITY FAILURE: {successes}/{total} agent policy modifications succeeded"
        )


# ===================================================================
# APEP-443.b: ToolTrust bridge integration & adversarial tests
# ===================================================================


class TestToolTrustBridgeAdversarial:
    """Integration and adversarial tests for the ToolTrust bridge."""

    @pytest.mark.asyncio
    async def test_malicious_verdict_applies_quarantine(self, mock_mongodb):
        """MALICIOUS verdict must apply QUARANTINE taint."""
        from app.services.tooltrust_bridge import tooltrust_bridge

        req = ToolTrustBridgeRequest(
            session_id="adv-bridge-1",
            tool_name="shell.exec",
            verdict=BridgeVerdictLevel.MALICIOUS,
        )
        resp = await tooltrust_bridge.process_verdict(req)
        assert resp.taint_applied == "QUARANTINE"
        assert resp.intercept_decision == "DENY"

    @pytest.mark.asyncio
    async def test_suspicious_verdict_applies_untrusted(self, mock_mongodb):
        from app.services.tooltrust_bridge import tooltrust_bridge

        req = ToolTrustBridgeRequest(
            session_id="adv-bridge-2",
            tool_name="file.write",
            verdict=BridgeVerdictLevel.SUSPICIOUS,
        )
        resp = await tooltrust_bridge.process_verdict(req)
        assert resp.taint_applied == "UNTRUSTED"
        assert resp.intercept_decision == "ESCALATE"

    @pytest.mark.asyncio
    async def test_clean_verdict_no_taint_no_block(self, mock_mongodb):
        from app.services.tooltrust_bridge import tooltrust_bridge

        req = ToolTrustBridgeRequest(
            session_id="adv-bridge-3",
            tool_name="file.read",
            verdict=BridgeVerdictLevel.CLEAN,
        )
        resp = await tooltrust_bridge.process_verdict(req)
        assert resp.taint_applied is None
        assert resp.intercept_decision == "ALLOW"

    @pytest.mark.asyncio
    async def test_bridge_records_all_events(self, mock_mongodb):
        """All bridge events must be recorded for audit."""
        from app.services.tooltrust_bridge import tooltrust_bridge

        for verdict in (
            BridgeVerdictLevel.CLEAN,
            BridgeVerdictLevel.SUSPICIOUS,
            BridgeVerdictLevel.MALICIOUS,
        ):
            req = ToolTrustBridgeRequest(
                session_id="adv-bridge-audit",
                tool_name="test.tool",
                verdict=verdict,
            )
            await tooltrust_bridge.process_verdict(req)

        events = await tooltrust_bridge.get_bridge_events("adv-bridge-audit")
        assert len(events) == 3

    @pytest.mark.asyncio
    async def test_bridge_handles_findings_metadata(self, mock_mongodb):
        """Bridge must accept and store scan findings from ToolTrust."""
        from app.services.tooltrust_bridge import tooltrust_bridge

        req = ToolTrustBridgeRequest(
            session_id="adv-bridge-findings",
            tool_name="file.write",
            verdict=BridgeVerdictLevel.MALICIOUS,
            findings=[
                {"rule_id": "INJ-001", "severity": "CRITICAL", "matched_text": "ignore previous"},
                {"rule_id": "INJ-042", "severity": "HIGH", "matched_text": "system override"},
            ],
            scan_latency_ms=12,
            layer=3,
            trust_cache_hit=False,
        )
        resp = await tooltrust_bridge.process_verdict(req)
        assert resp.accepted is True

        events = await tooltrust_bridge.get_bridge_events("adv-bridge-findings")
        assert len(events) >= 1
        assert events[0]["findings_count"] == 2

    @pytest.mark.asyncio
    async def test_bridge_with_trust_cache_hit(self, mock_mongodb):
        """Bridge must handle trust cache hit flag."""
        from app.services.tooltrust_bridge import tooltrust_bridge

        req = ToolTrustBridgeRequest(
            session_id="adv-bridge-cache",
            tool_name="file.read",
            verdict=BridgeVerdictLevel.CLEAN,
            trust_cache_hit=True,
        )
        resp = await tooltrust_bridge.process_verdict(req)
        assert resp.accepted is True

        events = await tooltrust_bridge.get_bridge_events("adv-bridge-cache")
        assert events[0]["trust_cache_hit"] is True


# ===================================================================
# End-to-end integration: SEQ rules with markers
# ===================================================================


class TestSEQEndToEnd:
    """End-to-end integration tests for marker placement + SEQ evaluation."""

    @pytest.mark.asyncio
    async def test_file_read_then_http_triggers_seq001(self, mock_mongodb):
        """Full pipeline: place markers, evaluate, detect SEQ-001."""
        from app.services.camel_seq_rules import evaluate_seq_markers
        from app.services.session_marker_service import session_marker_service

        sid = "e2e-seq001"

        # Simulate tool calls placing markers
        await session_marker_service.place_markers_for_tool(
            session_id=sid, tool_name="file.read", agent_id="bot",
        )
        await session_marker_service.place_markers_for_tool(
            session_id=sid, tool_name="http.post", agent_id="bot",
        )

        # Evaluate
        markers = await session_marker_service.get_ordered_markers(sid)
        result = await evaluate_seq_markers(sid, markers)
        assert result.has_enforcing_match is True

    @pytest.mark.asyncio
    async def test_config_read_write_triggers_seq003(self, mock_mongodb):
        from app.services.camel_seq_rules import evaluate_seq_markers
        from app.services.session_marker_service import session_marker_service

        sid = "e2e-seq003"

        await session_marker_service.place_markers_for_tool(
            session_id=sid, tool_name="config.read", agent_id="bot",
        )
        await session_marker_service.place_markers_for_tool(
            session_id=sid, tool_name="config.write", agent_id="bot",
        )

        markers = await session_marker_service.get_ordered_markers(sid)
        result = await evaluate_seq_markers(sid, markers)
        assert result.total_matches >= 1
        # SEQ-003 is advisory
        assert any(
            m.rule_id.value == "SEQ-003" and m.mode.value == "ADVISORY"
            for m in result.matches
        )

    @pytest.mark.asyncio
    async def test_benign_only_no_match(self, mock_mongodb):
        """Only benign tool calls should not trigger any SEQ rule."""
        from app.services.camel_seq_rules import evaluate_seq_markers
        from app.services.session_marker_service import session_marker_service

        sid = "e2e-benign"
        await session_marker_service.place_markers_for_tool(
            session_id=sid, tool_name="file.read", agent_id="bot",
        )
        await session_marker_service.place_markers_for_tool(
            session_id=sid, tool_name="file.write", agent_id="bot",
        )

        markers = await session_marker_service.get_ordered_markers(sid)
        result = await evaluate_seq_markers(sid, markers)
        # file.read + file.write should NOT trigger any exfil rule
        assert result.has_enforcing_match is False
