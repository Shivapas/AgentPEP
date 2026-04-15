"""Sprint 55 — Unit & Component Tests for CaMeL SEQ Rules, Session Markers,
ToolTrust Bridge, CIS Verdict Taint, Self-Protection & Protected Paths.

APEP-436.e: Security validation tests for CaMeL-lite SEQ rules.
APEP-437.e: Unit tests for session-wide typed marker system.
APEP-438.e: Unit tests for ToolTrust → AgentPEP Intercept bridge.
APEP-439.e: Unit tests for CIS scan verdict as taint input.
APEP-440.e: Security validation tests for self-protection.
APEP-441.c: Security tests for protected path patterns.
APEP-442.a: Unit and component tests for self-protection adversarial tests.
APEP-443.a: Unit and component tests for ToolTrust bridge integration.
"""

from __future__ import annotations

import pytest

from app.models.camel_seq import (
    BridgeVerdictLevel,
    CISVerdictTaintRequest,
    MarkerType,
    ProtectedPathAction,
    ProtectedPathPattern,
    SEQRuleID,
    SEQRuleMode,
    SelfProtectionAction,
    SelfProtectionCheckRequest,
    SessionMarker,
    ToolTrustBridgeRequest,
)


# ===================================================================
# APEP-436.e: CaMeL-lite SEQ rules tests
# ===================================================================


class TestCamelSEQPatterns:
    """Validate that 5 CaMeL-lite SEQ rules are registered correctly."""

    def test_seq_patterns_registered_in_library(self):
        """All 5 SEQ patterns must be present in the chain pattern library."""
        from app.services.chain_pattern_library import chain_pattern_library

        enabled = chain_pattern_library.get_all_enabled()
        seq_ids = {p.pattern_id for p in enabled if p.pattern_id.startswith("SEQ-")}
        assert seq_ids == {"SEQ-001", "SEQ-002", "SEQ-003", "SEQ-004", "SEQ-005"}

    def test_seq_patterns_are_builtin(self):
        """SEQ patterns must be marked as built-in (cannot be deleted via API)."""
        from app.services.chain_pattern_library import chain_pattern_library

        for p in chain_pattern_library.builtin_patterns:
            if p.pattern_id.startswith("SEQ-"):
                assert p.builtin is True, f"{p.pattern_id} must be built-in"

    def test_seq_001_002_are_enforcing(self):
        """SEQ-001 and SEQ-002 must use DENY action (enforcing)."""
        from app.services.camel_seq_rules import CAMEL_SEQ_PATTERNS

        for p in CAMEL_SEQ_PATTERNS:
            if p.pattern_id in ("SEQ-001", "SEQ-002"):
                assert p.action.value == "DENY", (
                    f"{p.pattern_id} must be DENY (enforcing)"
                )

    def test_seq_003_004_are_advisory(self):
        """SEQ-003 and SEQ-004 must use ALERT action (advisory)."""
        from app.services.camel_seq_rules import CAMEL_SEQ_PATTERNS

        for p in CAMEL_SEQ_PATTERNS:
            if p.pattern_id in ("SEQ-003", "SEQ-004"):
                assert p.action.value == "ALERT", (
                    f"{p.pattern_id} must be ALERT (advisory)"
                )

    def test_seq_005_is_config_write_enforcement(self):
        """SEQ-005 must use ESCALATE action (config-write enforcement)."""
        from app.services.camel_seq_rules import CAMEL_SEQ_PATTERNS

        for p in CAMEL_SEQ_PATTERNS:
            if p.pattern_id == "SEQ-005":
                assert p.action.value == "ESCALATE"

    def test_seq_patterns_integrity_hash(self):
        """SEQ patterns must have valid integrity hashes."""
        from app.services.chain_pattern_library import (
            chain_pattern_library,
            compute_pattern_integrity_hash,
        )

        for p in chain_pattern_library.builtin_patterns:
            if p.pattern_id.startswith("SEQ-"):
                expected = chain_pattern_library._builtin_hashes.get(p.pattern_id)
                actual = compute_pattern_integrity_hash(p)
                assert expected == actual, (
                    f"Integrity hash mismatch for {p.pattern_id}"
                )

    def test_seq_patterns_gap_tolerant_window(self):
        """SEQ-001/002 must have large window_seconds for gap tolerance."""
        from app.services.camel_seq_rules import CAMEL_SEQ_PATTERNS

        for p in CAMEL_SEQ_PATTERNS:
            if p.pattern_id in ("SEQ-001", "SEQ-002"):
                assert p.window_seconds >= 1800, (
                    f"{p.pattern_id} window_seconds must be >= 1800 for gap tolerance"
                )

    def test_seq_patterns_have_mitre_ids(self):
        """All SEQ patterns must have MITRE ATT&CK technique IDs."""
        from app.services.camel_seq_rules import CAMEL_SEQ_PATTERNS

        for p in CAMEL_SEQ_PATTERNS:
            assert p.mitre_technique_id, (
                f"{p.pattern_id} must have a MITRE technique ID"
            )

    def test_seq_mode_map_complete(self):
        """Every SEQ rule must have an enforcement mode in the mode map."""
        from app.services.camel_seq_rules import _SEQ_MODES, CAMEL_SEQ_PATTERNS

        for p in CAMEL_SEQ_PATTERNS:
            assert p.pattern_id in _SEQ_MODES, (
                f"{p.pattern_id} missing from _SEQ_MODES"
            )

    def test_seq_marker_requirements_complete(self):
        """Every SEQ rule must have marker requirements defined."""
        from app.services.camel_seq_rules import (
            _SEQ_MARKER_REQUIREMENTS,
            CAMEL_SEQ_PATTERNS,
        )

        for p in CAMEL_SEQ_PATTERNS:
            assert p.pattern_id in _SEQ_MARKER_REQUIREMENTS, (
                f"{p.pattern_id} missing from _SEQ_MARKER_REQUIREMENTS"
            )
            assert len(_SEQ_MARKER_REQUIREMENTS[p.pattern_id]) >= 2, (
                f"{p.pattern_id} must require at least 2 marker types"
            )


# ===================================================================
# APEP-437.e: Session-wide typed marker system tests
# ===================================================================


class TestSessionMarkerService:
    """Tests for session marker classification and persistence."""

    def test_classify_file_read(self):
        from app.services.session_marker_service import session_marker_service

        types = session_marker_service.classify_tool("file.read")
        assert MarkerType.FILE_READ in types

    def test_classify_http_post(self):
        from app.services.session_marker_service import session_marker_service

        types = session_marker_service.classify_tool("http.post")
        assert MarkerType.EXTERNAL_HTTP in types

    def test_classify_secret_access(self):
        from app.services.session_marker_service import session_marker_service

        types = session_marker_service.classify_tool("secret.get")
        assert MarkerType.SECRET_ACCESS in types

    def test_classify_shell_exec(self):
        from app.services.session_marker_service import session_marker_service

        types = session_marker_service.classify_tool("shell.exec")
        assert MarkerType.SHELL_EXEC in types

    def test_classify_config_read(self):
        from app.services.session_marker_service import session_marker_service

        types = session_marker_service.classify_tool("config.read")
        assert MarkerType.CONFIG_READ in types

    def test_classify_config_write(self):
        from app.services.session_marker_service import session_marker_service

        types = session_marker_service.classify_tool("config.write")
        assert MarkerType.CONFIG_WRITE in types

    def test_classify_env_read(self):
        from app.services.session_marker_service import session_marker_service

        types = session_marker_service.classify_tool("env.read")
        assert MarkerType.ENV_READ in types

    def test_classify_dns(self):
        from app.services.session_marker_service import session_marker_service

        types = session_marker_service.classify_tool("dns.lookup")
        assert MarkerType.DNS_EXFIL in types

    def test_classify_unknown_tool_returns_empty(self):
        from app.services.session_marker_service import session_marker_service

        types = session_marker_service.classify_tool("unknown.foobar")
        assert types == []

    @pytest.mark.asyncio
    async def test_place_marker(self, mock_mongodb):
        from app.services.session_marker_service import session_marker_service

        marker = await session_marker_service.place_marker(
            session_id="test-session",
            marker_type=MarkerType.FILE_READ,
            tool_name="file.read",
            agent_id="test-agent",
        )
        assert marker.session_id == "test-session"
        assert marker.marker_type == MarkerType.FILE_READ
        assert marker.marker_id.startswith("MK-")

    @pytest.mark.asyncio
    async def test_place_markers_for_tool(self, mock_mongodb):
        from app.services.session_marker_service import session_marker_service

        markers = await session_marker_service.place_markers_for_tool(
            session_id="test-session",
            tool_name="http.post",
            agent_id="test-agent",
        )
        assert len(markers) >= 1
        assert any(m.marker_type == MarkerType.EXTERNAL_HTTP for m in markers)

    @pytest.mark.asyncio
    async def test_get_markers(self, mock_mongodb):
        from app.services.session_marker_service import session_marker_service

        await session_marker_service.place_marker(
            session_id="s1", marker_type=MarkerType.FILE_READ, tool_name="file.read",
        )
        await session_marker_service.place_marker(
            session_id="s1", marker_type=MarkerType.EXTERNAL_HTTP, tool_name="http.post",
        )

        query = __import__(
            "app.models.camel_seq", fromlist=["SessionMarkerQuery"]
        ).SessionMarkerQuery(session_id="s1")
        resp = await session_marker_service.get_markers(query)
        assert resp.total == 2

    @pytest.mark.asyncio
    async def test_has_marker_types(self, mock_mongodb):
        from app.services.session_marker_service import session_marker_service

        await session_marker_service.place_marker(
            session_id="s2", marker_type=MarkerType.FILE_READ, tool_name="file.read",
        )
        result = await session_marker_service.has_marker_types(
            "s2", [MarkerType.FILE_READ, MarkerType.EXTERNAL_HTTP]
        )
        assert result[MarkerType.FILE_READ] is True
        assert result[MarkerType.EXTERNAL_HTTP] is False

    @pytest.mark.asyncio
    async def test_clear_session(self, mock_mongodb):
        from app.services.session_marker_service import session_marker_service

        await session_marker_service.place_marker(
            session_id="s3", marker_type=MarkerType.FILE_READ, tool_name="file.read",
        )
        count = await session_marker_service.clear_session("s3")
        assert count == 1


# ===================================================================
# SEQ marker-based evaluation tests
# ===================================================================


class TestSEQMarkerEvaluation:
    """Test CaMeL-lite SEQ rule evaluation against session markers."""

    @pytest.mark.asyncio
    async def test_seq_001_file_read_to_http(self):
        """SEQ-001: file.read → http.post should trigger ENFORCING match."""
        from datetime import UTC, datetime, timedelta

        from app.services.camel_seq_rules import evaluate_seq_markers

        now = datetime.now(UTC)
        markers = [
            SessionMarker(
                session_id="s-seq1",
                marker_type=MarkerType.FILE_READ,
                tool_name="file.read",
                created_at=now,
            ),
            SessionMarker(
                session_id="s-seq1",
                marker_type=MarkerType.EXTERNAL_HTTP,
                tool_name="http.post",
                created_at=now + timedelta(seconds=10),
            ),
        ]
        result = await evaluate_seq_markers("s-seq1", markers)
        assert result.total_matches >= 1
        assert result.has_enforcing_match is True

        seq001_match = next(
            (m for m in result.matches if m.rule_id == SEQRuleID.SEQ_001), None
        )
        assert seq001_match is not None
        assert seq001_match.mode == SEQRuleMode.ENFORCING

    @pytest.mark.asyncio
    async def test_seq_002_file_read_to_dns(self):
        """SEQ-002: file.read → dns should trigger ENFORCING match."""
        from datetime import UTC, datetime, timedelta

        from app.services.camel_seq_rules import evaluate_seq_markers

        now = datetime.now(UTC)
        markers = [
            SessionMarker(
                session_id="s-seq2",
                marker_type=MarkerType.FILE_READ,
                tool_name="db.read",
                created_at=now,
            ),
            SessionMarker(
                session_id="s-seq2",
                marker_type=MarkerType.DNS_EXFIL,
                tool_name="dns.lookup",
                created_at=now + timedelta(seconds=30),
            ),
        ]
        result = await evaluate_seq_markers("s-seq2", markers)
        assert result.has_enforcing_match is True

    @pytest.mark.asyncio
    async def test_seq_003_config_read_write_advisory(self):
        """SEQ-003: config.read → config.write should trigger ADVISORY match."""
        from datetime import UTC, datetime, timedelta

        from app.services.camel_seq_rules import evaluate_seq_markers

        now = datetime.now(UTC)
        markers = [
            SessionMarker(
                session_id="s-seq3",
                marker_type=MarkerType.CONFIG_READ,
                tool_name="config.read",
                created_at=now,
            ),
            SessionMarker(
                session_id="s-seq3",
                marker_type=MarkerType.CONFIG_WRITE,
                tool_name="config.write",
                created_at=now + timedelta(seconds=5),
            ),
        ]
        result = await evaluate_seq_markers("s-seq3", markers)
        assert result.total_matches >= 1
        # SEQ-003 is advisory — should NOT have enforcing match
        seq003 = next(
            (m for m in result.matches if m.rule_id == SEQRuleID.SEQ_003), None
        )
        assert seq003 is not None
        assert seq003.mode == SEQRuleMode.ADVISORY

    @pytest.mark.asyncio
    async def test_seq_004_secret_to_shell_advisory(self):
        """SEQ-004: secret.* → shell.exec should trigger ADVISORY match."""
        from datetime import UTC, datetime, timedelta

        from app.services.camel_seq_rules import evaluate_seq_markers

        now = datetime.now(UTC)
        markers = [
            SessionMarker(
                session_id="s-seq4",
                marker_type=MarkerType.SECRET_ACCESS,
                tool_name="secret.get",
                created_at=now,
            ),
            SessionMarker(
                session_id="s-seq4",
                marker_type=MarkerType.SHELL_EXEC,
                tool_name="shell.exec",
                created_at=now + timedelta(seconds=5),
            ),
        ]
        result = await evaluate_seq_markers("s-seq4", markers)
        seq004 = next(
            (m for m in result.matches if m.rule_id == SEQRuleID.SEQ_004), None
        )
        assert seq004 is not None
        assert seq004.mode == SEQRuleMode.ADVISORY

    @pytest.mark.asyncio
    async def test_seq_005_env_to_config_write(self):
        """SEQ-005: env.* → config.write should trigger ENFORCING match."""
        from datetime import UTC, datetime, timedelta

        from app.services.camel_seq_rules import evaluate_seq_markers

        now = datetime.now(UTC)
        markers = [
            SessionMarker(
                session_id="s-seq5",
                marker_type=MarkerType.ENV_READ,
                tool_name="env.get",
                created_at=now,
            ),
            SessionMarker(
                session_id="s-seq5",
                marker_type=MarkerType.CONFIG_WRITE,
                tool_name="config.write",
                created_at=now + timedelta(seconds=5),
            ),
        ]
        result = await evaluate_seq_markers("s-seq5", markers)
        assert result.has_enforcing_match is True

    @pytest.mark.asyncio
    async def test_gap_tolerance_benign_events_between(self):
        """Gap tolerance: benign events between markers should not evade detection."""
        from datetime import UTC, datetime, timedelta

        from app.services.camel_seq_rules import evaluate_seq_markers

        now = datetime.now(UTC)
        markers = [
            SessionMarker(
                session_id="s-gap",
                marker_type=MarkerType.FILE_READ,
                tool_name="file.read",
                created_at=now,
            ),
            # Benign gap events
            SessionMarker(
                session_id="s-gap",
                marker_type=MarkerType.FILE_WRITE,
                tool_name="file.write",
                created_at=now + timedelta(seconds=5),
            ),
            SessionMarker(
                session_id="s-gap",
                marker_type=MarkerType.SHELL_EXEC,
                tool_name="shell.exec",
                created_at=now + timedelta(seconds=10),
            ),
            # The exfil event after benign padding
            SessionMarker(
                session_id="s-gap",
                marker_type=MarkerType.EXTERNAL_HTTP,
                tool_name="http.post",
                created_at=now + timedelta(seconds=60),
            ),
        ]
        result = await evaluate_seq_markers("s-gap", markers)
        assert result.has_enforcing_match is True
        seq001 = next(
            (m for m in result.matches if m.rule_id == SEQRuleID.SEQ_001), None
        )
        assert seq001 is not None
        assert seq001.gap_count > 0  # Gaps were detected but rule still triggered

    @pytest.mark.asyncio
    async def test_no_match_when_markers_reversed(self):
        """Reversed order should not trigger SEQ rules."""
        from datetime import UTC, datetime, timedelta

        from app.services.camel_seq_rules import evaluate_seq_markers

        now = datetime.now(UTC)
        markers = [
            SessionMarker(
                session_id="s-rev",
                marker_type=MarkerType.EXTERNAL_HTTP,
                tool_name="http.post",
                created_at=now,
            ),
            SessionMarker(
                session_id="s-rev",
                marker_type=MarkerType.FILE_READ,
                tool_name="file.read",
                created_at=now + timedelta(seconds=10),
            ),
        ]
        result = await evaluate_seq_markers("s-rev", markers)
        # SEQ-001 requires FILE_READ before EXTERNAL_HTTP
        seq001 = next(
            (m for m in result.matches if m.rule_id == SEQRuleID.SEQ_001), None
        )
        assert seq001 is None

    @pytest.mark.asyncio
    async def test_no_match_on_empty_markers(self):
        from app.services.camel_seq_rules import evaluate_seq_markers

        result = await evaluate_seq_markers("s-empty", [])
        assert result.total_matches == 0
        assert result.has_enforcing_match is False


# ===================================================================
# APEP-438.e: ToolTrust → AgentPEP Intercept bridge tests
# ===================================================================


class TestToolTrustBridge:
    """Unit tests for the ToolTrust bridge service."""

    @pytest.mark.asyncio
    async def test_clean_verdict_no_taint(self, mock_mongodb):
        from app.services.tooltrust_bridge import tooltrust_bridge

        req = ToolTrustBridgeRequest(
            session_id="bridge-s1",
            tool_name="file.read",
            verdict=BridgeVerdictLevel.CLEAN,
        )
        resp = await tooltrust_bridge.process_verdict(req)
        assert resp.accepted is True
        assert resp.taint_applied is None
        assert resp.intercept_decision == "ALLOW"

    @pytest.mark.asyncio
    async def test_suspicious_verdict_untrusted(self, mock_mongodb):
        from app.services.tooltrust_bridge import tooltrust_bridge

        req = ToolTrustBridgeRequest(
            session_id="bridge-s2",
            tool_name="file.write",
            verdict=BridgeVerdictLevel.SUSPICIOUS,
            verdict_details="Possible injection pattern",
        )
        resp = await tooltrust_bridge.process_verdict(req)
        assert resp.accepted is True
        assert resp.taint_applied == "UNTRUSTED"
        assert resp.intercept_decision == "ESCALATE"

    @pytest.mark.asyncio
    async def test_malicious_verdict_quarantine(self, mock_mongodb):
        from app.services.tooltrust_bridge import tooltrust_bridge

        req = ToolTrustBridgeRequest(
            session_id="bridge-s3",
            tool_name="shell.exec",
            verdict=BridgeVerdictLevel.MALICIOUS,
            verdict_details="Confirmed injection payload",
            findings=[{"rule_id": "INJ-001", "severity": "CRITICAL"}],
        )
        resp = await tooltrust_bridge.process_verdict(req)
        assert resp.accepted is True
        assert resp.taint_applied == "QUARANTINE"
        assert resp.intercept_decision == "DENY"

    @pytest.mark.asyncio
    async def test_bridge_event_recorded(self, mock_mongodb):
        from app.services.tooltrust_bridge import tooltrust_bridge

        req = ToolTrustBridgeRequest(
            session_id="bridge-s4",
            tool_name="http.post",
            verdict=BridgeVerdictLevel.SUSPICIOUS,
        )
        await tooltrust_bridge.process_verdict(req)
        events = await tooltrust_bridge.get_bridge_events("bridge-s4")
        assert len(events) >= 1
        assert events[0]["verdict"] == "SUSPICIOUS"

    @pytest.mark.asyncio
    async def test_bridge_latency_tracked(self, mock_mongodb):
        from app.services.tooltrust_bridge import tooltrust_bridge

        req = ToolTrustBridgeRequest(
            session_id="bridge-s5",
            tool_name="file.read",
            verdict=BridgeVerdictLevel.CLEAN,
            scan_latency_ms=15,
        )
        resp = await tooltrust_bridge.process_verdict(req)
        assert resp.bridge_latency_ms >= 0


# ===================================================================
# APEP-439.e: CIS scan verdict as taint input tests
# ===================================================================


class TestCISVerdictTaint:
    """Unit tests for CIS verdict taint service."""

    @pytest.mark.asyncio
    async def test_clean_verdict_no_taint(self, mock_mongodb):
        from app.services.cis_verdict_taint import cis_verdict_taint_service

        req = CISVerdictTaintRequest(
            session_id="cis-s1",
            verdict=BridgeVerdictLevel.CLEAN,
            source_path="README.md",
        )
        resp = await cis_verdict_taint_service.apply_verdict(req)
        assert resp.applied is False
        assert resp.taint_level is None

    @pytest.mark.asyncio
    async def test_suspicious_verdict_untrusted(self, mock_mongodb):
        from app.services.cis_verdict_taint import cis_verdict_taint_service

        req = CISVerdictTaintRequest(
            session_id="cis-s2",
            verdict=BridgeVerdictLevel.SUSPICIOUS,
            source_path="CLAUDE.md",
            findings_count=3,
        )
        resp = await cis_verdict_taint_service.apply_verdict(req)
        assert resp.applied is True
        assert resp.taint_level == "UNTRUSTED"

    @pytest.mark.asyncio
    async def test_malicious_verdict_quarantine(self, mock_mongodb):
        from app.services.cis_verdict_taint import cis_verdict_taint_service

        req = CISVerdictTaintRequest(
            session_id="cis-s3",
            verdict=BridgeVerdictLevel.MALICIOUS,
            source_path=".cursorrules",
            findings_count=5,
        )
        resp = await cis_verdict_taint_service.apply_verdict(req)
        assert resp.applied is True
        assert resp.taint_level == "QUARANTINE"

    @pytest.mark.asyncio
    async def test_auto_taint_disabled(self, mock_mongodb):
        from app.services.cis_verdict_taint import cis_verdict_taint_service

        req = CISVerdictTaintRequest(
            session_id="cis-s4",
            verdict=BridgeVerdictLevel.MALICIOUS,
            auto_taint=False,
        )
        resp = await cis_verdict_taint_service.apply_verdict(req)
        assert resp.applied is False

    @pytest.mark.asyncio
    async def test_verdict_event_recorded(self, mock_mongodb):
        from app.services.cis_verdict_taint import cis_verdict_taint_service

        req = CISVerdictTaintRequest(
            session_id="cis-s5",
            verdict=BridgeVerdictLevel.SUSPICIOUS,
            scan_result_id="scan-123",
        )
        await cis_verdict_taint_service.apply_verdict(req)
        events = await cis_verdict_taint_service.get_verdict_events("cis-s5")
        assert len(events) >= 1
        assert events[0]["verdict"] == "SUSPICIOUS"


# ===================================================================
# APEP-440.e: Self-protection security validation tests
# ===================================================================


class TestSelfProtection:
    """Security validation tests for agent-initiated policy modification self-protection."""

    def test_agent_blocked_from_policy_create(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="policy.create",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False
        assert resp.action == SelfProtectionAction.BLOCK

    def test_agent_blocked_from_policy_update(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="policy.update",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_agent_blocked_from_policy_delete(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="policy.delete",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_agent_blocked_from_rule_modify(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="rule.update",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_agent_blocked_from_config_modify(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="config.modify",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_agent_blocked_from_self_protection_disable(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="self_protection.disable",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_agent_blocked_from_kill_switch_deactivate(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="kill_switch.deactivate",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_human_tty_allowed(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="human",
            operation="policy.create",
            is_tty=True,
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is True

    def test_human_non_tty_warned(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="human",
            operation="policy.update",
            is_tty=False,
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is True
        assert resp.action == SelfProtectionAction.WARN

    def test_api_key_non_tty_blocked(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="api_key",
            operation="policy.delete",
            is_tty=False,
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is False

    def test_non_protected_operation_allowed(self):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="data.read",
        )
        resp = self_protection_guard.check(req)
        assert resp.allowed is True

    def test_hook_command_tooltrust_allow_blocked(self):
        from app.services.self_protection import self_protection_guard

        resp = self_protection_guard.check_command(
            "tooltrust allow file.write", "agent"
        )
        assert resp.allowed is False
        assert resp.guard_name == "hook_command_guard"

    def test_hook_command_agentpep_policy_blocked(self):
        from app.services.self_protection import self_protection_guard

        resp = self_protection_guard.check_command(
            "agentpep policy create --name test", "agent"
        )
        assert resp.allowed is False

    def test_hook_command_human_allowed(self):
        from app.services.self_protection import self_protection_guard

        resp = self_protection_guard.check_command(
            "tooltrust allow file.write", "human"
        )
        assert resp.allowed is True

    @pytest.mark.asyncio
    async def test_audit_event_recorded(self, mock_mongodb):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent",
            operation="policy.delete",
        )
        resp = self_protection_guard.check(req)
        event = await self_protection_guard.audit_event(req, resp)
        assert event.action_taken == SelfProtectionAction.BLOCK

    @pytest.mark.asyncio
    async def test_get_events(self, mock_mongodb):
        from app.services.self_protection import self_protection_guard

        req = SelfProtectionCheckRequest(
            caller_type="agent", operation="policy.create"
        )
        resp = self_protection_guard.check(req)
        await self_protection_guard.audit_event(req, resp)

        events = await self_protection_guard.get_events(blocked_only=True)
        assert len(events) >= 1


# ===================================================================
# APEP-441.c: Protected path patterns tests
# ===================================================================


class TestProtectedPathGuard:
    """Security tests for protected path patterns for PreToolUse."""

    def test_builtin_patterns_loaded(self):
        from app.services.protected_path_guard import protected_path_guard

        patterns = protected_path_guard.builtin_patterns
        assert len(patterns) >= 10

    def test_claude_md_protected(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.write", "project/CLAUDE.md")
        assert result.blocked is True
        assert result.action == ProtectedPathAction.DENY

    def test_cursorrules_protected(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.write", "project/.cursorrules")
        assert result.blocked is True
        assert result.action == ProtectedPathAction.DENY

    def test_agents_md_protected(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.delete", "src/AGENTS.md")
        assert result.blocked is True

    def test_env_file_escalates(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.write", "project/.env")
        assert result.blocked is True
        assert result.action == ProtectedPathAction.ESCALATE

    def test_env_variant_escalates(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.write", "project/.env.production")
        assert result.blocked is True

    def test_credentials_json_protected(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.read", "config/credentials.json")
        assert result.blocked is True

    def test_agentpep_yaml_protected(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.write", "config/agentpep.yaml")
        assert result.blocked is True

    def test_tooltrust_dir_protected(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.write", ".tooltrust/config.json")
        assert result.blocked is True

    def test_etc_passwd_protected(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.read", "/etc/passwd")
        assert result.blocked is True

    def test_etc_shadow_protected(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.read", "/etc/shadow")
        assert result.blocked is True

    def test_normal_file_allowed(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.write", "src/main.py")
        assert result.blocked is False

    def test_tool_not_in_applies_list_allowed(self):
        """file.read is not in CLAUDE.md's applies_to_tools."""
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.read", "project/CLAUDE.md")
        assert result.blocked is False

    def test_add_custom_pattern(self):
        from app.services.protected_path_guard import protected_path_guard

        pattern = ProtectedPathPattern(
            pattern_id="PP-CUSTOM-001",
            path_glob="**/secret_config.yaml",
            description="Custom secret config",
            action=ProtectedPathAction.DENY,
            applies_to_tools=["file.write", "file.delete"],
        )
        errors = protected_path_guard.add_custom_pattern(pattern)
        assert errors == []
        result = protected_path_guard.check("file.write", "config/secret_config.yaml")
        assert result.blocked is True
        # Cleanup
        protected_path_guard.remove_custom_pattern("PP-CUSTOM-001")

    def test_cannot_delete_builtin(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.remove_custom_pattern("PP-BUILTIN-001")
        assert result is False

    def test_validate_empty_glob_rejected(self):
        from app.services.protected_path_guard import validate_path_pattern

        pattern = ProtectedPathPattern(
            path_glob="",
            applies_to_tools=["file.write"],
        )
        errors = validate_path_pattern(pattern)
        assert len(errors) > 0

    def test_validate_empty_tools_rejected(self):
        from app.services.protected_path_guard import validate_path_pattern

        pattern = ProtectedPathPattern(
            path_glob="**/test",
            applies_to_tools=[],
        )
        errors = validate_path_pattern(pattern)
        assert len(errors) > 0

    def test_empty_path_not_blocked(self):
        from app.services.protected_path_guard import protected_path_guard

        result = protected_path_guard.check("file.write", "")
        assert result.blocked is False
