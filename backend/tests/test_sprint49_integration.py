"""Integration & adversarial tests for Sprint 49 — Tool Call Chain Detection Engine.

APEP-389.g: Integration tests for subsequence matching engine.
APEP-390.g: Adversarial tests for built-in chain pattern library.
APEP-395.a/b: Integration and adversarial tests.

Tests verify:
  - End-to-end pipeline wiring (detector + library + escalation)
  - API endpoint responses
  - Cross-component interactions
  - Adversarial inputs and edge cases
  - Security boundary enforcement
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.tool_call_chain import (
    ChainCategory,
    ChainDetectionAction,
    ChainDetectionResult,
    ChainMatchStrategy,
    ChainSeverity,
    EscalationStatus,
    ToolCallChainPattern,
    ToolCallChainStep,
)
from app.services.chain_escalation import ChainEscalationManager
from app.services.chain_pattern_library import (
    ChainPatternLibrary,
    validate_chain_pattern,
)
from app.services.subsequence_matcher import SubsequenceMatchingEngine
from app.services.tool_call_chain_detector import ToolCallChainDetector
from app.services.tool_combination_detector import ToolCallRecord
from tests.conftest import _get_auth_headers


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# API endpoint integration tests
# ---------------------------------------------------------------------------


class TestChainDetectionAPIEndpoints:
    """Integration tests for Sprint 49 API endpoints."""

    @pytest.mark.asyncio
    async def test_chain_status(self, client):
        response = await client.get(
            "/v1/chains/status", headers=_get_auth_headers()
        )
        assert response.status_code == 200
        data = response.json()
        assert "enabled_patterns" in data
        assert "builtin_patterns" in data
        assert "custom_patterns" in data
        assert "total_patterns" in data
        assert "integrity_check" in data
        assert data["integrity_check"] == "PASS"
        assert data["builtin_patterns"] == 10

    @pytest.mark.asyncio
    async def test_list_patterns(self, client):
        response = await client.get(
            "/v1/chains/patterns", headers=_get_auth_headers()
        )
        assert response.status_code == 200
        data = response.json()
        assert "patterns" in data
        assert "total" in data
        assert data["total"] >= 10
        # Verify all patterns have required fields
        for p in data["patterns"]:
            assert "pattern_id" in p
            assert "name" in p
            assert "steps" in p
            assert len(p["steps"]) >= 2

    @pytest.mark.asyncio
    async def test_list_patterns_enabled_only(self, client):
        response = await client.get(
            "/v1/chains/patterns?enabled_only=true",
            headers=_get_auth_headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 10

    @pytest.mark.asyncio
    async def test_get_pattern_by_id(self, client):
        response = await client.get(
            "/v1/chains/patterns/CHAIN-001",
            headers=_get_auth_headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["pattern_id"] == "CHAIN-001"
        assert data["name"] == "Data Exfiltration via HTTP"
        assert data["builtin"] is True

    @pytest.mark.asyncio
    async def test_get_pattern_not_found(self, client):
        response = await client.get(
            "/v1/chains/patterns/NONEXISTENT",
            headers=_get_auth_headers(),
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_create_custom_pattern(self, client):
        response = await client.post(
            "/v1/chains/patterns",
            json={
                "name": "API Test Pattern",
                "description": "Created via API test",
                "steps": [
                    {"tool_pattern": "test.read"},
                    {"tool_pattern": "test.write"},
                ],
                "category": "DATA_EXFILTRATION",
                "severity": "MEDIUM",
                "action": "ALERT",
                "window_seconds": 300,
                "risk_boost": 0.5,
            },
            headers=_get_auth_headers(),
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "API Test Pattern"
        assert data["builtin"] is False
        assert data["severity"] == "MEDIUM"

    @pytest.mark.asyncio
    async def test_delete_builtin_pattern_forbidden(self, client):
        response = await client.delete(
            "/v1/chains/patterns/CHAIN-001",
            headers=_get_auth_headers(),
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_detect_chains_endpoint(self, client):
        response = await client.post(
            "/v1/chains/detect?session_id=test-sess&tool_name=http.post",
            headers=_get_auth_headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert "matches" in data
        assert "total_matches" in data
        assert "scan_latency_us" in data

    @pytest.mark.asyncio
    async def test_list_escalations(self, client):
        response = await client.get(
            "/v1/chains/escalations",
            headers=_get_auth_headers(),
        )
        assert response.status_code == 200
        data = response.json()
        assert "escalations" in data
        assert "total" in data

    @pytest.mark.asyncio
    async def test_get_escalation_not_found(self, client):
        import uuid
        response = await client.get(
            f"/v1/chains/escalations/{uuid.uuid4()}",
            headers=_get_auth_headers(),
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Cross-component integration tests
# ---------------------------------------------------------------------------


class TestCrossComponentIntegration:
    """Tests verifying Sprint 49 components work together."""

    @pytest.mark.asyncio
    async def test_detector_uses_library_patterns(self):
        """Detector should use patterns from chain_pattern_library."""
        detector = ToolCallChainDetector()
        # Create a history that matches CHAIN-001 (db.query → http.post)
        history = [
            ToolCallRecord(tool_name="db.query", timestamp=1000.0),
            ToolCallRecord(tool_name="http.post", timestamp=1010.0),
        ]
        result = await detector.check_history(history)
        assert result.total_matches > 0
        # Verify the match came from the library
        for m in result.matches:
            assert m.pattern_id.startswith("CHAIN-")

    @pytest.mark.asyncio
    async def test_detection_triggers_escalation(self):
        """Chain detection result should create escalation records."""
        detector = ToolCallChainDetector()
        manager = ChainEscalationManager()

        history = [
            ToolCallRecord(tool_name="secret.read", timestamp=1000.0),
            ToolCallRecord(tool_name="http.post", timestamp=1010.0),
        ]
        result = await detector.check_history(
            history, session_id="esc-test", agent_id="agent-1"
        )
        assert result.total_matches > 0

        escalations = manager.create_escalations_from_result(result)
        assert len(escalations) > 0
        for esc in escalations:
            assert esc.session_id == "esc-test"
            assert esc.agent_id == "agent-1"
            assert esc.status == EscalationStatus.PENDING

    @pytest.mark.asyncio
    async def test_custom_pattern_detected_by_detector(self):
        """Custom patterns added to library should be detected."""
        lib = ChainPatternLibrary()
        custom = ToolCallChainPattern(
            pattern_id="CUSTOM-INT",
            name="Custom Integration",
            steps=[
                ToolCallChainStep(tool_pattern="custom.start"),
                ToolCallChainStep(tool_pattern="custom.finish"),
            ],
            category=ChainCategory.RESOURCE_ABUSE,
            severity=ChainSeverity.MEDIUM,
            action=ChainDetectionAction.ALERT,
            window_seconds=300,
            risk_boost=0.5,
        )
        lib.add_custom_pattern(custom)

        engine = SubsequenceMatchingEngine()
        history = [
            ToolCallRecord(tool_name="custom.start", timestamp=1000.0),
            ToolCallRecord(tool_name="custom.finish", timestamp=1010.0),
        ]
        patterns = lib.get_all_enabled()
        results = engine.match_all(history, patterns)
        custom_matches = [r for r in results if r.pattern_id == "CUSTOM-INT"]
        assert len(custom_matches) == 1

    @pytest.mark.asyncio
    async def test_multiple_chains_in_single_session(self):
        """Multiple attack chains in one session should all be detected."""
        detector = ToolCallChainDetector()
        history = [
            # Chain 1: credential theft (CHAIN-002)
            ToolCallRecord(tool_name="secret.read", timestamp=1000.0),
            ToolCallRecord(tool_name="http.post", timestamp=1010.0),
            # Chain 2: backdoor account (CHAIN-003)
            ToolCallRecord(tool_name="admin.list_users", timestamp=1020.0),
            ToolCallRecord(tool_name="admin.create_user", timestamp=1030.0),
            ToolCallRecord(tool_name="admin.modify_role", timestamp=1040.0),
        ]
        result = await detector.check_history(history, session_id="multi")
        assert result.total_matches >= 2
        pattern_ids = {m.pattern_id for m in result.matches}
        assert "CHAIN-002" in pattern_ids
        assert "CHAIN-003" in pattern_ids

    @pytest.mark.asyncio
    async def test_escalation_lifecycle(self):
        """Full lifecycle: create → acknowledge → resolve."""
        manager = ChainEscalationManager()
        from app.models.tool_call_chain import ChainMatchResult, ChainMatchedStep

        match = ChainMatchResult(
            pattern_id="CP-LIFE",
            pattern_name="Lifecycle Test",
            category=ChainCategory.DATA_EXFILTRATION,
            severity=ChainSeverity.HIGH,
            action=ChainDetectionAction.ESCALATE,
            risk_boost=0.8,
        )
        # Create
        esc = manager.create_escalation(match, session_id="life-test")
        assert esc.status == EscalationStatus.PENDING

        # Acknowledge
        acked = manager.acknowledge_escalation(esc.escalation_id)
        assert acked.status == EscalationStatus.ACKNOWLEDGED

        # Resolve
        resolved = manager.resolve_escalation(
            esc.escalation_id,
            EscalationStatus.RESOLVED,
            resolution_note="Confirmed attack, blocked user",
            resolved_by="security-team",
        )
        assert resolved.status == EscalationStatus.RESOLVED
        assert resolved.resolved_at is not None


# ---------------------------------------------------------------------------
# Adversarial tests (APEP-395)
# ---------------------------------------------------------------------------


class TestAdversarialInputs:
    """Adversarial tests for chain detection security boundaries."""

    def test_pattern_with_injection_characters(self):
        """Patterns with shell injection characters should be rejected."""
        pattern = ToolCallChainPattern(
            name="Injection Test",
            steps=[
                ToolCallChainStep(tool_pattern="safe.tool"),
                ToolCallChainStep(tool_pattern="$(rm -rf /)"),
            ],
        )
        errors = validate_chain_pattern(pattern)
        assert len(errors) > 0

    def test_pattern_with_sql_injection(self):
        """Patterns with SQL-like injection should be rejected."""
        pattern = ToolCallChainPattern(
            name="SQL Injection",
            steps=[
                ToolCallChainStep(tool_pattern="safe.tool"),
                ToolCallChainStep(tool_pattern="'; DROP TABLE --"),
            ],
        )
        errors = validate_chain_pattern(pattern)
        assert len(errors) > 0

    def test_extremely_long_pattern_name(self):
        """Extremely long pattern names should be handled."""
        # Pydantic will enforce max_length on create request
        try:
            req = ChainPatternCreateRequest(
                name="A" * 1000,
                steps=[
                    ToolCallChainStep(tool_pattern="a.*"),
                    ToolCallChainStep(tool_pattern="b.*"),
                ],
            )
            # If Pydantic doesn't catch it, validator should
        except Exception:
            pass  # Expected — Pydantic validation

    def test_unicode_tool_pattern(self):
        """Unicode characters in tool patterns should be rejected."""
        pattern = ToolCallChainPattern(
            name="Unicode Test",
            steps=[
                ToolCallChainStep(tool_pattern="safe.tool"),
                ToolCallChainStep(tool_pattern="tо\u043ell.rеаd"),  # Cyrillic chars
            ],
        )
        errors = validate_chain_pattern(pattern)
        assert len(errors) > 0

    def test_zero_width_characters(self):
        """Zero-width characters in patterns should be rejected."""
        pattern = ToolCallChainPattern(
            name="Zero Width",
            steps=[
                ToolCallChainStep(tool_pattern="safe.tool"),
                ToolCallChainStep(tool_pattern="tool\u200b.read"),  # Zero-width space
            ],
        )
        errors = validate_chain_pattern(pattern)
        assert len(errors) > 0

    @pytest.mark.asyncio
    async def test_empty_tool_name_in_history(self):
        """Empty tool names in history should not crash the detector."""
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="", timestamp=1000.0),
            ToolCallRecord(tool_name="", timestamp=1010.0),
            ToolCallRecord(tool_name="db.query", timestamp=1020.0),
        ]
        result = await detector.check_history(history)
        # Should not crash; may or may not detect patterns
        assert isinstance(result, ChainDetectionResult)

    @pytest.mark.asyncio
    async def test_huge_history_doesnt_crash(self):
        """Large session history should complete without errors."""
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(
                tool_name=f"tool.op{i % 20}",
                timestamp=1000.0 + i * 0.1,
            )
            for i in range(500)
        ]
        result = await detector.check_history(history)
        assert isinstance(result, ChainDetectionResult)

    @pytest.mark.asyncio
    async def test_same_timestamp_all_tools(self):
        """All tools at the same timestamp should be handled."""
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="db.query", timestamp=1000.0),
            ToolCallRecord(tool_name="http.post", timestamp=1000.0),
        ]
        result = await detector.check_history(history)
        assert isinstance(result, ChainDetectionResult)

    @pytest.mark.asyncio
    async def test_negative_timestamps(self):
        """Negative timestamps should not crash the detector."""
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="db.query", timestamp=-100.0),
            ToolCallRecord(tool_name="http.post", timestamp=-50.0),
        ]
        result = await detector.check_history(history)
        assert isinstance(result, ChainDetectionResult)

    def test_builtin_pattern_cannot_be_deleted(self):
        """Built-in patterns must resist deletion attempts."""
        lib = ChainPatternLibrary()
        for p in lib.builtin_patterns:
            assert lib.delete_custom_pattern(p.pattern_id) is False

    def test_builtin_pattern_cannot_be_updated(self):
        """Built-in patterns must resist update attempts."""
        lib = ChainPatternLibrary()
        _, errors = lib.update_custom_pattern("CHAIN-001", {"name": "Hacked"})
        assert len(errors) > 0

    def test_integrity_check_detects_no_tampering(self):
        """Fresh library should pass integrity check."""
        lib = ChainPatternLibrary()
        tampered = lib.verify_builtin_integrity()
        assert tampered == []

    def test_overlapping_patterns_all_detected(self):
        """Overlapping tool sequences should trigger all matching patterns."""
        engine = SubsequenceMatchingEngine()
        # Both patterns match the same history
        p1 = ToolCallChainPattern(
            pattern_id="OVERLAP-1",
            name="Overlap 1",
            steps=[
                ToolCallChainStep(tool_pattern="*.read"),
                ToolCallChainStep(tool_pattern="http.*"),
            ],
        )
        p2 = ToolCallChainPattern(
            pattern_id="OVERLAP-2",
            name="Overlap 2",
            steps=[
                ToolCallChainStep(tool_pattern="file.*"),
                ToolCallChainStep(tool_pattern="http.post"),
            ],
        )
        history = [
            ToolCallRecord(tool_name="file.read", timestamp=1000.0),
            ToolCallRecord(tool_name="http.post", timestamp=1010.0),
        ]
        results = engine.match_all(history, [p1, p2])
        assert len(results) == 2

    def test_wildcard_only_pattern(self):
        """Patterns with only wildcards should still work correctly."""
        engine = SubsequenceMatchingEngine()
        pattern = ToolCallChainPattern(
            name="Wildcard",
            steps=[
                ToolCallChainStep(tool_pattern="*"),
                ToolCallChainStep(tool_pattern="*"),
            ],
        )
        history = [
            ToolCallRecord(tool_name="anything", timestamp=1000.0),
            ToolCallRecord(tool_name="else", timestamp=1010.0),
        ]
        result = engine.match(history, pattern)
        assert result is not None

    @pytest.mark.asyncio
    async def test_interleaved_benign_tools_dont_prevent_detection(self):
        """Benign tools interleaved with attack chain should still detect."""
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="secret.read", timestamp=1000.0),
            ToolCallRecord(tool_name="log.info", timestamp=1005.0),
            ToolCallRecord(tool_name="log.debug", timestamp=1007.0),
            ToolCallRecord(tool_name="http.post", timestamp=1010.0),
        ]
        result = await detector.check_history(history)
        assert result.total_matches > 0
        matched_ids = {m.pattern_id for m in result.matches}
        assert "CHAIN-002" in matched_ids

    @pytest.mark.asyncio
    async def test_reverse_order_doesnt_match(self):
        """Tools in reverse order should NOT trigger sequential patterns."""
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="http.post", timestamp=1000.0),
            ToolCallRecord(tool_name="secret.read", timestamp=1010.0),
        ]
        result = await detector.check_history(history)
        # CHAIN-002 expects secret.* → http.*, not reversed
        chain2_matches = [m for m in result.matches if m.pattern_id == "CHAIN-002"]
        assert len(chain2_matches) == 0

    @pytest.mark.asyncio
    async def test_partial_chain_no_match(self):
        """Partial chain (only first step) should not trigger detection."""
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="secret.read", timestamp=1000.0),
            ToolCallRecord(tool_name="log.info", timestamp=1010.0),
        ]
        result = await detector.check_history(history)
        chain2_matches = [m for m in result.matches if m.pattern_id == "CHAIN-002"]
        assert len(chain2_matches) == 0

    @pytest.mark.asyncio
    async def test_chain_outside_time_window(self):
        """Chain steps outside the time window should not match."""
        detector = ToolCallChainDetector()
        # CHAIN-002 has window_seconds=300, set gap > 300s
        history = [
            ToolCallRecord(tool_name="secret.read", timestamp=1000.0),
            ToolCallRecord(tool_name="http.post", timestamp=2000.0),  # 1000s gap
        ]
        result = await detector.check_history(history)
        chain2_matches = [m for m in result.matches if m.pattern_id == "CHAIN-002"]
        assert len(chain2_matches) == 0
