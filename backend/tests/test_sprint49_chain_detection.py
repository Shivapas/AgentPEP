"""Unit tests for Sprint 49 — Tool Call Chain Detection Engine.

APEP-388.e: Unit tests for ToolCallChain pattern model.
APEP-389.f: Unit tests for subsequence matching engine.
APEP-390.f: Unit tests for built-in chain pattern library (10 patterns).
APEP-391.e: Unit tests for chain detector PolicyEvaluator integration.
APEP-392.e: Unit tests for chain detection escalation.
APEP-393.c: Unit tests for chain pattern management API.
"""

import time
from uuid import uuid4

import pytest

from app.models.tool_call_chain import (
    ChainCategory,
    ChainDetectionAction,
    ChainDetectionResult,
    ChainEscalation,
    ChainEscalationResolveRequest,
    ChainMatchResult,
    ChainMatchStrategy,
    ChainPatternCreateRequest,
    ChainPatternListResponse,
    ChainPatternUpdateRequest,
    ChainSeverity,
    EscalationPriority,
    EscalationStatus,
    ToolCallChainPattern,
    ToolCallChainStep,
)
from app.services.chain_escalation import ChainEscalationManager, chain_escalation_manager
from app.services.chain_pattern_library import (
    ChainPatternLibrary,
    chain_pattern_library,
    compute_pattern_integrity_hash,
    validate_chain_pattern,
)
from app.services.subsequence_matcher import SubsequenceMatchingEngine, subsequence_matcher
from app.services.tool_call_chain_detector import ToolCallChainDetector
from app.services.tool_combination_detector import ToolCallRecord


# ---------------------------------------------------------------------------
# APEP-388.e: ToolCallChain pattern model tests
# ---------------------------------------------------------------------------


class TestToolCallChainPatternModel:
    """Unit tests for ToolCallChainPattern Pydantic model."""

    def test_create_minimal_pattern(self):
        pattern = ToolCallChainPattern(
            name="Test Pattern",
            steps=[
                ToolCallChainStep(tool_pattern="db.query"),
                ToolCallChainStep(tool_pattern="http.post"),
            ],
        )
        assert pattern.name == "Test Pattern"
        assert len(pattern.steps) == 2
        assert pattern.pattern_id.startswith("CP-")
        assert pattern.enabled is True
        assert pattern.builtin is False

    def test_pattern_default_values(self):
        pattern = ToolCallChainPattern(
            name="Defaults",
            steps=[
                ToolCallChainStep(tool_pattern="a"),
                ToolCallChainStep(tool_pattern="b"),
            ],
        )
        assert pattern.severity == ChainSeverity.HIGH
        assert pattern.action == ChainDetectionAction.ESCALATE
        assert pattern.match_strategy == ChainMatchStrategy.SUBSEQUENCE
        assert pattern.window_seconds == 600
        assert pattern.risk_boost == 0.8
        assert pattern.category == ChainCategory.DATA_EXFILTRATION

    def test_pattern_with_all_fields(self):
        pattern = ToolCallChainPattern(
            pattern_id="TEST-001",
            name="Full Pattern",
            description="A fully specified pattern",
            steps=[
                ToolCallChainStep(tool_pattern="secret.*", optional=False, max_gap=3),
                ToolCallChainStep(tool_pattern="*encode*", optional=True, max_gap=5),
                ToolCallChainStep(tool_pattern="http.post", optional=False, max_gap=5),
            ],
            category=ChainCategory.CREDENTIAL_THEFT,
            severity=ChainSeverity.CRITICAL,
            action=ChainDetectionAction.DENY,
            match_strategy=ChainMatchStrategy.EXACT,
            window_seconds=300,
            risk_boost=0.95,
            mitre_technique_id="T1555",
            enabled=True,
            builtin=True,
        )
        assert pattern.pattern_id == "TEST-001"
        assert pattern.steps[1].optional is True
        assert pattern.mitre_technique_id == "T1555"
        assert pattern.builtin is True

    def test_step_default_values(self):
        step = ToolCallChainStep(tool_pattern="*.read")
        assert step.optional is False
        assert step.max_gap == 10

    def test_pattern_serialization_roundtrip(self):
        pattern = ToolCallChainPattern(
            name="Roundtrip",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b.*"),
            ],
        )
        data = pattern.model_dump(mode="json")
        restored = ToolCallChainPattern(**data)
        assert restored.name == pattern.name
        assert len(restored.steps) == 2
        assert restored.steps[0].tool_pattern == "a.*"

    def test_chain_detection_result_empty(self):
        result = ChainDetectionResult()
        assert result.total_matches == 0
        assert result.matches == []
        assert result.max_risk_boost == 0.0
        assert result.detail == "No chain patterns detected"

    def test_chain_match_result(self):
        result = ChainMatchResult(
            pattern_id="CP-001",
            pattern_name="Test",
            category=ChainCategory.DATA_EXFILTRATION,
            severity=ChainSeverity.HIGH,
            action=ChainDetectionAction.ESCALATE,
            risk_boost=0.8,
            confidence=0.9,
        )
        assert result.pattern_id == "CP-001"
        assert result.confidence == 0.9

    def test_chain_escalation_model(self):
        esc = ChainEscalation(
            session_id="sess-1",
            agent_id="agent-1",
            pattern_id="CP-001",
            pattern_name="Test Pattern",
            severity=ChainSeverity.CRITICAL,
            priority=EscalationPriority.P1_CRITICAL,
        )
        assert esc.status == EscalationStatus.PENDING
        assert esc.resolved_at is None
        assert esc.escalation_id is not None

    def test_create_request_validation(self):
        req = ChainPatternCreateRequest(
            name="New Pattern",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b.*"),
            ],
        )
        assert req.name == "New Pattern"
        assert req.enabled is True

    def test_update_request_partial(self):
        req = ChainPatternUpdateRequest(name="Updated Name")
        data = req.model_dump(exclude_none=True)
        assert data == {"name": "Updated Name"}


# ---------------------------------------------------------------------------
# APEP-389.f: Subsequence matching engine tests
# ---------------------------------------------------------------------------


class TestSubsequenceMatchingEngine:
    """Unit tests for the subsequence matching engine."""

    def _make_history(self, tools: list[str], start_time: float = 1000.0, interval: float = 10.0) -> list[ToolCallRecord]:
        """Helper to create a tool call history."""
        return [
            ToolCallRecord(tool_name=t, timestamp=start_time + i * interval)
            for i, t in enumerate(tools)
        ]

    def _make_pattern(self, steps: list[str], **kwargs) -> ToolCallChainPattern:
        """Helper to create a pattern from tool patterns."""
        return ToolCallChainPattern(
            name=kwargs.pop("name", "Test"),
            steps=[ToolCallChainStep(tool_pattern=s) for s in steps],
            **kwargs,
        )

    def test_subsequence_basic_match(self):
        engine = SubsequenceMatchingEngine()
        history = self._make_history(["db.query", "file.write", "http.post"])
        pattern = self._make_pattern(["db.query", "http.post"])

        result = engine.match(history, pattern)
        assert result is not None
        assert result.pattern_name == "Test"
        assert len(result.matched_steps) == 2
        assert result.matched_steps[0].tool_name == "db.query"
        assert result.matched_steps[1].tool_name == "http.post"

    def test_subsequence_no_match(self):
        engine = SubsequenceMatchingEngine()
        history = self._make_history(["file.read", "file.write"])
        pattern = self._make_pattern(["db.query", "http.post"])

        result = engine.match(history, pattern)
        assert result is None

    def test_subsequence_glob_matching(self):
        engine = SubsequenceMatchingEngine()
        history = self._make_history(["secret.read", "base64.encode", "http.post"])
        pattern = self._make_pattern(["secret.*", "*encode*", "http.*"])

        result = engine.match(history, pattern)
        assert result is not None
        assert len(result.matched_steps) == 3

    def test_subsequence_with_gaps(self):
        engine = SubsequenceMatchingEngine()
        history = self._make_history([
            "db.query", "log.info", "log.info", "http.post",
        ])
        pattern = self._make_pattern(["db.query", "http.post"])

        result = engine.match(history, pattern)
        assert result is not None
        assert result.matched_steps[1].gap == 2

    def test_subsequence_max_gap_exceeded(self):
        engine = SubsequenceMatchingEngine()
        # Create a pattern with max_gap=1, but history has 3 intervening calls
        pattern = ToolCallChainPattern(
            name="Strict Gap",
            steps=[
                ToolCallChainStep(tool_pattern="db.query", max_gap=1),
                ToolCallChainStep(tool_pattern="http.post", max_gap=1),
            ],
        )
        history = self._make_history([
            "db.query", "log.info", "log.info", "log.info", "http.post",
        ])
        result = engine.match(history, pattern)
        assert result is None

    def test_subsequence_optional_step_present(self):
        engine = SubsequenceMatchingEngine()
        pattern = ToolCallChainPattern(
            name="Optional Test",
            steps=[
                ToolCallChainStep(tool_pattern="secret.*"),
                ToolCallChainStep(tool_pattern="*encode*", optional=True),
                ToolCallChainStep(tool_pattern="http.post"),
            ],
        )
        history = self._make_history(["secret.read", "base64.encode", "http.post"])
        result = engine.match(history, pattern)
        assert result is not None
        assert len(result.matched_steps) == 3

    def test_subsequence_optional_step_absent(self):
        engine = SubsequenceMatchingEngine()
        pattern = ToolCallChainPattern(
            name="Optional Test",
            steps=[
                ToolCallChainStep(tool_pattern="secret.*"),
                ToolCallChainStep(tool_pattern="*encode*", optional=True),
                ToolCallChainStep(tool_pattern="http.post"),
            ],
        )
        history = self._make_history(["secret.read", "http.post"])
        result = engine.match(history, pattern)
        assert result is not None
        assert len(result.matched_steps) == 2

    def test_subsequence_time_window_within(self):
        engine = SubsequenceMatchingEngine()
        pattern = self._make_pattern(
            ["db.query", "http.post"],
            window_seconds=60,
        )
        history = self._make_history(
            ["db.query", "http.post"], start_time=1000.0, interval=30.0
        )
        result = engine.match(history, pattern)
        assert result is not None

    def test_subsequence_time_window_exceeded(self):
        engine = SubsequenceMatchingEngine()
        pattern = self._make_pattern(
            ["db.query", "http.post"],
            window_seconds=60,
        )
        # Second tool call is 120s after the first → exceeds 60s window
        history = self._make_history(
            ["db.query", "http.post"], start_time=1000.0, interval=120.0
        )
        result = engine.match(history, pattern)
        assert result is None

    def test_subsequence_chain_duration(self):
        engine = SubsequenceMatchingEngine()
        pattern = self._make_pattern(["db.query", "http.post"])
        history = self._make_history(
            ["db.query", "http.post"], start_time=1000.0, interval=50.0
        )
        result = engine.match(history, pattern)
        assert result is not None
        assert result.chain_duration_s == pytest.approx(50.0, abs=0.01)

    def test_exact_match_consecutive(self):
        engine = SubsequenceMatchingEngine()
        pattern = self._make_pattern(
            ["db.query", "http.post"],
            match_strategy=ChainMatchStrategy.EXACT,
        )
        history = self._make_history(["db.query", "http.post"])
        result = engine.match(history, pattern)
        assert result is not None
        assert result.match_strategy == ChainMatchStrategy.EXACT

    def test_exact_match_with_gap_fails(self):
        engine = SubsequenceMatchingEngine()
        pattern = self._make_pattern(
            ["db.query", "http.post"],
            match_strategy=ChainMatchStrategy.EXACT,
        )
        history = self._make_history(["db.query", "log.info", "http.post"])
        result = engine.match(history, pattern)
        assert result is None

    def test_sliding_window_finds_best_match(self):
        engine = SubsequenceMatchingEngine()
        pattern = self._make_pattern(
            ["db.query", "http.post"],
            match_strategy=ChainMatchStrategy.SLIDING_WINDOW,
        )
        history = self._make_history(["log.info", "db.query", "http.post"])
        result = engine.match(history, pattern)
        assert result is not None
        assert result.match_strategy == ChainMatchStrategy.SLIDING_WINDOW

    def test_match_all_multiple_patterns(self):
        engine = SubsequenceMatchingEngine()
        p1 = self._make_pattern(["db.query", "http.post"], name="P1")
        p2 = self._make_pattern(["secret.*", "http.*"], name="P2")
        p3 = self._make_pattern(["admin.*", "deploy.*"], name="P3")

        history = self._make_history([
            "secret.read", "db.query", "http.post",
        ])
        results = engine.match_all(history, [p1, p2, p3])
        assert len(results) == 2  # P1 and P2 match, P3 doesn't
        names = {r.pattern_name for r in results}
        assert "P1" in names
        assert "P2" in names
        assert "P3" not in names

    def test_disabled_pattern_skipped(self):
        engine = SubsequenceMatchingEngine()
        pattern = self._make_pattern(
            ["db.query", "http.post"],
            enabled=False,
        )
        history = self._make_history(["db.query", "http.post"])
        result = engine.match(history, pattern)
        assert result is None

    def test_empty_history_returns_none(self):
        engine = SubsequenceMatchingEngine()
        pattern = self._make_pattern(["db.query", "http.post"])
        result = engine.match([], pattern)
        assert result is None

    def test_confidence_calculation(self):
        engine = SubsequenceMatchingEngine()
        pattern = ToolCallChainPattern(
            name="Three Step",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b.*", optional=True),
                ToolCallChainStep(tool_pattern="c.*"),
            ],
        )
        # Only a.* and c.* match (b.* is optional and skipped) → 2/3 confidence
        history = self._make_history(["a.read", "c.write"])
        result = engine.match(history, pattern)
        assert result is not None
        assert result.confidence == pytest.approx(2 / 3, abs=0.01)


# ---------------------------------------------------------------------------
# APEP-390.f: Built-in chain pattern library tests
# ---------------------------------------------------------------------------


class TestChainPatternLibrary:
    """Unit tests for the built-in chain pattern library."""

    def test_builtin_count(self):
        lib = ChainPatternLibrary()
        assert len(lib.builtin_patterns) == 10

    def test_all_builtins_enabled(self):
        lib = ChainPatternLibrary()
        for p in lib.builtin_patterns:
            assert p.enabled is True
            assert p.builtin is True

    def test_all_builtins_have_required_fields(self):
        lib = ChainPatternLibrary()
        for p in lib.builtin_patterns:
            assert p.pattern_id.startswith("CHAIN-")
            assert len(p.name) > 0
            assert len(p.description) > 0
            assert len(p.steps) >= 2
            assert p.window_seconds >= 30
            assert 0.0 <= p.risk_boost <= 1.0
            assert p.mitre_technique_id != ""

    def test_builtin_pattern_ids_unique(self):
        lib = ChainPatternLibrary()
        ids = [p.pattern_id for p in lib.builtin_patterns]
        assert len(ids) == len(set(ids))

    def test_builtin_categories_covered(self):
        lib = ChainPatternLibrary()
        categories = {p.category for p in lib.builtin_patterns}
        # Verify diverse category coverage
        assert len(categories) >= 5

    def test_integrity_check_passes(self):
        lib = ChainPatternLibrary()
        tampered = lib.verify_builtin_integrity()
        assert tampered == []

    def test_get_all_enabled(self):
        lib = ChainPatternLibrary()
        enabled = lib.get_all_enabled()
        assert len(enabled) == 10  # All built-ins enabled, no custom

    def test_get_pattern_by_id(self):
        lib = ChainPatternLibrary()
        pattern = lib.get_pattern("CHAIN-001")
        assert pattern is not None
        assert pattern.name == "Data Exfiltration via HTTP"

    def test_get_pattern_not_found(self):
        lib = ChainPatternLibrary()
        assert lib.get_pattern("NONEXISTENT") is None

    def test_add_custom_pattern(self):
        lib = ChainPatternLibrary()
        custom = ToolCallChainPattern(
            pattern_id="CUSTOM-001",
            name="Custom Test Pattern",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b.*"),
            ],
        )
        errors = lib.add_custom_pattern(custom)
        assert errors == []
        assert lib.total_count == 11
        assert lib.get_pattern("CUSTOM-001") is not None

    def test_add_custom_pattern_validation_error(self):
        lib = ChainPatternLibrary()
        bad_pattern = ToolCallChainPattern(
            name="",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b.*"),
            ],
        )
        errors = lib.add_custom_pattern(bad_pattern)
        assert len(errors) > 0
        assert "empty" in errors[0].lower()

    def test_update_custom_pattern(self):
        lib = ChainPatternLibrary()
        custom = ToolCallChainPattern(
            pattern_id="CUSTOM-002",
            name="Original Name",
            steps=[
                ToolCallChainStep(tool_pattern="x.*"),
                ToolCallChainStep(tool_pattern="y.*"),
            ],
        )
        lib.add_custom_pattern(custom)
        updated, errors = lib.update_custom_pattern("CUSTOM-002", {"name": "Updated Name"})
        assert errors == []
        assert updated is not None
        assert updated.name == "Updated Name"

    def test_update_builtin_pattern_fails(self):
        lib = ChainPatternLibrary()
        _, errors = lib.update_custom_pattern("CHAIN-001", {"name": "Hacked"})
        assert len(errors) > 0
        assert "built-in" in errors[0].lower()

    def test_delete_custom_pattern(self):
        lib = ChainPatternLibrary()
        custom = ToolCallChainPattern(
            pattern_id="CUSTOM-DEL",
            name="To Delete",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b.*"),
            ],
        )
        lib.add_custom_pattern(custom)
        assert lib.delete_custom_pattern("CUSTOM-DEL") is True
        assert lib.get_pattern("CUSTOM-DEL") is None

    def test_delete_builtin_pattern_fails(self):
        lib = ChainPatternLibrary()
        assert lib.delete_custom_pattern("CHAIN-001") is False

    def test_total_count(self):
        lib = ChainPatternLibrary()
        assert lib.total_count == 10
        lib.add_custom_pattern(
            ToolCallChainPattern(
                pattern_id="CUSTOM-CNT",
                name="Count Test",
                steps=[
                    ToolCallChainStep(tool_pattern="a.*"),
                    ToolCallChainStep(tool_pattern="b.*"),
                ],
            )
        )
        assert lib.total_count == 11


class TestChainPatternValidation:
    """Unit tests for chain pattern validation and security guards."""

    def test_valid_pattern(self):
        pattern = ToolCallChainPattern(
            name="Valid",
            steps=[
                ToolCallChainStep(tool_pattern="db.query"),
                ToolCallChainStep(tool_pattern="http.post"),
            ],
        )
        errors = validate_chain_pattern(pattern)
        assert errors == []

    def test_empty_name_rejected(self):
        pattern = ToolCallChainPattern(
            name="",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b.*"),
            ],
        )
        errors = validate_chain_pattern(pattern)
        assert any("name" in e.lower() for e in errors)

    def test_single_step_rejected(self):
        # Need to bypass Pydantic validation for this test
        pattern = ToolCallChainPattern(
            name="Single Step",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b.*"),
            ],
        )
        # Manually override steps to test validator
        pattern_data = pattern.model_dump()
        pattern_data["steps"] = [{"tool_pattern": "a.*"}]
        try:
            bad_pattern = ToolCallChainPattern(**pattern_data)
        except Exception:
            # Pydantic validation catches it
            return
        errors = validate_chain_pattern(bad_pattern)
        assert any("at least 2" in e for e in errors)

    def test_unsafe_pattern_characters(self):
        pattern = ToolCallChainPattern(
            name="Unsafe",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b;rm -rf /"),  # Dangerous
            ],
        )
        errors = validate_chain_pattern(pattern)
        assert any("unsafe" in e.lower() for e in errors)

    def test_window_too_small(self):
        pattern = ToolCallChainPattern(
            name="Small Window",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b.*"),
            ],
            window_seconds=30,  # minimum allowed
        )
        errors = validate_chain_pattern(pattern)
        assert errors == []

    def test_risk_boost_bounds(self):
        pattern = ToolCallChainPattern(
            name="Bounded",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b.*"),
            ],
            risk_boost=0.5,
        )
        errors = validate_chain_pattern(pattern)
        assert errors == []

    def test_integrity_hash_deterministic(self):
        pattern = ToolCallChainPattern(
            pattern_id="HASH-TEST",
            name="Hash Test",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b.*"),
            ],
            category=ChainCategory.DATA_EXFILTRATION,
            severity=ChainSeverity.HIGH,
            risk_boost=0.8,
        )
        hash1 = compute_pattern_integrity_hash(pattern)
        hash2 = compute_pattern_integrity_hash(pattern)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex digest


# ---------------------------------------------------------------------------
# APEP-391.e: Chain detector tests
# ---------------------------------------------------------------------------


class TestToolCallChainDetector:
    """Unit tests for the ToolCallChainDetector."""

    @pytest.mark.asyncio
    async def test_check_history_detects_exfiltration(self):
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="db.query", timestamp=1000.0),
            ToolCallRecord(tool_name="file.write", timestamp=1010.0),
            ToolCallRecord(tool_name="http.post", timestamp=1020.0),
        ]
        result = await detector.check_history(history, session_id="test-sess")
        assert result.total_matches > 0
        assert result.max_risk_boost > 0

    @pytest.mark.asyncio
    async def test_check_history_no_match(self):
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="log.info", timestamp=1000.0),
            ToolCallRecord(tool_name="log.debug", timestamp=1010.0),
        ]
        result = await detector.check_history(history, session_id="test-sess")
        assert result.total_matches == 0
        assert result.detail == "No chain patterns detected"

    @pytest.mark.asyncio
    async def test_check_history_credential_theft(self):
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="secret.read", timestamp=1000.0),
            ToolCallRecord(tool_name="base64.encode", timestamp=1010.0),
            ToolCallRecord(tool_name="http.post", timestamp=1020.0),
        ]
        result = await detector.check_history(history, session_id="test-sess")
        assert result.total_matches > 0
        matched_ids = {m.pattern_id for m in result.matches}
        assert "CHAIN-002" in matched_ids

    @pytest.mark.asyncio
    async def test_check_history_backdoor_account(self):
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="admin.list_users", timestamp=1000.0),
            ToolCallRecord(tool_name="admin.create_user", timestamp=1010.0),
            ToolCallRecord(tool_name="admin.modify_role", timestamp=1020.0),
        ]
        result = await detector.check_history(history, session_id="test-sess")
        matched_ids = {m.pattern_id for m in result.matches}
        assert "CHAIN-003" in matched_ids

    @pytest.mark.asyncio
    async def test_check_history_malware_chain(self):
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="file.write", timestamp=1000.0),
            ToolCallRecord(tool_name="shell.exec", timestamp=1005.0),
            ToolCallRecord(tool_name="file.delete", timestamp=1010.0),
        ]
        result = await detector.check_history(history, session_id="test-sess")
        matched_ids = {m.pattern_id for m in result.matches}
        assert "CHAIN-004" in matched_ids

    @pytest.mark.asyncio
    async def test_check_history_mass_destruction(self):
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="db.drop_users", timestamp=1000.0),
            ToolCallRecord(tool_name="db.drop_orders", timestamp=1005.0),
            ToolCallRecord(tool_name="file.delete", timestamp=1010.0),
        ]
        result = await detector.check_history(history, session_id="test-sess")
        matched_ids = {m.pattern_id for m in result.matches}
        assert "CHAIN-009" in matched_ids

    @pytest.mark.asyncio
    async def test_highest_severity_and_action(self):
        detector = ToolCallChainDetector()
        # Trigger CHAIN-002 (CRITICAL/DENY) and CHAIN-005 (HIGH/ESCALATE)
        history = [
            ToolCallRecord(tool_name="secret.read", timestamp=1000.0),
            ToolCallRecord(tool_name="admin.list_users", timestamp=1005.0),
            ToolCallRecord(tool_name="http.post", timestamp=1010.0),
        ]
        result = await detector.check_history(history, session_id="test-sess")
        assert result.total_matches > 0
        assert result.highest_severity == ChainSeverity.CRITICAL
        assert result.recommended_action == ChainDetectionAction.DENY

    @pytest.mark.asyncio
    async def test_empty_history(self):
        detector = ToolCallChainDetector()
        result = await detector.check_history([], session_id="test-sess")
        assert result.total_matches == 0

    @pytest.mark.asyncio
    async def test_scan_latency_recorded(self):
        detector = ToolCallChainDetector()
        history = [
            ToolCallRecord(tool_name="db.query", timestamp=1000.0),
            ToolCallRecord(tool_name="http.post", timestamp=1010.0),
        ]
        result = await detector.check_history(history, session_id="test-sess")
        assert result.scan_latency_us >= 0


# ---------------------------------------------------------------------------
# APEP-392.e: Chain detection escalation tests
# ---------------------------------------------------------------------------


class TestChainEscalationManager:
    """Unit tests for chain detection escalation."""

    def setup_method(self):
        self.manager = ChainEscalationManager()

    def _make_match(self, **kwargs) -> ChainMatchResult:
        defaults = {
            "pattern_id": "CP-001",
            "pattern_name": "Test Pattern",
            "category": ChainCategory.DATA_EXFILTRATION,
            "severity": ChainSeverity.HIGH,
            "action": ChainDetectionAction.ESCALATE,
            "risk_boost": 0.8,
            "matched_steps": [],
            "description": "Test match",
        }
        defaults.update(kwargs)
        return ChainMatchResult(**defaults)

    def test_create_escalation(self):
        match = self._make_match()
        esc = self.manager.create_escalation(match, session_id="sess-1", agent_id="agent-1")
        assert esc.session_id == "sess-1"
        assert esc.agent_id == "agent-1"
        assert esc.pattern_id == "CP-001"
        assert esc.status == EscalationStatus.PENDING
        assert esc.priority == EscalationPriority.P2_HIGH

    def test_critical_severity_maps_to_p1(self):
        match = self._make_match(severity=ChainSeverity.CRITICAL)
        esc = self.manager.create_escalation(match)
        assert esc.priority == EscalationPriority.P1_CRITICAL

    def test_medium_severity_maps_to_p3(self):
        match = self._make_match(severity=ChainSeverity.MEDIUM)
        esc = self.manager.create_escalation(match)
        assert esc.priority == EscalationPriority.P3_MEDIUM

    def test_get_escalation(self):
        match = self._make_match()
        esc = self.manager.create_escalation(match)
        fetched = self.manager.get_escalation(esc.escalation_id)
        assert fetched is not None
        assert fetched.escalation_id == esc.escalation_id

    def test_get_nonexistent_escalation(self):
        assert self.manager.get_escalation(uuid4()) is None

    def test_list_escalations(self):
        for i in range(5):
            self.manager.create_escalation(
                self._make_match(pattern_id=f"CP-{i:03d}"),
                session_id="sess-1",
            )
        results = self.manager.list_escalations()
        assert len(results) == 5

    def test_list_escalations_filter_session(self):
        self.manager.create_escalation(self._make_match(), session_id="sess-1")
        self.manager.create_escalation(self._make_match(), session_id="sess-2")
        results = self.manager.list_escalations(session_id="sess-1")
        assert len(results) == 1
        assert results[0].session_id == "sess-1"

    def test_list_escalations_filter_status(self):
        esc = self.manager.create_escalation(self._make_match())
        self.manager.resolve_escalation(
            esc.escalation_id,
            EscalationStatus.RESOLVED,
        )
        self.manager.create_escalation(self._make_match())  # still pending

        pending = self.manager.list_escalations(status=EscalationStatus.PENDING)
        assert len(pending) == 1
        resolved = self.manager.list_escalations(status=EscalationStatus.RESOLVED)
        assert len(resolved) == 1

    def test_resolve_escalation(self):
        match = self._make_match()
        esc = self.manager.create_escalation(match)
        resolved = self.manager.resolve_escalation(
            esc.escalation_id,
            EscalationStatus.RESOLVED,
            resolution_note="Investigated, confirmed false alarm",
            resolved_by="admin",
        )
        assert resolved is not None
        assert resolved.status == EscalationStatus.RESOLVED
        assert resolved.resolution_note == "Investigated, confirmed false alarm"
        assert resolved.resolved_by == "admin"
        assert resolved.resolved_at is not None

    def test_resolve_nonexistent_returns_none(self):
        assert self.manager.resolve_escalation(uuid4(), EscalationStatus.RESOLVED) is None

    def test_resolve_already_resolved(self):
        match = self._make_match()
        esc = self.manager.create_escalation(match)
        self.manager.resolve_escalation(esc.escalation_id, EscalationStatus.RESOLVED)
        # Resolving again returns existing (no update)
        again = self.manager.resolve_escalation(esc.escalation_id, EscalationStatus.DISMISSED)
        assert again is not None
        assert again.status == EscalationStatus.RESOLVED  # Unchanged

    def test_acknowledge_escalation(self):
        match = self._make_match()
        esc = self.manager.create_escalation(match)
        acked = self.manager.acknowledge_escalation(esc.escalation_id)
        assert acked is not None
        assert acked.status == EscalationStatus.ACKNOWLEDGED

    def test_acknowledge_nonexistent(self):
        assert self.manager.acknowledge_escalation(uuid4()) is None

    def test_pending_count(self):
        self.manager.create_escalation(self._make_match())
        self.manager.create_escalation(self._make_match())
        assert self.manager.pending_count == 2

        esc = self.manager.list_escalations()[0]
        self.manager.resolve_escalation(esc.escalation_id, EscalationStatus.RESOLVED)
        assert self.manager.pending_count == 1

    def test_create_escalations_from_result(self):
        result = ChainDetectionResult(
            session_id="sess-1",
            agent_id="agent-1",
            matches=[
                self._make_match(action=ChainDetectionAction.ESCALATE),
                self._make_match(action=ChainDetectionAction.DENY, pattern_id="CP-002"),
                self._make_match(action=ChainDetectionAction.LOG_ONLY, pattern_id="CP-003"),
            ],
            total_matches=3,
        )
        escalations = self.manager.create_escalations_from_result(result)
        # LOG_ONLY should not create an escalation
        assert len(escalations) == 2

    def test_clear(self):
        self.manager.create_escalation(self._make_match())
        self.manager.create_escalation(self._make_match())
        assert self.manager.pending_count == 2
        self.manager.clear()
        assert self.manager.pending_count == 0

    def test_false_positive_resolution(self):
        match = self._make_match()
        esc = self.manager.create_escalation(match)
        resolved = self.manager.resolve_escalation(
            esc.escalation_id,
            EscalationStatus.FALSE_POSITIVE,
            resolution_note="Not a real attack",
        )
        assert resolved is not None
        assert resolved.status == EscalationStatus.FALSE_POSITIVE


# ---------------------------------------------------------------------------
# APEP-393.c: Chain pattern management API tests
# ---------------------------------------------------------------------------


class TestChainPatternManagementAPI:
    """Unit tests for chain pattern management API via models."""

    def test_create_request_valid(self):
        req = ChainPatternCreateRequest(
            name="API Pattern",
            description="Created via API",
            steps=[
                ToolCallChainStep(tool_pattern="a.*"),
                ToolCallChainStep(tool_pattern="b.*"),
            ],
            category=ChainCategory.CREDENTIAL_THEFT,
            severity=ChainSeverity.CRITICAL,
            action=ChainDetectionAction.DENY,
            window_seconds=300,
            risk_boost=0.9,
            mitre_technique_id="T1555",
        )
        assert req.name == "API Pattern"
        assert req.risk_boost == 0.9

    def test_update_request_partial_fields(self):
        req = ChainPatternUpdateRequest(
            severity=ChainSeverity.MEDIUM,
            enabled=False,
        )
        data = req.model_dump(exclude_none=True)
        assert "severity" in data
        assert "enabled" in data
        assert "name" not in data

    def test_list_response(self):
        patterns = [
            ToolCallChainPattern(
                name=f"P{i}",
                steps=[
                    ToolCallChainStep(tool_pattern="a.*"),
                    ToolCallChainStep(tool_pattern="b.*"),
                ],
            )
            for i in range(3)
        ]
        resp = ChainPatternListResponse(patterns=patterns, total=3)
        assert resp.total == 3
        assert len(resp.patterns) == 3

    def test_escalation_resolve_request(self):
        req = ChainEscalationResolveRequest(
            status=EscalationStatus.RESOLVED,
            resolution_note="Investigated",
            resolved_by="admin@example.com",
        )
        assert req.status == EscalationStatus.RESOLVED
