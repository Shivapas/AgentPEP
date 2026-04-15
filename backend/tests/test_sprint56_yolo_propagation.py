"""Sprint 56 — Security validation tests for YOLO mode session flag propagation (APEP-445.e).

Tests cover:
  - YOLO detection via prompt signals
  - YOLO detection via metadata flags
  - Flag propagation to session scan config
  - Security guards preventing unauthorized flag clearing
  - Trusted source validation
  - Risk multiplier bounds validation
  - Locked session downgrade prevention
"""

from __future__ import annotations

import pytest

from app.services.yolo_mode_detector import YOLOModeDetector
from app.services.yolo_session_propagator import YOLOSessionPropagator


@pytest.fixture
def propagator():
    """Create a fresh YOLOSessionPropagator for each test."""
    p = YOLOSessionPropagator()
    yield p
    p.clear_all()


@pytest.fixture
def detector():
    return YOLOModeDetector()


class TestYOLODetection:
    """APEP-445.b: Core YOLO detection logic."""

    def test_detect_prompt_yolo_mode(self, detector):
        result = detector.check_prompt("Please enable yolo mode for this session")
        assert result.detected is True
        assert len(result.signals) > 0

    def test_detect_prompt_auto_approve(self, detector):
        result = detector.check_prompt("auto-approve all tool calls")
        assert result.detected is True

    def test_detect_prompt_clean(self, detector):
        result = detector.check_prompt("Please read the file config.yaml")
        assert result.detected is False

    def test_detect_metadata_yolo_flag(self, detector):
        result = detector.check_metadata({"yolo": True})
        assert result.detected is True

    def test_detect_metadata_auto_approve(self, detector):
        result = detector.check_metadata({"auto_approve": "true"})
        assert result.detected is True

    def test_detect_metadata_clean(self, detector):
        result = detector.check_metadata({"session_id": "s1"})
        assert result.detected is False

    def test_detect_metadata_skip_confirmation(self, detector):
        result = detector.check_metadata({"skip_confirmation": 1})
        assert result.detected is True

    def test_check_all_combines_signals(self, detector):
        result = detector.check_all(
            text="enable yolo mode",
            metadata={"auto_approve": True},
        )
        assert result.detected is True
        assert len(result.signals) >= 2


class TestYOLOPropagation:
    """APEP-445.b: YOLO flag propagation to session scan config."""

    @pytest.mark.asyncio
    async def test_propagate_flag(self, propagator, mock_mongodb):
        result = await propagator.propagate_flag(
            session_id="sess-yolo-1",
            signals=["YOLO_MODE env var detected"],
        )
        assert result.yolo_detected is True
        assert result.flag_propagated is True
        assert result.scan_mode_applied == "STRICT"
        assert result.risk_multiplier == 1.5

    @pytest.mark.asyncio
    async def test_propagate_custom_multiplier(self, propagator, mock_mongodb):
        result = await propagator.propagate_flag(
            session_id="sess-yolo-2",
            signals=["test"],
            risk_multiplier=2.0,
        )
        assert result.risk_multiplier == 2.0

    @pytest.mark.asyncio
    async def test_check_and_propagate_detected(self, propagator, mock_mongodb):
        result = await propagator.check_and_propagate(
            session_id="sess-yolo-3",
            text="please enable yolo mode",
        )
        assert result.yolo_detected is True
        assert result.flag_propagated is True

    @pytest.mark.asyncio
    async def test_check_and_propagate_clean(self, propagator, mock_mongodb):
        result = await propagator.check_and_propagate(
            session_id="sess-clean",
            text="read the config file",
        )
        assert result.yolo_detected is False
        assert result.flag_propagated is False

    @pytest.mark.asyncio
    async def test_already_flagged_returns_cached(self, propagator, mock_mongodb):
        await propagator.propagate_flag(
            session_id="sess-yolo-4",
            signals=["test signal"],
        )
        result = await propagator.check_and_propagate(
            session_id="sess-yolo-4",
            text="enable yolo mode",
        )
        assert result.already_flagged is True
        assert result.flag_propagated is False


class TestSecurityGuards:
    """APEP-445.c: Security guards for YOLO flag manipulation."""

    @pytest.mark.asyncio
    async def test_untrusted_source_rejected(self, propagator, mock_mongodb):
        result = await propagator.propagate_flag(
            session_id="sess-guard-1",
            signals=["test"],
            source="untrusted_caller",
        )
        assert result.yolo_detected is False
        assert result.flag_propagated is False

    @pytest.mark.asyncio
    async def test_trusted_source_accepted(self, propagator, mock_mongodb):
        result = await propagator.propagate_flag(
            session_id="sess-guard-2",
            signals=["test"],
            source="yolo_detector",
        )
        assert result.yolo_detected is True
        assert result.flag_propagated is True

    @pytest.mark.asyncio
    async def test_admin_source_accepted(self, propagator, mock_mongodb):
        result = await propagator.propagate_flag(
            session_id="sess-guard-3",
            signals=["manual flag"],
            source="admin",
        )
        assert result.flag_propagated is True

    @pytest.mark.asyncio
    async def test_clear_locked_flag_non_admin(self, propagator, mock_mongodb):
        await propagator.propagate_flag(
            session_id="sess-guard-4",
            signals=["test"],
        )
        cleared = await propagator.clear_flag("sess-guard-4", source="agent")
        assert cleared is False

    @pytest.mark.asyncio
    async def test_clear_locked_flag_admin(self, propagator, mock_mongodb):
        await propagator.propagate_flag(
            session_id="sess-guard-5",
            signals=["test"],
        )
        cleared = await propagator.clear_flag("sess-guard-5", source="admin")
        assert cleared is True

    def test_is_flagged(self, propagator):
        assert propagator.is_flagged("nonexistent") is False

    @pytest.mark.asyncio
    async def test_is_flagged_after_propagation(self, propagator, mock_mongodb):
        await propagator.propagate_flag(
            session_id="sess-check-flag",
            signals=["test"],
        )
        assert propagator.is_flagged("sess-check-flag") is True


class TestRiskMultiplierValidation:
    """APEP-445.c: Risk multiplier bounds validation."""

    @pytest.mark.asyncio
    async def test_default_multiplier(self, propagator, mock_mongodb):
        result = await propagator.propagate_flag(
            session_id="sess-rm-1",
            signals=["test"],
        )
        assert result.risk_multiplier == 1.5

    def test_unflagged_session_has_no_flag(self, propagator):
        flag = propagator.get_flag("no-session")
        assert flag is None

    @pytest.mark.asyncio
    async def test_flagged_session_has_multiplier(self, propagator, mock_mongodb):
        await propagator.propagate_flag(
            session_id="sess-rm-2",
            signals=["test"],
            risk_multiplier=2.5,
        )
        flag = propagator.get_flag("sess-rm-2")
        assert flag is not None
        assert flag.risk_multiplier == 2.5


class TestListFlags:
    """APEP-445.b: Listing YOLO session flags."""

    @pytest.mark.asyncio
    async def test_list_flags_empty(self, propagator, mock_mongodb):
        result = await propagator.list_flags()
        assert result.total == 0
        assert result.flags == []

    @pytest.mark.asyncio
    async def test_list_flags_after_propagation(self, propagator, mock_mongodb):
        await propagator.propagate_flag(
            session_id="sess-list-1",
            signals=["test signal"],
        )
        result = await propagator.list_flags()
        assert result.total == 1
        assert result.flags[0].session_id == "sess-list-1"
