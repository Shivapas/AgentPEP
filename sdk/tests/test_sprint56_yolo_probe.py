"""Sprint 56 — Tests for YOLO mode detection via environment probe (APEP-446.c).

Tests cover:
  - Environment variable detection
  - CLI argument detection
  - Combined detection
  - Clean environment (no false positives)
  - Convenience function
"""

from __future__ import annotations

import os
import sys

import pytest

from agentpep.yolo_detector import YOLOEnvironmentProbe, YOLOProbeResult, detect_yolo_mode


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure all YOLO env vars are cleared before each test."""
    yolo_vars = [
        "YOLO_MODE", "AUTO_APPROVE", "AUTO_APPROVE_ALL",
        "SKIP_CONFIRMATION", "NO_HUMAN_REVIEW", "AUTONOMOUS_MODE",
        "NO_HITL", "DANGEROUSLY_SKIP_PERMISSIONS",
        "CLAUDE_CODE_APPROVE_ALL",
    ]
    for var in yolo_vars:
        monkeypatch.delenv(var, raising=False)


class TestEnvironmentVariableDetection:
    """APEP-446.b: Detect YOLO mode from environment variables."""

    def test_yolo_mode_env_var(self, monkeypatch):
        monkeypatch.setenv("YOLO_MODE", "true")
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is True
        assert any("YOLO_MODE" in s for s in result.signals)

    def test_auto_approve_env_var(self, monkeypatch):
        monkeypatch.setenv("AUTO_APPROVE", "1")
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is True

    def test_skip_confirmation_env_var(self, monkeypatch):
        monkeypatch.setenv("SKIP_CONFIRMATION", "yes")
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is True

    def test_no_hitl_env_var(self, monkeypatch):
        monkeypatch.setenv("NO_HITL", "enabled")
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is True

    def test_dangerously_skip_permissions(self, monkeypatch):
        monkeypatch.setenv("DANGEROUSLY_SKIP_PERMISSIONS", "true")
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is True

    def test_claude_code_approve_all(self, monkeypatch):
        monkeypatch.setenv("CLAUDE_CODE_APPROVE_ALL", "true")
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is True

    def test_false_env_var_ignored(self, monkeypatch):
        monkeypatch.setenv("YOLO_MODE", "false")
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is False

    def test_empty_env_var_ignored(self, monkeypatch):
        monkeypatch.setenv("YOLO_MODE", "")
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is False

    def test_multiple_env_vars(self, monkeypatch):
        monkeypatch.setenv("YOLO_MODE", "true")
        monkeypatch.setenv("AUTO_APPROVE", "1")
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is True
        assert len(result.signals) >= 2


class TestCLIArgDetection:
    """APEP-446.b: Detect YOLO mode from CLI arguments."""

    def test_yolo_flag(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["cmd", "--yolo"])
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is True
        assert any("--yolo" in s for s in result.signals)

    def test_auto_approve_flag(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["cmd", "--auto-approve"])
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is True

    def test_dangerously_skip_permissions_flag(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["cmd", "--dangerously-skip-permissions"])
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is True

    def test_y_flag(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["cmd", "-y"])
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is True

    def test_no_yolo_flags(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["cmd", "--config", "test.yml"])
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is False


class TestCleanEnvironment:
    """APEP-446.b: Ensure no false positives in clean environment."""

    def test_clean_env_and_args(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["cmd"])
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert result.yolo_detected is False
        assert len(result.signals) == 0


class TestProbeResult:
    """APEP-446.b: Probe result data structure."""

    def test_result_fields(self, monkeypatch):
        monkeypatch.setenv("YOLO_MODE", "true")
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        assert isinstance(result, YOLOProbeResult)
        assert result.recommended_action == "ESCALATE_TO_STRICT"
        assert result.risk_multiplier == 1.5

    def test_result_immutable(self, monkeypatch):
        monkeypatch.setenv("YOLO_MODE", "true")
        probe = YOLOEnvironmentProbe()
        result = probe.detect()
        with pytest.raises(AttributeError):
            result.yolo_detected = False  # type: ignore[misc]


class TestConvenienceFunction:
    """APEP-446.b: detect_yolo_mode() convenience function."""

    def test_detect_yolo_mode_clean(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["cmd"])
        result = detect_yolo_mode()
        assert result.yolo_detected is False

    def test_detect_yolo_mode_detected(self, monkeypatch):
        monkeypatch.setenv("YOLO_MODE", "true")
        result = detect_yolo_mode()
        assert result.yolo_detected is True
