"""Sprint 35 — APEP-280: AdaptiveHardeningEngine tests.

Tests for the adaptive hardening engine covering:
  - Risk accumulation per session
  - Instruction generation for each risk category
  - Session isolation
  - No instructions when risk is low
  - Instruction content and severity
"""

from __future__ import annotations

import pytest

from app.models.policy import RiskFactor
from app.services.adaptive_hardening import (
    AdaptiveHardeningEngine,
    HardeningInstruction,
    RiskAccumulationState,
    SessionRiskAccumulator,
    adaptive_hardening_engine,
)


class TestRiskAccumulationState:
    """APEP-280: RiskAccumulationState tracking."""

    def test_default_state(self) -> None:
        state = RiskAccumulationState()
        assert state.total_calls == 0
        assert state.avg_risk_score == 0.0

    def test_avg_risk_score(self) -> None:
        state = RiskAccumulationState(total_calls=4, total_risk_score=2.0)
        assert state.avg_risk_score == 0.5


class TestSessionRiskAccumulator:
    """APEP-280: Session risk accumulation."""

    def test_record_basic(self) -> None:
        acc = SessionRiskAccumulator()
        acc.record("session-1", 0.5, [])
        state = acc.get_state("session-1")
        assert state.total_calls == 1
        assert state.peak_risk_score == 0.5

    def test_record_high_risk(self) -> None:
        acc = SessionRiskAccumulator()
        acc.record("session-1", 0.8, [])
        state = acc.get_state("session-1")
        assert state.high_risk_calls == 1

    def test_record_tool_combo_factor(self) -> None:
        acc = SessionRiskAccumulator()
        factors = [RiskFactor(factor_name="tool_combination", score=0.8, detail="suspicious")]
        acc.record("session-1", 0.6, factors)
        state = acc.get_state("session-1")
        assert state.tool_combo_alerts == 1

    def test_record_velocity_factor(self) -> None:
        acc = SessionRiskAccumulator()
        factors = [RiskFactor(factor_name="velocity_anomaly", score=0.5, detail="fast")]
        acc.record("session-1", 0.4, factors)
        state = acc.get_state("session-1")
        assert state.velocity_anomalies == 1

    def test_record_echo_factor(self) -> None:
        acc = SessionRiskAccumulator()
        factors = [RiskFactor(factor_name="echo_detection", score=0.6, detail="repeat")]
        acc.record("session-1", 0.4, factors)
        state = acc.get_state("session-1")
        assert state.echo_detections == 1

    def test_session_isolation(self) -> None:
        acc = SessionRiskAccumulator()
        acc.record("session-1", 0.8, [])
        acc.record("session-2", 0.2, [])
        assert acc.get_state("session-1").peak_risk_score == 0.8
        assert acc.get_state("session-2").peak_risk_score == 0.2

    def test_unknown_session_returns_default(self) -> None:
        acc = SessionRiskAccumulator()
        state = acc.get_state("nonexistent")
        assert state.total_calls == 0

    def test_max_sessions_eviction(self) -> None:
        acc = SessionRiskAccumulator(max_sessions=3)
        for i in range(5):
            acc.record(f"session-{i}", 0.1, [])
        # Only 3 sessions should remain
        assert sum(1 for i in range(5) if acc.get_state(f"session-{i}").total_calls > 0) == 3


class TestAdaptiveHardeningEngine:
    """APEP-280: Hardening instruction generation."""

    def test_no_instructions_low_risk(self) -> None:
        engine = AdaptiveHardeningEngine()
        factors = [RiskFactor(factor_name="operation_type", score=0.1, detail="read")]
        instructions = engine.record_and_generate("safe-session", factors, 0.1)
        assert instructions == []

    def test_tool_combination_instruction(self) -> None:
        engine = AdaptiveHardeningEngine()
        factors = [RiskFactor(factor_name="tool_combination", score=0.8, detail="sus")]
        instructions = engine.record_and_generate("combo-session", factors, 0.6)
        assert any(i.category == "tool_combination" for i in instructions)
        assert any("HARD-001" == i.instruction_id for i in instructions)

    def test_velocity_anomaly_instruction(self) -> None:
        engine = AdaptiveHardeningEngine()
        factors = [RiskFactor(factor_name="velocity_anomaly", score=0.5, detail="fast")]
        instructions = engine.record_and_generate("fast-session", factors, 0.4)
        assert any(i.category == "velocity_anomaly" for i in instructions)

    def test_echo_detection_instruction(self) -> None:
        engine = AdaptiveHardeningEngine()
        factors = [RiskFactor(factor_name="echo_detection", score=0.6, detail="repeat")]
        instructions = engine.record_and_generate("echo-session", factors, 0.4)
        assert any(i.category == "echo_detection" for i in instructions)

    def test_high_risk_session_instruction(self) -> None:
        engine = AdaptiveHardeningEngine()
        factors = [RiskFactor(factor_name="operation_type", score=0.9, detail="delete")]
        instructions = engine.record_and_generate("risky-session", factors, 0.8)
        assert any(i.category == "high_risk_session" for i in instructions)

    def test_injection_defense_instruction(self) -> None:
        engine = AdaptiveHardeningEngine()
        factors = [RiskFactor(factor_name="data_sensitivity", score=0.8, detail="pii")]
        instructions = engine.record_and_generate("inject-session", factors, 0.6)
        assert any(i.category == "injection_defense" for i in instructions)

    def test_delegation_warning_instruction(self) -> None:
        engine = AdaptiveHardeningEngine()
        factors = [RiskFactor(factor_name="delegation_depth", score=0.5, detail="deep")]
        instructions = engine.record_and_generate("deleg-session", factors, 0.4)
        assert any(i.category == "delegation_warning" for i in instructions)

    def test_accumulation_across_calls(self) -> None:
        engine = AdaptiveHardeningEngine()
        # First call: low risk
        inst1 = engine.record_and_generate(
            "accum-session",
            [RiskFactor(factor_name="operation_type", score=0.1, detail="read")],
            0.1,
        )
        assert inst1 == []

        # Second call: tool combo
        inst2 = engine.record_and_generate(
            "accum-session",
            [RiskFactor(factor_name="tool_combination", score=0.8, detail="sus")],
            0.6,
        )
        assert any(i.category == "tool_combination" for i in inst2)

    def test_instruction_fields(self) -> None:
        engine = AdaptiveHardeningEngine()
        factors = [RiskFactor(factor_name="tool_combination", score=0.8, detail="sus")]
        instructions = engine.record_and_generate("fields-session", factors, 0.6)
        for inst in instructions:
            assert inst.instruction_id
            assert inst.category
            assert inst.text
            assert inst.severity
            assert inst.triggered_by


class TestSingleton:
    """Module-level singleton."""

    def test_singleton_exists(self) -> None:
        assert adaptive_hardening_engine is not None
        assert isinstance(adaptive_hardening_engine, AdaptiveHardeningEngine)
