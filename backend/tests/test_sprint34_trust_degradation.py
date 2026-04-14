"""Sprint 34 — APEP-270: Trust degradation simulation tests.

Tests for the TrustDegradationSimulator covering:
  - No degradation on trusted interactions
  - Degradation on untrusted/quarantine events
  - Injection detection penalty
  - Delegation hop penalties
  - Irreversible ceiling property
  - Custom configuration
  - Timeline serialisation
"""

from __future__ import annotations

import json

import pytest

from app.services.trust_degradation import (
    DegradationConfig,
    DegradationTimeline,
    InteractionEvent,
    InteractionType,
    TaintLevel,
    TrustDegradationSimulator,
    TrustSnapshot,
)


class TestTrustDegradationSimulator:
    """APEP-270: Trust degradation simulation."""

    def test_all_trusted_no_degradation(self) -> None:
        sim = TrustDegradationSimulator()
        events = [
            InteractionEvent(step=i, interaction_type=InteractionType.TOOL_CALL,
                             taint_level=TaintLevel.TRUSTED, tool_name=f"tool_{i}")
            for i in range(5)
        ]
        timeline = sim.simulate(events)
        assert timeline.final_ceiling == 1.0
        assert timeline.total_degradation == 0.0
        assert len(timeline.degradation_events) == 0

    def test_untrusted_tool_call_degrades(self) -> None:
        sim = TrustDegradationSimulator()
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.TOOL_CALL,
                             taint_level=TaintLevel.UNTRUSTED),
        ]
        timeline = sim.simulate(events)
        assert timeline.final_ceiling == pytest.approx(1.0 - 0.15)

    def test_quarantine_tool_call_degrades_more(self) -> None:
        sim = TrustDegradationSimulator()
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.TOOL_CALL,
                             taint_level=TaintLevel.QUARANTINE),
        ]
        timeline = sim.simulate(events)
        assert timeline.final_ceiling == pytest.approx(1.0 - 0.40)

    def test_injection_detected_penalty(self) -> None:
        sim = TrustDegradationSimulator()
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.INJECTION_DETECTED),
        ]
        timeline = sim.simulate(events)
        assert timeline.final_ceiling == pytest.approx(0.5)

    def test_escalation_penalty(self) -> None:
        sim = TrustDegradationSimulator()
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.ESCALATION_TRIGGERED),
        ]
        timeline = sim.simulate(events)
        assert timeline.final_ceiling == pytest.approx(0.9)

    def test_context_injection_untrusted(self) -> None:
        sim = TrustDegradationSimulator()
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.CONTEXT_INJECTION,
                             taint_level=TaintLevel.UNTRUSTED),
        ]
        timeline = sim.simulate(events)
        assert timeline.final_ceiling == pytest.approx(1.0 - 0.20)

    def test_context_injection_quarantine(self) -> None:
        sim = TrustDegradationSimulator()
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.CONTEXT_INJECTION,
                             taint_level=TaintLevel.QUARANTINE),
        ]
        timeline = sim.simulate(events)
        # context_injection_penalty + quarantine_penalty = 0.20 + 0.40
        assert timeline.final_ceiling == pytest.approx(1.0 - 0.60)

    def test_delegation_hop_penalty(self) -> None:
        sim = TrustDegradationSimulator()
        events = [
            InteractionEvent(step=i, interaction_type=InteractionType.DELEGATION_HOP,
                             agent_id=f"agent-{i}")
            for i in range(3)
        ]
        timeline = sim.simulate(events)
        assert timeline.final_ceiling == pytest.approx(1.0 - 3 * 0.05)

    def test_cumulative_degradation(self) -> None:
        sim = TrustDegradationSimulator()
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.TOOL_CALL,
                             taint_level=TaintLevel.UNTRUSTED),
            InteractionEvent(step=2, interaction_type=InteractionType.INJECTION_DETECTED),
            InteractionEvent(step=3, interaction_type=InteractionType.DELEGATION_HOP),
        ]
        timeline = sim.simulate(events)
        expected = 1.0 - 0.15 - 0.50 - 0.05
        assert timeline.final_ceiling == pytest.approx(expected)
        assert len(timeline.degradation_events) == 3

    def test_minimum_ceiling_floor(self) -> None:
        config = DegradationConfig(minimum_ceiling=0.1)
        sim = TrustDegradationSimulator(config)
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.INJECTION_DETECTED),
            InteractionEvent(step=2, interaction_type=InteractionType.INJECTION_DETECTED),
            InteractionEvent(step=3, interaction_type=InteractionType.INJECTION_DETECTED),
        ]
        timeline = sim.simulate(events)
        assert timeline.final_ceiling == pytest.approx(0.1)

    def test_irreversible_no_recovery(self) -> None:
        config = DegradationConfig(irreversible=True)
        sim = TrustDegradationSimulator(config)
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.CONTEXT_INJECTION,
                             taint_level=TaintLevel.UNTRUSTED),
            InteractionEvent(step=2, interaction_type=InteractionType.TOOL_CALL,
                             taint_level=TaintLevel.TRUSTED),
            InteractionEvent(step=3, interaction_type=InteractionType.TOOL_CALL,
                             taint_level=TaintLevel.TRUSTED),
        ]
        timeline = sim.simulate(events)
        # After step 1: ceiling drops. Steps 2-3 are trusted — no further drop, no recovery.
        after_step1 = timeline.snapshots[0].trust_ceiling
        assert timeline.snapshots[1].trust_ceiling == after_step1
        assert timeline.snapshots[2].trust_ceiling == after_step1

    def test_custom_config(self) -> None:
        config = DegradationConfig(
            initial_ceiling=0.8,
            untrusted_penalty=0.25,
            injection_penalty=0.30,
        )
        sim = TrustDegradationSimulator(config)
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.INJECTION_DETECTED),
        ]
        timeline = sim.simulate(events)
        assert timeline.initial_ceiling == 0.8
        assert timeline.final_ceiling == pytest.approx(0.5)

    def test_config_from_dict(self) -> None:
        config = DegradationConfig.from_dict({
            "initial_ceiling": 0.9,
            "untrusted_penalty": 0.10,
            "quarantine_penalty": 0.30,
        })
        assert config.initial_ceiling == 0.9
        assert config.untrusted_penalty == 0.10

    def test_timeline_serialisation(self) -> None:
        sim = TrustDegradationSimulator()
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.TOOL_CALL,
                             taint_level=TaintLevel.UNTRUSTED, agent_id="bot",
                             tool_name="file.read", description="Read file"),
            InteractionEvent(step=2, interaction_type=InteractionType.INJECTION_DETECTED),
        ]
        timeline = sim.simulate(events)
        d = timeline.to_dict()

        assert "initial_ceiling" in d
        assert "final_ceiling" in d
        assert "total_degradation" in d
        assert "snapshots" in d
        assert len(d["snapshots"]) == 2

        # Must be JSON-serialisable
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert parsed["total_steps"] == 2

    def test_empty_event_list(self) -> None:
        sim = TrustDegradationSimulator()
        timeline = sim.simulate([])
        assert timeline.final_ceiling == 1.0
        assert len(timeline.snapshots) == 0

    def test_taint_propagation_penalties(self) -> None:
        sim = TrustDegradationSimulator()
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.TAINT_PROPAGATION,
                             taint_level=TaintLevel.UNTRUSTED),
            InteractionEvent(step=2, interaction_type=InteractionType.TAINT_PROPAGATION,
                             taint_level=TaintLevel.QUARANTINE),
        ]
        timeline = sim.simulate(events)
        expected = 1.0 - 0.15 - 0.40
        assert timeline.final_ceiling == pytest.approx(expected)
