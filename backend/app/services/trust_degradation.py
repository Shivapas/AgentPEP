"""TrustDegradationSimulator — model session trust ceiling decay.

Sprint 34 — APEP-270: Simulate trust degradation across configurable
interaction sequences. Models how a session's trust ceiling decays
irreversibly when untrusted or derived content contaminates the context.

The simulator accepts a sequence of interaction events (tool calls with
taint labels, context injections, delegation hops) and computes the
trust ceiling at each step, producing a decay timeline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class InteractionType(StrEnum):
    """Types of interactions that affect trust ceiling."""

    TOOL_CALL = "TOOL_CALL"
    CONTEXT_INJECTION = "CONTEXT_INJECTION"
    DELEGATION_HOP = "DELEGATION_HOP"
    TAINT_PROPAGATION = "TAINT_PROPAGATION"
    INJECTION_DETECTED = "INJECTION_DETECTED"
    ESCALATION_TRIGGERED = "ESCALATION_TRIGGERED"


class TaintLevel(StrEnum):
    """Taint levels for trust computation."""

    TRUSTED = "TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    QUARANTINE = "QUARANTINE"


@dataclass
class InteractionEvent:
    """A single interaction event in a session sequence."""

    step: int
    interaction_type: InteractionType
    taint_level: TaintLevel = TaintLevel.TRUSTED
    agent_id: str = ""
    tool_name: str = ""
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "interaction_type": self.interaction_type.value,
            "taint_level": self.taint_level.value,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "description": self.description,
        }


@dataclass
class TrustSnapshot:
    """Trust state at a specific point in the interaction sequence."""

    step: int
    trust_ceiling: float
    previous_ceiling: float
    degradation_reason: str = ""
    interaction: InteractionEvent | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "step": self.step,
            "trust_ceiling": round(self.trust_ceiling, 4),
            "previous_ceiling": round(self.previous_ceiling, 4),
            "delta": round(self.trust_ceiling - self.previous_ceiling, 4),
            "degradation_reason": self.degradation_reason,
        }
        if self.interaction:
            result["interaction"] = self.interaction.to_dict()
        return result


@dataclass
class DegradationConfig:
    """Configuration for trust degradation behaviour."""

    initial_ceiling: float = 1.0
    untrusted_penalty: float = 0.15
    quarantine_penalty: float = 0.40
    delegation_penalty_per_hop: float = 0.05
    injection_penalty: float = 0.50
    escalation_penalty: float = 0.10
    context_injection_penalty: float = 0.20
    minimum_ceiling: float = 0.0
    irreversible: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DegradationConfig:
        return cls(
            initial_ceiling=data.get("initial_ceiling", 1.0),
            untrusted_penalty=data.get("untrusted_penalty", 0.15),
            quarantine_penalty=data.get("quarantine_penalty", 0.40),
            delegation_penalty_per_hop=data.get("delegation_penalty_per_hop", 0.05),
            injection_penalty=data.get("injection_penalty", 0.50),
            escalation_penalty=data.get("escalation_penalty", 0.10),
            context_injection_penalty=data.get("context_injection_penalty", 0.20),
            minimum_ceiling=data.get("minimum_ceiling", 0.0),
            irreversible=data.get("irreversible", True),
        )


@dataclass
class DegradationTimeline:
    """Full timeline of trust degradation across an interaction sequence."""

    config: DegradationConfig
    snapshots: list[TrustSnapshot] = field(default_factory=list)

    @property
    def initial_ceiling(self) -> float:
        return self.config.initial_ceiling

    @property
    def final_ceiling(self) -> float:
        return self.snapshots[-1].trust_ceiling if self.snapshots else self.config.initial_ceiling

    @property
    def total_degradation(self) -> float:
        return round(self.initial_ceiling - self.final_ceiling, 4)

    @property
    def degradation_events(self) -> list[TrustSnapshot]:
        return [s for s in self.snapshots if s.trust_ceiling < s.previous_ceiling]

    def to_dict(self) -> dict[str, Any]:
        return {
            "initial_ceiling": self.initial_ceiling,
            "final_ceiling": round(self.final_ceiling, 4),
            "total_degradation": self.total_degradation,
            "total_steps": len(self.snapshots),
            "degradation_events": len(self.degradation_events),
            "snapshots": [s.to_dict() for s in self.snapshots],
        }


# ---------------------------------------------------------------------------
# Simulator
# ---------------------------------------------------------------------------


class TrustDegradationSimulator:
    """Simulate trust ceiling degradation across interaction sequences.

    The trust ceiling starts at ``config.initial_ceiling`` (default 1.0) and
    degrades irreversibly based on interaction events. Each event type has a
    configurable penalty. Once the ceiling drops, it cannot recover (if
    ``irreversible=True``).

    Usage::

        simulator = TrustDegradationSimulator()
        events = [
            InteractionEvent(step=1, interaction_type=InteractionType.TOOL_CALL,
                           taint_level=TaintLevel.TRUSTED, tool_name="file.read"),
            InteractionEvent(step=2, interaction_type=InteractionType.CONTEXT_INJECTION,
                           taint_level=TaintLevel.UNTRUSTED),
            InteractionEvent(step=3, interaction_type=InteractionType.INJECTION_DETECTED),
        ]
        timeline = simulator.simulate(events)
    """

    def __init__(self, config: DegradationConfig | None = None) -> None:
        self.config = config or DegradationConfig()

    def simulate(
        self,
        events: list[InteractionEvent],
    ) -> DegradationTimeline:
        """Run the degradation simulation across an event sequence.

        Args:
            events: Ordered list of interaction events.

        Returns:
            DegradationTimeline with step-by-step trust snapshots.
        """
        timeline = DegradationTimeline(config=self.config)
        current_ceiling = self.config.initial_ceiling

        for event in events:
            previous = current_ceiling
            penalty, reason = self._compute_penalty(event)

            if penalty > 0:
                current_ceiling = max(
                    current_ceiling - penalty,
                    self.config.minimum_ceiling,
                )
            elif not self.config.irreversible and penalty < 0:
                # Allow recovery only if irreversible=False
                current_ceiling = min(
                    current_ceiling - penalty,
                    self.config.initial_ceiling,
                )

            snapshot = TrustSnapshot(
                step=event.step,
                trust_ceiling=current_ceiling,
                previous_ceiling=previous,
                degradation_reason=reason if penalty > 0 else "",
                interaction=event,
            )
            timeline.snapshots.append(snapshot)

        return timeline

    def _compute_penalty(
        self, event: InteractionEvent
    ) -> tuple[float, str]:
        """Compute the trust penalty for an interaction event.

        Returns:
            Tuple of (penalty_amount, reason_string).
        """
        itype = event.interaction_type
        taint = event.taint_level

        if itype == InteractionType.INJECTION_DETECTED:
            return self.config.injection_penalty, "Injection pattern detected"

        if itype == InteractionType.ESCALATION_TRIGGERED:
            return self.config.escalation_penalty, "Escalation triggered"

        if itype == InteractionType.CONTEXT_INJECTION:
            if taint == TaintLevel.QUARANTINE:
                return (
                    self.config.context_injection_penalty + self.config.quarantine_penalty,
                    "Quarantined context injection",
                )
            if taint == TaintLevel.UNTRUSTED:
                return self.config.context_injection_penalty, "Untrusted context injection"
            return 0.0, ""

        if itype == InteractionType.DELEGATION_HOP:
            return self.config.delegation_penalty_per_hop, "Delegation hop"

        if itype == InteractionType.TAINT_PROPAGATION:
            if taint == TaintLevel.QUARANTINE:
                return self.config.quarantine_penalty, "Quarantine taint propagation"
            if taint == TaintLevel.UNTRUSTED:
                return self.config.untrusted_penalty, "Untrusted taint propagation"
            return 0.0, ""

        if itype == InteractionType.TOOL_CALL:
            if taint == TaintLevel.QUARANTINE:
                return self.config.quarantine_penalty, "Tool call with quarantined data"
            if taint == TaintLevel.UNTRUSTED:
                return self.config.untrusted_penalty, "Tool call with untrusted data"
            return 0.0, ""

        return 0.0, ""


# Module-level singleton
trust_degradation_simulator = TrustDegradationSimulator()
