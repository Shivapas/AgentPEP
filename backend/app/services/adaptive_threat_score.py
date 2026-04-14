"""Adaptive Threat Score — Sprint 50 (APEP-401/402).

Maintains a per-session adaptive threat score that integrates signals from
network events (DLP, injection, SSRF), authorization events (deny, escalate),
kill switch activations, and sentinel findings.

The score decays over time via de-escalation timers (APEP-402) when no
new threat signals arrive.  Escalation is recommended when the score
exceeds configurable thresholds.

Extends the existing session accumulated risk scorer (APEP-067) with
network event signals.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from uuid import uuid4

from app.models.kill_switch import (
    AdaptiveThreatScoreResult,
    DeescalationState,
    DeescalationTimer,
    DeescalationTimerStatus,
    ThreatScoreEventType,
    ThreatSignal,
)

logger = logging.getLogger(__name__)


# Severity weights for each event type
_EVENT_TYPE_WEIGHTS: dict[ThreatScoreEventType, float] = {
    ThreatScoreEventType.KILL_SWITCH_ACTIVATED: 1.0,
    ThreatScoreEventType.SENTINEL_HIT: 0.8,
    ThreatScoreEventType.CHAIN_DETECTED: 0.7,
    ThreatScoreEventType.INJECTION_DETECTED: 0.6,
    ThreatScoreEventType.SSRF_BLOCKED: 0.5,
    ThreatScoreEventType.NETWORK_DLP_HIT: 0.4,
    ThreatScoreEventType.PROCESS_LINEAGE_ALERT: 0.4,
    ThreatScoreEventType.ESCALATION_TRIGGERED: 0.3,
    ThreatScoreEventType.DENY_DECISION: 0.2,
}

# Thresholds
_ESCALATION_THRESHOLD = 0.7
_DE_ESCALATION_ELIGIBLE_THRESHOLD = 0.3


class _SessionThreatState:
    """Internal state tracking for a single session's threat score."""

    __slots__ = ("signals", "de_escalation_timers", "last_score", "last_computed")

    def __init__(self) -> None:
        self.signals: list[ThreatSignal] = []
        self.de_escalation_timers: list[DeescalationTimer] = []
        self.last_score: float = 0.0
        self.last_computed: float = 0.0


class AdaptiveThreatScoreEngine:
    """Per-session adaptive threat scoring engine (APEP-401).

    Signals are recorded per session with a configurable time window.
    The score is computed as a weighted sum of active signals within
    the window, normalized to [0.0, 1.0].
    """

    def __init__(
        self,
        window_seconds: int = 600,
        escalation_threshold: float = _ESCALATION_THRESHOLD,
        de_escalation_threshold: float = _DE_ESCALATION_ELIGIBLE_THRESHOLD,
    ) -> None:
        self._window_seconds = window_seconds
        self._escalation_threshold = escalation_threshold
        self._de_escalation_threshold = de_escalation_threshold
        self._sessions: dict[str, _SessionThreatState] = {}
        self._decay_task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._running: bool = False

    # ------------------------------------------------------------------
    # Signal ingestion (APEP-401.c)
    # ------------------------------------------------------------------

    async def record_signal(
        self,
        session_id: str,
        event_type: ThreatScoreEventType,
        agent_id: str = "",
        source: str = "",
        description: str = "",
        metadata: dict | None = None,
    ) -> AdaptiveThreatScoreResult:
        """Record a new threat signal and recompute the session score.

        Returns the updated threat score result.
        """
        state = self._get_or_create_session(session_id)

        weight = _EVENT_TYPE_WEIGHTS.get(event_type, 0.1)

        signal = ThreatSignal(
            event_type=event_type,
            severity_weight=weight,
            source=source,
            description=description,
            session_id=session_id,
            agent_id=agent_id,
            metadata=metadata or {},
        )
        state.signals.append(signal)

        # Cancel any running de-escalation timers for this session
        for timer in state.de_escalation_timers:
            if timer.state == DeescalationState.RUNNING:
                timer.state = DeescalationState.CANCELLED
                timer.cancelled_at = datetime.now(UTC)
                timer.cancel_reason = f"New threat signal: {event_type.value}"

        result = self._compute_score(session_id, agent_id)

        # Publish score update event
        await self._publish_score_event(session_id, agent_id, state.last_score, result.score, event_type)

        state.last_score = result.score
        state.last_computed = time.time()

        return result

    # ------------------------------------------------------------------
    # Score computation (APEP-401.c)
    # ------------------------------------------------------------------

    def get_score(
        self,
        session_id: str,
        agent_id: str = "",
        include_signals: bool = False,
    ) -> AdaptiveThreatScoreResult:
        """Get the current adaptive threat score for a session."""
        return self._compute_score(session_id, agent_id, include_signals)

    def _compute_score(
        self,
        session_id: str,
        agent_id: str = "",
        include_signals: bool = False,
    ) -> AdaptiveThreatScoreResult:
        """Compute the adaptive threat score from active signals."""
        state = self._sessions.get(session_id)
        if state is None:
            return AdaptiveThreatScoreResult(
                session_id=session_id,
                agent_id=agent_id,
                window_seconds=self._window_seconds,
            )

        now = time.time()
        cutoff = now - self._window_seconds

        # Filter to signals within the window
        active_signals = [
            s for s in state.signals
            if s.timestamp.timestamp() > cutoff
        ]

        if not active_signals:
            return AdaptiveThreatScoreResult(
                session_id=session_id,
                agent_id=agent_id,
                de_escalation_eligible=True,
                window_seconds=self._window_seconds,
            )

        # Weighted sum with diminishing returns
        # Each additional signal of the same type has reduced weight
        type_counts: dict[ThreatScoreEventType, int] = {}
        total_weight = 0.0

        for sig in active_signals:
            count = type_counts.get(sig.event_type, 0)
            type_counts[sig.event_type] = count + 1
            # Diminishing returns: 1.0, 0.5, 0.33, 0.25, ...
            diminish = 1.0 / (count + 1)
            total_weight += sig.severity_weight * diminish

        # Normalize to [0, 1] using a soft ceiling
        score = min(total_weight / 2.0, 1.0)

        # Find the highest severity event
        highest = max(
            active_signals,
            key=lambda s: s.severity_weight,
        )

        escalation_recommended = score >= self._escalation_threshold
        de_escalation_eligible = score <= self._de_escalation_threshold

        return AdaptiveThreatScoreResult(
            session_id=session_id,
            agent_id=agent_id,
            score=round(score, 4),
            signal_count=len(active_signals),
            signals=active_signals if include_signals else [],
            highest_event_type=highest.event_type,
            escalation_recommended=escalation_recommended,
            de_escalation_eligible=de_escalation_eligible,
            window_seconds=self._window_seconds,
        )

    # ------------------------------------------------------------------
    # De-escalation timer (APEP-402)
    # ------------------------------------------------------------------

    def create_deescalation_timer(
        self,
        session_id: str,
        agent_id: str = "",
        decay_rate: float = 0.1,
        interval_seconds: int = 60,
        target_score: float = 0.0,
    ) -> DeescalationTimer:
        """Create a de-escalation timer for a session.

        The timer will gradually reduce the threat score by removing
        old signals and applying decay.  It auto-cancels if a new
        threat signal arrives.
        """
        state = self._get_or_create_session(session_id)

        timer = DeescalationTimer(
            session_id=session_id,
            agent_id=agent_id,
            state=DeescalationState.RUNNING,
            initial_score=state.last_score,
            current_score=state.last_score,
            target_score=target_score,
            decay_rate=decay_rate,
            interval_seconds=interval_seconds,
            started_at=datetime.now(UTC),
        )

        state.de_escalation_timers.append(timer)

        # Start the decay task
        asyncio.ensure_future(self._run_deescalation(session_id, timer))

        logger.info(
            "De-escalation timer created for session %s: %.2f -> %.2f (rate=%.2f, interval=%ds)",
            session_id,
            timer.initial_score,
            target_score,
            decay_rate,
            interval_seconds,
        )

        return timer

    async def _run_deescalation(
        self,
        session_id: str,
        timer: DeescalationTimer,
    ) -> None:
        """Run a de-escalation timer, decaying score over time."""
        while timer.state == DeescalationState.RUNNING:
            await asyncio.sleep(timer.interval_seconds)

            if timer.state != DeescalationState.RUNNING:
                break

            timer.current_score = max(
                timer.current_score - timer.decay_rate,
                timer.target_score,
            )

            if timer.current_score <= timer.target_score:
                timer.state = DeescalationState.COMPLETED
                timer.completed_at = datetime.now(UTC)
                logger.info(
                    "De-escalation timer completed for session %s (score: %.2f)",
                    session_id,
                    timer.current_score,
                )
                break

    def get_deescalation_status(self, session_id: str) -> DeescalationTimerStatus:
        """Get de-escalation timer status for a session."""
        state = self._sessions.get(session_id)
        if state is None:
            return DeescalationTimerStatus(session_id=session_id)

        active = [
            t for t in state.de_escalation_timers
            if t.state in (DeescalationState.PENDING, DeescalationState.RUNNING)
        ]

        earliest = None
        if active:
            for t in active:
                if t.started_at:
                    est_completion = datetime.fromtimestamp(
                        t.started_at.timestamp()
                        + t.total_duration_seconds,
                        tz=UTC,
                    )
                    if earliest is None or est_completion < earliest:
                        earliest = est_completion

        return DeescalationTimerStatus(
            session_id=session_id,
            active_timers=active,
            total_timers=len(state.de_escalation_timers),
            earliest_completion=earliest,
        )

    def cancel_deescalation_timers(
        self,
        session_id: str,
        reason: str = "Manual cancellation",
    ) -> int:
        """Cancel all active de-escalation timers for a session."""
        state = self._sessions.get(session_id)
        if state is None:
            return 0

        cancelled = 0
        for timer in state.de_escalation_timers:
            if timer.state in (DeescalationState.PENDING, DeescalationState.RUNNING):
                timer.state = DeescalationState.CANCELLED
                timer.cancelled_at = datetime.now(UTC)
                timer.cancel_reason = reason
                cancelled += 1

        return cancelled

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_or_create_session(self, session_id: str) -> _SessionThreatState:
        """Get or create session threat state."""
        if session_id not in self._sessions:
            self._sessions[session_id] = _SessionThreatState()
        return self._sessions[session_id]

    def clear_session(self, session_id: str) -> None:
        """Clear all threat state for a session."""
        self._sessions.pop(session_id, None)

    def clear_all(self) -> None:
        """Clear all session state."""
        self._sessions.clear()

    # ------------------------------------------------------------------
    # Kafka events
    # ------------------------------------------------------------------

    async def _publish_score_event(
        self,
        session_id: str,
        agent_id: str,
        previous_score: float,
        new_score: float,
        trigger_event_type: ThreatScoreEventType | None = None,
    ) -> None:
        """Publish a threat score update event to Kafka."""
        try:
            from app.services.kafka_producer import kafka_producer

            event = {
                "event_type": "THREAT_SCORE_UPDATE",
                "session_id": session_id,
                "agent_id": agent_id,
                "previous_score": previous_score,
                "new_score": new_score,
                "trigger_event_type": trigger_event_type.value if trigger_event_type else "",
                "escalation_recommended": new_score >= self._escalation_threshold,
            }
            await kafka_producer.publish_network_event(event)
        except Exception:
            logger.warning("Failed to publish threat score event", exc_info=True)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the adaptive threat score engine."""
        self._running = True
        logger.info("Adaptive threat score engine started")

    async def stop(self) -> None:
        """Stop and clean up."""
        self._running = False
        # Cancel all active timers
        for state in self._sessions.values():
            for timer in state.de_escalation_timers:
                if timer.state in (DeescalationState.PENDING, DeescalationState.RUNNING):
                    timer.state = DeescalationState.CANCELLED
                    timer.cancelled_at = datetime.now(UTC)
                    timer.cancel_reason = "Engine shutdown"
        logger.info("Adaptive threat score engine stopped")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

adaptive_threat_score = AdaptiveThreatScoreEngine()
