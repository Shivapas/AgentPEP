"""Chain Detection Escalation Service — Sprint 49 (APEP-392).

Manages escalation records created when chain patterns are detected.
Provides CRUD operations, priority assignment, and resolution tracking.
Publishes Kafka events for chain detection alerts.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from uuid import UUID

from app.models.tool_call_chain import (
    ChainCategory,
    ChainDetectionAction,
    ChainDetectionResult,
    ChainEscalation,
    ChainMatchResult,
    ChainSeverity,
    EscalationPriority,
    EscalationStatus,
)

logger = logging.getLogger(__name__)


# Severity → Priority mapping
_SEVERITY_TO_PRIORITY: dict[ChainSeverity, EscalationPriority] = {
    ChainSeverity.CRITICAL: EscalationPriority.P1_CRITICAL,
    ChainSeverity.HIGH: EscalationPriority.P2_HIGH,
    ChainSeverity.MEDIUM: EscalationPriority.P3_MEDIUM,
    ChainSeverity.LOW: EscalationPriority.P4_LOW,
    ChainSeverity.INFO: EscalationPriority.P4_LOW,
}


class ChainEscalationManager:
    """Manages chain detection escalations (APEP-392).

    Creates, tracks, and resolves escalation records when chain
    patterns trigger ESCALATE or DENY actions.
    """

    def __init__(self) -> None:
        self._escalations: dict[UUID, ChainEscalation] = {}

    def create_escalation(
        self,
        match: ChainMatchResult,
        session_id: str = "",
        agent_id: str = "",
    ) -> ChainEscalation:
        """Create an escalation record from a chain match result."""
        priority = _SEVERITY_TO_PRIORITY.get(
            match.severity, EscalationPriority.P3_MEDIUM
        )
        matched_tools = [step.tool_name for step in match.matched_steps]

        escalation = ChainEscalation(
            session_id=session_id,
            agent_id=agent_id,
            pattern_id=match.pattern_id,
            pattern_name=match.pattern_name,
            category=match.category,
            severity=match.severity,
            priority=priority,
            status=EscalationStatus.PENDING,
            risk_boost=match.risk_boost,
            matched_tools=matched_tools,
            chain_duration_s=match.chain_duration_s,
            mitre_technique_id=match.mitre_technique_id,
            description=match.description,
        )

        self._escalations[escalation.escalation_id] = escalation
        logger.info(
            "Chain escalation created: %s (pattern=%s, severity=%s, priority=%s)",
            escalation.escalation_id,
            match.pattern_id,
            match.severity.value,
            priority.value,
        )
        return escalation

    def create_escalations_from_result(
        self,
        result: ChainDetectionResult,
    ) -> list[ChainEscalation]:
        """Create escalation records for all actionable matches in a detection result."""
        escalations: list[ChainEscalation] = []
        for match in result.matches:
            if match.action in (
                ChainDetectionAction.ESCALATE,
                ChainDetectionAction.DENY,
            ):
                esc = self.create_escalation(
                    match=match,
                    session_id=result.session_id,
                    agent_id=result.agent_id,
                )
                escalations.append(esc)
        return escalations

    def get_escalation(self, escalation_id: UUID) -> ChainEscalation | None:
        """Get an escalation by ID."""
        return self._escalations.get(escalation_id)

    def list_escalations(
        self,
        session_id: str | None = None,
        status: EscalationStatus | None = None,
        limit: int = 50,
    ) -> list[ChainEscalation]:
        """List escalations, optionally filtered by session and/or status."""
        results = list(self._escalations.values())
        if session_id is not None:
            results = [e for e in results if e.session_id == session_id]
        if status is not None:
            results = [e for e in results if e.status == status]
        # Sort by creation time (newest first)
        results.sort(key=lambda e: e.created_at, reverse=True)
        return results[:limit]

    def resolve_escalation(
        self,
        escalation_id: UUID,
        status: EscalationStatus,
        resolution_note: str = "",
        resolved_by: str = "",
    ) -> ChainEscalation | None:
        """Resolve an escalation with a new status and optional note."""
        escalation = self._escalations.get(escalation_id)
        if escalation is None:
            return None

        if escalation.status in (
            EscalationStatus.RESOLVED,
            EscalationStatus.FALSE_POSITIVE,
            EscalationStatus.DISMISSED,
        ):
            logger.warning(
                "Attempted to resolve already-resolved escalation: %s",
                escalation_id,
            )
            return escalation

        # Update the escalation via model_copy
        updated = escalation.model_copy(
            update={
                "status": status,
                "resolution_note": resolution_note,
                "resolved_by": resolved_by,
                "resolved_at": datetime.now(UTC),
            }
        )
        self._escalations[escalation_id] = updated

        logger.info(
            "Chain escalation resolved: %s -> %s (by %s)",
            escalation_id,
            status.value,
            resolved_by or "system",
        )
        return updated

    def acknowledge_escalation(
        self, escalation_id: UUID
    ) -> ChainEscalation | None:
        """Acknowledge a pending escalation."""
        escalation = self._escalations.get(escalation_id)
        if escalation is None:
            return None
        if escalation.status != EscalationStatus.PENDING:
            return escalation

        updated = escalation.model_copy(
            update={"status": EscalationStatus.ACKNOWLEDGED}
        )
        self._escalations[escalation_id] = updated
        return updated

    @property
    def pending_count(self) -> int:
        return sum(
            1
            for e in self._escalations.values()
            if e.status == EscalationStatus.PENDING
        )

    def clear(self) -> None:
        """Clear all escalations (for testing)."""
        self._escalations.clear()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

chain_escalation_manager = ChainEscalationManager()
