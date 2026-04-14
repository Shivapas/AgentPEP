"""TrustDegradationEngine — real-time trust ceiling tracking with persistence.

Sprint 36 — APEP-286: Wraps the Sprint 34 TrustDegradationSimulator with
MongoDB persistence, per-session state tracking, and an API-friendly
interface. The engine maintains a TrustDegradationRecord per session and
updates the trust ceiling as new interaction events arrive.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from app.db import mongodb as db_module
from app.models.sprint36 import TrustDegradationRecord
from app.services.trust_degradation import (
    DegradationConfig,
    InteractionEvent,
    InteractionType,
    TaintLevel,
    TrustDegradationSimulator,
)

logger = logging.getLogger(__name__)


class TrustDegradationEngine:
    """Real-time trust degradation engine with MongoDB persistence.

    Tracks per-session trust ceilings and applies irreversible degradation
    penalties when interaction events are recorded. Sessions can be locked
    when the trust ceiling drops below a configured floor.
    """

    def __init__(
        self,
        config: DegradationConfig | None = None,
        lock_threshold: float = 0.1,
    ) -> None:
        self._config = config or DegradationConfig()
        self._simulator = TrustDegradationSimulator(self._config)
        self._lock_threshold = lock_threshold

    async def get_or_create_record(
        self,
        session_id: str,
        tenant_id: str = "default",
    ) -> TrustDegradationRecord:
        """Get existing trust record for a session, or create a new one."""
        db = db_module.get_database()
        collection = db[db_module.TRUST_DEGRADATION_RECORDS]

        doc = await collection.find_one({"session_id": session_id})
        if doc:
            return TrustDegradationRecord(**doc)

        record = TrustDegradationRecord(
            session_id=session_id,
            tenant_id=tenant_id,
            current_ceiling=self._config.initial_ceiling,
            initial_ceiling=self._config.initial_ceiling,
        )
        await collection.insert_one(record.model_dump(mode="json"))
        return record

    async def record_event(
        self,
        session_id: str,
        interaction_type: str,
        taint_level: str = "TRUSTED",
        agent_id: str = "",
        tool_name: str = "",
        tenant_id: str = "default",
    ) -> TrustDegradationRecord:
        """Record an interaction event and update the trust ceiling.

        Args:
            session_id: Session to degrade.
            interaction_type: One of InteractionType values.
            taint_level: TRUSTED, UNTRUSTED, or QUARANTINE.
            agent_id: Agent that triggered the event.
            tool_name: Tool involved (if applicable).
            tenant_id: Tenant identifier.

        Returns:
            Updated TrustDegradationRecord.
        """
        record = await self.get_or_create_record(session_id, tenant_id)

        if record.locked:
            logger.warning(
                "trust_degradation_locked session_id=%s ceiling=%.4f",
                session_id,
                record.current_ceiling,
            )
            return record

        # Build a single-step simulation from the current ceiling
        event = InteractionEvent(
            step=record.degradation_count + 1,
            interaction_type=InteractionType(interaction_type),
            taint_level=TaintLevel(taint_level),
            agent_id=agent_id,
            tool_name=tool_name,
        )

        # Use simulator to compute penalty
        penalty, reason = self._simulator._compute_penalty(event)

        if penalty > 0:
            new_ceiling = max(
                record.current_ceiling - penalty,
                self._config.minimum_ceiling,
            )
            total_degradation = round(record.initial_ceiling - new_ceiling, 4)
            locked = new_ceiling <= self._lock_threshold

            db = db_module.get_database()
            collection = db[db_module.TRUST_DEGRADATION_RECORDS]
            await collection.update_one(
                {"session_id": session_id},
                {
                    "$set": {
                        "current_ceiling": new_ceiling,
                        "total_degradation": total_degradation,
                        "degradation_count": record.degradation_count + 1,
                        "last_degradation_reason": reason,
                        "locked": locked,
                        "updated_at": datetime.now(UTC).isoformat(),
                    }
                },
            )

            record.current_ceiling = new_ceiling
            record.total_degradation = total_degradation
            record.degradation_count += 1
            record.last_degradation_reason = reason
            record.locked = locked

            # Emit Prometheus metrics
            try:
                from app.core.observability import (
                    TRUST_CEILING_HISTOGRAM,
                    TRUST_DEGRADATION_EVENTS,
                )

                TRUST_DEGRADATION_EVENTS.labels(
                    reason=reason,
                    locked=str(locked),
                ).inc()
                TRUST_CEILING_HISTOGRAM.observe(new_ceiling)
            except Exception:
                pass  # Non-blocking

            logger.info(
                "trust_degraded session_id=%s ceiling=%.4f penalty=%.4f reason=%s locked=%s",
                session_id,
                new_ceiling,
                penalty,
                reason,
                locked,
            )

        return record

    async def get_ceiling(self, session_id: str) -> float:
        """Get the current trust ceiling for a session."""
        record = await self.get_or_create_record(session_id)
        return record.current_ceiling

    async def is_locked(self, session_id: str) -> bool:
        """Check if a session's trust has been locked."""
        record = await self.get_or_create_record(session_id)
        return record.locked

    async def admin_reset(
        self,
        session_id: str,
    ) -> TrustDegradationRecord:
        """Admin-only trust reset for a session.

        Provides a trust-reset mechanism for security administrators
        to unlock sessions after review.
        """
        db = db_module.get_database()
        collection = db[db_module.TRUST_DEGRADATION_RECORDS]

        await collection.update_one(
            {"session_id": session_id},
            {
                "$set": {
                    "current_ceiling": self._config.initial_ceiling,
                    "total_degradation": 0.0,
                    "degradation_count": 0,
                    "last_degradation_reason": "admin_reset",
                    "locked": False,
                    "updated_at": datetime.now(UTC).isoformat(),
                }
            },
        )

        record = await self.get_or_create_record(session_id)
        logger.info("trust_reset session_id=%s by=admin", session_id)
        return record


# Module-level singleton
trust_degradation_engine = TrustDegradationEngine()
