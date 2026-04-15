"""YOLO mode session flag propagation — Sprint 56 (APEP-445).

When the YOLOModeDetector detects YOLO mode, this service propagates the
detection through the session lifecycle:

  1. Locks the session to STRICT scan mode via SessionScanConfig.
  2. Applies a configurable risk multiplier (default 1.5x) to the session.
  3. Emits a Kafka event for audit/observability.
  4. Records the YOLO flag in session metadata for downstream consumers.
  5. Prevents downgrade of the session scan mode while YOLO is active.

Security guards (APEP-445.c):
  - Validates that the YOLO flag can only be set by trusted sources.
  - Prevents external callers from clearing the YOLO flag once set.
  - Audits all flag propagation events.

Pipeline integration (APEP-445.d):
  - Integrates with PolicyEvaluator to apply risk multiplier.
  - Integrates with CIS pipeline to force STRICT mode.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from app.services.yolo_mode_detector import YOLODetection, YOLOModeDetector, yolo_detector

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class YOLOSessionFlag(BaseModel):
    """YOLO mode flag state for a session."""

    flag_id: str = Field(default_factory=lambda: str(uuid4()))
    session_id: str
    detected: bool = False
    signals: list[str] = Field(default_factory=list)
    risk_multiplier: float = Field(default=1.5, description="Applied risk score multiplier")
    enforced_scan_mode: str = Field(default="STRICT")
    propagated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str = Field(default="yolo_detector", description="What triggered the flag")
    locked: bool = Field(default=True, description="Once set, cannot be cleared by non-admin")
    metadata: dict[str, Any] = Field(default_factory=dict)


class YOLOPropagationResult(BaseModel):
    """Result of a YOLO flag propagation."""

    session_id: str
    yolo_detected: bool = False
    signals: list[str] = Field(default_factory=list)
    scan_mode_applied: str = "STANDARD"
    risk_multiplier: float = 1.0
    flag_propagated: bool = False
    already_flagged: bool = False


class YOLOSessionFlagListResponse(BaseModel):
    """List of YOLO session flags."""

    flags: list[YOLOSessionFlag] = Field(default_factory=list)
    total: int = 0


# ---------------------------------------------------------------------------
# Trusted sources that can set YOLO flags
# ---------------------------------------------------------------------------

_TRUSTED_SOURCES = frozenset({
    "yolo_detector",
    "policy_evaluator",
    "cis_pipeline",
    "admin",
    "system",
})

YOLO_FLAGS_COLLECTION = "yolo_session_flags"


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class YOLOSessionPropagator:
    """Propagates YOLO mode detection across the session lifecycle (APEP-445).

    When YOLO mode is detected, this service:
      1. Sets the session scan config to STRICT + locked.
      2. Applies a 1.5x risk multiplier.
      3. Records the flag for audit trail.
      4. Emits a Kafka event.

    Parameters
    ----------
    default_risk_multiplier:
        Risk score multiplier applied when YOLO mode is detected.
    """

    def __init__(self, default_risk_multiplier: float = 1.5) -> None:
        self._default_multiplier = default_risk_multiplier
        self._flags: dict[str, YOLOSessionFlag] = {}

    async def check_and_propagate(
        self,
        session_id: str,
        *,
        text: str = "",
        metadata: dict[str, object] | None = None,
        source: str = "yolo_detector",
    ) -> YOLOPropagationResult:
        """Run YOLO detection and propagate if detected.

        Combines prompt analysis, metadata checking, and behavioural
        analysis into one call, then propagates the result.
        """
        # Check if already flagged
        if session_id in self._flags and self._flags[session_id].detected:
            existing = self._flags[session_id]
            return YOLOPropagationResult(
                session_id=session_id,
                yolo_detected=True,
                signals=existing.signals,
                scan_mode_applied=existing.enforced_scan_mode,
                risk_multiplier=existing.risk_multiplier,
                flag_propagated=False,
                already_flagged=True,
            )

        # Run all YOLO detection checks
        detection = yolo_detector.check_all(
            text=text,
            metadata=metadata,
            session_id=session_id,
        )

        if not detection.detected:
            return YOLOPropagationResult(
                session_id=session_id,
                yolo_detected=False,
                scan_mode_applied="STANDARD",
                risk_multiplier=1.0,
            )

        # Propagate the detection
        return await self.propagate_flag(
            session_id=session_id,
            signals=detection.signals,
            source=source,
        )

    async def propagate_flag(
        self,
        session_id: str,
        *,
        signals: list[str] | None = None,
        risk_multiplier: float | None = None,
        source: str = "yolo_detector",
    ) -> YOLOPropagationResult:
        """Propagate a YOLO flag to a session (called after detection)."""

        # Security guard: validate source
        if source not in _TRUSTED_SOURCES:
            logger.warning(
                "Untrusted source %r attempted to set YOLO flag for session %s",
                source,
                session_id,
            )
            return YOLOPropagationResult(
                session_id=session_id,
                yolo_detected=False,
            )

        multiplier = risk_multiplier or self._default_multiplier

        # Create flag
        flag = YOLOSessionFlag(
            session_id=session_id,
            detected=True,
            signals=signals or [],
            risk_multiplier=multiplier,
            source=source,
        )

        # Store in memory
        self._flags[session_id] = flag

        # 1. Lock session to STRICT scan mode
        try:
            from app.services.session_scan_config import session_scan_config

            await session_scan_config.set_mode(
                session_id,
                "STRICT",
                reason=f"YOLO mode detected: {'; '.join(flag.signals[:3])}",
                set_by="yolo_detector",
                risk_multiplier=multiplier,
                lock=True,
            )
        except Exception:
            logger.warning(
                "Failed to lock session %s to STRICT mode",
                session_id,
                exc_info=True,
            )

        # 2. Persist to MongoDB
        try:
            from app.db import mongodb as db_module

            db = db_module.get_database()
            await db[YOLO_FLAGS_COLLECTION].update_one(
                {"session_id": session_id},
                {"$set": flag.model_dump(mode="json")},
                upsert=True,
            )
        except Exception:
            logger.warning(
                "Failed to persist YOLO flag for session %s",
                session_id,
                exc_info=True,
            )

        # 3. Emit Kafka event
        try:
            from app.services.kafka_producer import kafka_producer

            await kafka_producer.send(
                topic="agentpep.yolo",
                value={
                    "event_type": "YOLO_DETECTED",
                    "session_id": session_id,
                    "signals": flag.signals,
                    "risk_multiplier": multiplier,
                    "source": source,
                    "timestamp": flag.propagated_at.isoformat(),
                },
            )
        except Exception:
            logger.debug("Kafka event send failed (non-critical)")

        # 4. Emit Prometheus metric
        try:
            from app.core.observability import SECURITY_ALERT_TOTAL

            SECURITY_ALERT_TOTAL.labels(
                alert_type="YOLO_MODE",
                severity="CRITICAL",
            ).inc()
        except Exception:
            pass

        logger.info(
            "YOLO flag propagated for session %s: %s",
            session_id,
            "; ".join(flag.signals[:3]),
        )

        return YOLOPropagationResult(
            session_id=session_id,
            yolo_detected=True,
            signals=flag.signals,
            scan_mode_applied="STRICT",
            risk_multiplier=multiplier,
            flag_propagated=True,
        )

    def is_flagged(self, session_id: str) -> bool:
        """Check if a session is flagged as YOLO mode (in-memory fast path)."""
        flag = self._flags.get(session_id)
        return flag.detected if flag else False

    def get_flag(self, session_id: str) -> YOLOSessionFlag | None:
        """Get the YOLO flag for a session."""
        return self._flags.get(session_id)

    async def clear_flag(
        self,
        session_id: str,
        *,
        source: str = "admin",
    ) -> bool:
        """Clear a YOLO flag (admin only).

        Security guard: only admin source can clear a locked flag.
        """
        if source != "admin":
            flag = self._flags.get(session_id)
            if flag and flag.locked:
                logger.warning(
                    "Non-admin source %r attempted to clear locked YOLO flag for %s",
                    source,
                    session_id,
                )
                return False

        self._flags.pop(session_id, None)

        try:
            from app.db import mongodb as db_module

            db = db_module.get_database()
            await db[YOLO_FLAGS_COLLECTION].delete_one(
                {"session_id": session_id}
            )
        except Exception:
            logger.warning(
                "Failed to clear YOLO flag for %s",
                session_id,
                exc_info=True,
            )

        # Unlock session scan config
        try:
            from app.services.session_scan_config import session_scan_config

            await session_scan_config.remove_config(session_id)
        except Exception:
            pass

        return True

    async def list_flags(
        self,
        limit: int = 100,
        active_only: bool = True,
    ) -> YOLOSessionFlagListResponse:
        """List all YOLO session flags."""
        try:
            from app.db import mongodb as db_module

            db = db_module.get_database()
            query: dict = {}
            if active_only:
                query["detected"] = True

            cursor = (
                db[YOLO_FLAGS_COLLECTION]
                .find(query, {"_id": 0})
                .sort("propagated_at", -1)
                .limit(limit)
            )
            flags = [YOLOSessionFlag.model_validate(doc) async for doc in cursor]
            total = await db[YOLO_FLAGS_COLLECTION].count_documents(query)
            return YOLOSessionFlagListResponse(flags=flags, total=total)
        except Exception:
            logger.warning("Failed to list YOLO flags", exc_info=True)
            return YOLOSessionFlagListResponse()

    def clear_all(self) -> None:
        """Clear all in-memory flags (for testing)."""
        self._flags.clear()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

yolo_session_propagator = YOLOSessionPropagator()
