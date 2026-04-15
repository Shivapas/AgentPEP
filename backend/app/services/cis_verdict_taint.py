"""CIS Scan Verdict as Taint Input — Sprint 55 (APEP-439).

Converts CIS (Content Ingestion Security) scan verdicts into taint
signals within the session taint graph.  When a CIS scan detects
SUSPICIOUS or MALICIOUS content, the corresponding taint level is
automatically applied to the session.

Verdict mapping:
  CLEAN      → no taint (TRUSTED)
  SUSPICIOUS → UNTRUSTED
  MALICIOUS  → QUARANTINE

This bridge operates alongside the auto-taint feature in CIS scan
endpoints and provides a dedicated service for applying verdicts
from external or deferred scans.
"""

from __future__ import annotations

import logging
import time

from app.db import mongodb as db_module
from app.models.camel_seq import (
    BridgeVerdictLevel,
    CISVerdictTaintRequest,
    CISVerdictTaintResponse,
)

logger = logging.getLogger(__name__)

# MongoDB collection for verdict-taint bridge events
CIS_VERDICT_TAINT_COLLECTION = "cis_verdict_taint_events"

# Verdict-to-taint level mapping
_VERDICT_TO_TAINT: dict[BridgeVerdictLevel, str | None] = {
    BridgeVerdictLevel.CLEAN: None,
    BridgeVerdictLevel.SUSPICIOUS: "UNTRUSTED",
    BridgeVerdictLevel.MALICIOUS: "QUARANTINE",
}


class CISVerdictTaintService:
    """Applies CIS scan verdicts as taint signals to sessions (APEP-439)."""

    async def apply_verdict(
        self,
        request: CISVerdictTaintRequest,
    ) -> CISVerdictTaintResponse:
        """Apply a CIS scan verdict as a taint signal to the session.

        Args:
            request: The verdict taint request.

        Returns:
            CISVerdictTaintResponse with application status.
        """
        taint_level = _VERDICT_TO_TAINT.get(request.verdict)

        if taint_level is None or not request.auto_taint:
            # CLEAN verdict or auto-taint disabled — record but don't apply
            await self._record_event(request, applied=False, taint_level=None)
            return CISVerdictTaintResponse(
                applied=False,
                taint_level=None,
                session_id=request.session_id,
                detail=f"CIS verdict {request.verdict.value}: no taint applied",
            )

        # Apply taint to session via taint graph
        applied = False
        try:
            from app.models.policy import TaintLevel as TL
            from app.models.policy import TaintSource
            from app.services.taint_graph import session_graph_manager

            tl = TL(taint_level)
            graph = session_graph_manager.get_or_create(request.session_id)
            graph.add_node(
                source=TaintSource.TOOL_OUTPUT,
                value=(
                    f"cis_verdict:{request.source_path or 'unknown'} "
                    f"verdict={request.verdict.value} "
                    f"findings={request.findings_count}"
                ),
                taint_level=tl,
            )
            applied = True
            logger.info(
                "CIS verdict taint applied: session=%s, verdict=%s, taint=%s",
                request.session_id,
                request.verdict.value,
                taint_level,
            )
        except Exception:
            logger.warning(
                "Failed to apply CIS verdict taint to session %s",
                request.session_id,
                exc_info=True,
            )

        await self._record_event(request, applied=applied, taint_level=taint_level)

        return CISVerdictTaintResponse(
            applied=applied,
            taint_level=taint_level if applied else None,
            session_id=request.session_id,
            detail=(
                f"CIS verdict {request.verdict.value} → taint {taint_level}"
                if applied
                else f"Failed to apply taint for verdict {request.verdict.value}"
            ),
        )

    async def _record_event(
        self,
        request: CISVerdictTaintRequest,
        applied: bool,
        taint_level: str | None,
    ) -> None:
        """Record the verdict-taint event to MongoDB."""
        try:
            db = db_module.get_database()
            event = {
                "session_id": request.session_id,
                "scan_result_id": request.scan_result_id,
                "verdict": request.verdict.value,
                "source_path": request.source_path,
                "findings_count": request.findings_count,
                "auto_taint": request.auto_taint,
                "applied": applied,
                "taint_level": taint_level,
            }
            await db[CIS_VERDICT_TAINT_COLLECTION].insert_one(event)
        except Exception:
            logger.warning(
                "Failed to record CIS verdict taint event",
                exc_info=True,
            )

    async def get_verdict_events(
        self,
        session_id: str,
        limit: int = 50,
    ) -> list[dict]:
        """Retrieve verdict-taint events for a session."""
        try:
            db = db_module.get_database()
            cursor = (
                db[CIS_VERDICT_TAINT_COLLECTION]
                .find({"session_id": session_id}, {"_id": 0})
                .limit(limit)
            )
            return [doc async for doc in cursor]
        except Exception:
            logger.warning(
                "Failed to fetch CIS verdict events for session %s",
                session_id,
                exc_info=True,
            )
            return []


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

cis_verdict_taint_service = CISVerdictTaintService()
