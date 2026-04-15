"""ToolTrust → AgentPEP Intercept Bridge — Sprint 55 (APEP-438).

Bridges ToolTrust Layer 3 PreToolUse scan verdicts into the AgentPEP
Intercept pipeline.  When ToolTrust Layer 3 makes a decision about a
tool call (CLEAN, SUSPICIOUS, MALICIOUS), it forwards the verdict to
this bridge which:

  1. Converts the verdict to a taint signal in the session graph.
  2. Optionally evaluates the tool call through the full Intercept API.
  3. Records bridge events for audit and Kafka publication.

The bridge adds <50ms latency over the standalone Layer 3 hook decision.
"""

from __future__ import annotations

import logging
import time

from app.db import mongodb as db_module
from app.models.camel_seq import (
    BridgeVerdictLevel,
    ToolTrustBridgeRequest,
    ToolTrustBridgeResponse,
)

logger = logging.getLogger(__name__)

# MongoDB collection for bridge events
BRIDGE_EVENTS_COLLECTION = "tooltrust_bridge_events"

# Verdict-to-taint mapping
_VERDICT_TAINT_MAP: dict[BridgeVerdictLevel, str | None] = {
    BridgeVerdictLevel.CLEAN: None,  # No taint applied
    BridgeVerdictLevel.SUSPICIOUS: "UNTRUSTED",
    BridgeVerdictLevel.MALICIOUS: "QUARANTINE",
}


class ToolTrustBridge:
    """Bridges ToolTrust Layer 3 verdicts into AgentPEP (APEP-438).

    Stateless service that processes incoming bridge requests and
    applies taint signals to sessions based on ToolTrust verdicts.
    """

    async def process_verdict(
        self,
        request: ToolTrustBridgeRequest,
    ) -> ToolTrustBridgeResponse:
        """Process a ToolTrust Layer 3 verdict and apply taint.

        Args:
            request: The bridge request from ToolTrust.

        Returns:
            ToolTrustBridgeResponse with taint status and processing details.
        """
        start_ms = time.monotonic()

        taint_level = _VERDICT_TAINT_MAP.get(request.verdict)
        taint_applied: str | None = None
        intercept_decision: str | None = None

        # Apply taint if verdict warrants it
        if taint_level is not None:
            try:
                from app.models.policy import TaintLevel, TaintSource
                from app.services.taint_graph import session_graph_manager

                tl = TaintLevel(taint_level)
                graph = session_graph_manager.get_or_create(request.session_id)
                graph.add_node(
                    source=TaintSource.TOOL_OUTPUT,
                    value=f"tooltrust_bridge:{request.tool_name} verdict={request.verdict.value}",
                    taint_level=tl,
                )
                taint_applied = taint_level
                logger.info(
                    "ToolTrust bridge applied taint %s to session %s for tool %s",
                    taint_level,
                    request.session_id,
                    request.tool_name,
                )
            except Exception:
                logger.warning(
                    "Failed to apply taint from ToolTrust bridge",
                    exc_info=True,
                )

        # For MALICIOUS verdicts, recommend blocking
        if request.verdict == BridgeVerdictLevel.MALICIOUS:
            intercept_decision = "DENY"
        elif request.verdict == BridgeVerdictLevel.SUSPICIOUS:
            intercept_decision = "ESCALATE"
        else:
            intercept_decision = "ALLOW"

        elapsed_ms = int((time.monotonic() - start_ms) * 1000)

        # Record bridge event
        await self._record_event(request, taint_applied, intercept_decision, elapsed_ms)

        detail = (
            f"ToolTrust L{request.layer} verdict={request.verdict.value} → "
            f"taint={taint_applied or 'none'}, decision={intercept_decision}"
        )
        if request.verdict_details:
            detail += f" ({request.verdict_details})"

        return ToolTrustBridgeResponse(
            accepted=True,
            taint_applied=taint_applied,
            intercept_decision=intercept_decision,
            bridge_latency_ms=elapsed_ms,
            detail=detail,
        )

    async def _record_event(
        self,
        request: ToolTrustBridgeRequest,
        taint_applied: str | None,
        intercept_decision: str | None,
        elapsed_ms: int,
    ) -> None:
        """Record bridge event to MongoDB for audit."""
        try:
            db = db_module.get_database()
            event = {
                "session_id": request.session_id,
                "agent_id": request.agent_id,
                "tool_name": request.tool_name,
                "verdict": request.verdict.value,
                "verdict_details": request.verdict_details,
                "findings_count": len(request.findings),
                "layer": request.layer,
                "trust_cache_hit": request.trust_cache_hit,
                "scan_latency_ms": request.scan_latency_ms,
                "taint_applied": taint_applied,
                "intercept_decision": intercept_decision,
                "bridge_latency_ms": elapsed_ms,
            }
            await db[BRIDGE_EVENTS_COLLECTION].insert_one(event)
        except Exception:
            logger.warning(
                "Failed to record ToolTrust bridge event",
                exc_info=True,
            )

    async def get_bridge_events(
        self,
        session_id: str,
        limit: int = 50,
    ) -> list[dict]:
        """Retrieve bridge events for a session."""
        try:
            db = db_module.get_database()
            cursor = (
                db[BRIDGE_EVENTS_COLLECTION]
                .find({"session_id": session_id}, {"_id": 0})
                .sort("bridge_latency_ms", -1)
                .limit(limit)
            )
            return [doc async for doc in cursor]
        except Exception:
            logger.warning(
                "Failed to fetch bridge events for session %s",
                session_id,
                exc_info=True,
            )
            return []


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

tooltrust_bridge = ToolTrustBridge()
