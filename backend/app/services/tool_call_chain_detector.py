"""Tool Call Chain Detector — Sprint 49 (APEP-388/389/391).

Orchestrates chain pattern detection against session history.
Fetches tool call history from the audit_decisions collection,
runs the subsequence matching engine against all enabled patterns,
and returns aggregated detection results.

Integrates into the PolicyEvaluator post-decision stage to auto-
escalate or deny when attack chains are detected.
"""

from __future__ import annotations

import logging
import time

from app.db import mongodb as db_module
from app.models.tool_call_chain import (
    ChainCategory,
    ChainDetectionAction,
    ChainDetectionResult,
    ChainMatchResult,
    ChainSeverity,
)
from app.services.chain_pattern_library import chain_pattern_library
from app.services.subsequence_matcher import subsequence_matcher
from app.services.tool_combination_detector import ToolCallRecord

logger = logging.getLogger(__name__)


# Severity ordering for comparison
_SEVERITY_ORDER: dict[ChainSeverity, int] = {
    ChainSeverity.INFO: 0,
    ChainSeverity.LOW: 1,
    ChainSeverity.MEDIUM: 2,
    ChainSeverity.HIGH: 3,
    ChainSeverity.CRITICAL: 4,
}

# Action priority (higher = more restrictive)
_ACTION_ORDER: dict[ChainDetectionAction, int] = {
    ChainDetectionAction.LOG_ONLY: 0,
    ChainDetectionAction.ALERT: 1,
    ChainDetectionAction.ESCALATE: 2,
    ChainDetectionAction.DENY: 3,
}


class ToolCallChainDetector:
    """Detects multi-step attack chains in tool call sessions (APEP-388/391).

    The detector is stateless per invocation — session history is fetched
    from MongoDB's audit_decisions collection on each check.  All enabled
    patterns from the chain_pattern_library are evaluated.
    """

    def __init__(self, history_limit: int = 100) -> None:
        self._history_limit = history_limit

    async def check_session(
        self,
        session_id: str,
        current_tool: str,
        agent_id: str = "",
    ) -> ChainDetectionResult:
        """Check the current tool call against session history for chain patterns.

        Fetches recent audit decisions, appends the current tool, and
        runs all enabled patterns through the subsequence matching engine.
        """
        start_us = time.monotonic()

        history = await self._fetch_session_history(session_id)

        # Append current tool to history for matching
        history.append(
            ToolCallRecord(
                tool_name=current_tool,
                timestamp=time.time(),
                agent_id=agent_id,
            )
        )

        # Get all enabled patterns
        patterns = chain_pattern_library.get_all_enabled()
        if not patterns:
            return ChainDetectionResult(
                session_id=session_id,
                agent_id=agent_id,
                detail="No chain patterns enabled",
            )

        # Run matching engine
        matches = subsequence_matcher.match_all(history, patterns)

        elapsed_us = int((time.monotonic() - start_us) * 1_000_000)

        if not matches:
            return ChainDetectionResult(
                session_id=session_id,
                agent_id=agent_id,
                detail="No chain patterns detected",
                scan_latency_us=elapsed_us,
            )

        # Aggregate results
        max_risk_boost = max(m.risk_boost for m in matches)
        highest_severity = max(
            (m.severity for m in matches),
            key=lambda s: _SEVERITY_ORDER.get(s, 0),
        )
        recommended_action = max(
            (m.action for m in matches),
            key=lambda a: _ACTION_ORDER.get(a, 0),
        )

        detail_parts = [
            f"{m.pattern_name} ({m.pattern_id}): {m.severity.value}"
            for m in matches
        ]

        return ChainDetectionResult(
            session_id=session_id,
            agent_id=agent_id,
            matches=matches,
            total_matches=len(matches),
            max_risk_boost=max_risk_boost,
            highest_severity=highest_severity,
            recommended_action=recommended_action,
            detail=f"Detected {len(matches)} chain(s): {'; '.join(detail_parts)}",
            scan_latency_us=elapsed_us,
        )

    async def check_history(
        self,
        history: list[ToolCallRecord],
        session_id: str = "",
        agent_id: str = "",
    ) -> ChainDetectionResult:
        """Check pre-fetched history against all enabled patterns.

        Useful for testing and batch analysis where history is already
        available.
        """
        start_us = time.monotonic()

        patterns = chain_pattern_library.get_all_enabled()
        matches = subsequence_matcher.match_all(history, patterns)

        elapsed_us = int((time.monotonic() - start_us) * 1_000_000)

        if not matches:
            return ChainDetectionResult(
                session_id=session_id,
                agent_id=agent_id,
                detail="No chain patterns detected",
                scan_latency_us=elapsed_us,
            )

        max_risk_boost = max(m.risk_boost for m in matches)
        highest_severity = max(
            (m.severity for m in matches),
            key=lambda s: _SEVERITY_ORDER.get(s, 0),
        )
        recommended_action = max(
            (m.action for m in matches),
            key=lambda a: _ACTION_ORDER.get(a, 0),
        )

        detail_parts = [
            f"{m.pattern_name} ({m.pattern_id}): {m.severity.value}"
            for m in matches
        ]

        return ChainDetectionResult(
            session_id=session_id,
            agent_id=agent_id,
            matches=matches,
            total_matches=len(matches),
            max_risk_boost=max_risk_boost,
            highest_severity=highest_severity,
            recommended_action=recommended_action,
            detail=f"Detected {len(matches)} chain(s): {'; '.join(detail_parts)}",
            scan_latency_us=elapsed_us,
        )

    async def _fetch_session_history(
        self,
        session_id: str,
    ) -> list[ToolCallRecord]:
        """Fetch recent tool calls for a session from the audit_decisions collection."""
        try:
            db = db_module.get_database()
            cursor = (
                db[db_module.AUDIT_DECISIONS]
                .find(
                    {"session_id": session_id},
                    {"tool_name": 1, "timestamp": 1, "agent_id": 1, "_id": 0},
                )
                .sort("timestamp", -1)
                .limit(self._history_limit)
            )
            records: list[ToolCallRecord] = []
            async for doc in cursor:
                ts = doc.get("timestamp")
                if ts is not None:
                    ts_float = ts.timestamp() if hasattr(ts, "timestamp") else float(ts)
                else:
                    ts_float = 0.0
                records.append(
                    ToolCallRecord(
                        tool_name=doc.get("tool_name", ""),
                        timestamp=ts_float,
                        agent_id=doc.get("agent_id", ""),
                    )
                )
            # Return in chronological order
            records.reverse()
            return records
        except Exception:
            logger.warning(
                "Failed to fetch session history for chain detection",
                exc_info=True,
            )
            return []


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

tool_call_chain_detector = ToolCallChainDetector()
