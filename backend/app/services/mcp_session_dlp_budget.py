"""MCP session DLP budget — per-session DLP finding/data budget tracking.

Sprint 48 — APEP-385: Tracks cumulative DLP findings and scanned data volume
per MCP proxy session. When a session exceeds its budget (too many findings
or too much data scanned), subsequent tool calls are blocked.

This prevents a compromised or misbehaving MCP server from gradually
exfiltrating data across many small tool calls within a single session.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from app.models.mcp_security import MCPDLPFinding, MCPSessionDLPBudget

logger = logging.getLogger(__name__)


class MCPSessionDLPBudgetTracker:
    """Tracks DLP budgets per MCP proxy session.

    Each session has configurable limits on:
      - Total DLP findings before the session is blocked
      - Total CRITICAL findings before the session is blocked
      - Total outbound bytes scanned
      - Total inbound bytes scanned

    When any budget is exceeded, the session is marked as over-budget
    and subsequent tool calls should be denied.
    """

    def __init__(self) -> None:
        self._budgets: dict[str, MCPSessionDLPBudget] = {}

    def create_budget(
        self,
        session_id: str,
        agent_id: str,
        *,
        max_dlp_findings: int = 10,
        max_critical_findings: int = 3,
        max_outbound_bytes: int = 104_857_600,
        max_inbound_bytes: int = 524_288_000,
    ) -> MCPSessionDLPBudget:
        """Create a DLP budget for a new MCP session.

        Args:
            session_id: MCP proxy session ID.
            agent_id: Agent ID for the session.
            max_dlp_findings: Maximum total DLP findings allowed.
            max_critical_findings: Maximum CRITICAL findings allowed.
            max_outbound_bytes: Maximum outbound data volume (bytes).
            max_inbound_bytes: Maximum inbound data volume (bytes).

        Returns:
            The created MCPSessionDLPBudget.
        """
        budget = MCPSessionDLPBudget(
            session_id=session_id,
            agent_id=agent_id,
            max_dlp_findings=max_dlp_findings,
            max_critical_findings=max_critical_findings,
            max_outbound_bytes_scanned=max_outbound_bytes,
            max_inbound_bytes_scanned=max_inbound_bytes,
        )
        self._budgets[session_id] = budget
        logger.debug(
            "DLP budget created: session=%s max_findings=%d max_critical=%d",
            session_id,
            max_dlp_findings,
            max_critical_findings,
        )
        return budget

    def get_budget(self, session_id: str) -> MCPSessionDLPBudget | None:
        """Get the DLP budget for a session."""
        return self._budgets.get(session_id)

    def record_findings(
        self,
        session_id: str,
        findings: list[MCPDLPFinding],
    ) -> MCPSessionDLPBudget | None:
        """Record DLP findings against a session's budget.

        Args:
            session_id: MCP proxy session ID.
            findings: List of DLP findings to record.

        Returns:
            Updated budget, or None if no budget exists.
        """
        budget = self._budgets.get(session_id)
        if budget is None:
            return None

        for finding in findings:
            budget.current_dlp_findings += 1
            if finding.severity == "CRITICAL":
                budget.current_critical_findings += 1

        budget.updated_at = datetime.now(UTC)
        self._check_exceeded(budget)
        return budget

    def record_bytes_scanned(
        self,
        session_id: str,
        *,
        outbound_bytes: int = 0,
        inbound_bytes: int = 0,
    ) -> MCPSessionDLPBudget | None:
        """Record bytes scanned against a session's data budget.

        Args:
            session_id: MCP proxy session ID.
            outbound_bytes: Bytes of outbound data scanned.
            inbound_bytes: Bytes of inbound data scanned.

        Returns:
            Updated budget, or None if no budget exists.
        """
        budget = self._budgets.get(session_id)
        if budget is None:
            return None

        budget.outbound_bytes_scanned += outbound_bytes
        budget.inbound_bytes_scanned += inbound_bytes
        budget.updated_at = datetime.now(UTC)
        self._check_exceeded(budget)
        return budget

    def is_exceeded(self, session_id: str) -> bool:
        """Check if a session's DLP budget is exceeded."""
        budget = self._budgets.get(session_id)
        if budget is None:
            return False
        return budget.budget_exceeded

    def remove_budget(self, session_id: str) -> None:
        """Remove the DLP budget for a session (called on session end)."""
        self._budgets.pop(session_id, None)

    def _check_exceeded(self, budget: MCPSessionDLPBudget) -> None:
        """Check if any budget limit has been exceeded and update state."""
        if budget.budget_exceeded:
            return  # Already exceeded

        if budget.current_dlp_findings >= budget.max_dlp_findings:
            budget.budget_exceeded = True
            budget.exceeded_reason = (
                f"DLP finding count ({budget.current_dlp_findings}) "
                f"exceeded limit ({budget.max_dlp_findings})"
            )
        elif budget.current_critical_findings >= budget.max_critical_findings:
            budget.budget_exceeded = True
            budget.exceeded_reason = (
                f"CRITICAL finding count ({budget.current_critical_findings}) "
                f"exceeded limit ({budget.max_critical_findings})"
            )
        elif budget.outbound_bytes_scanned >= budget.max_outbound_bytes_scanned:
            budget.budget_exceeded = True
            budget.exceeded_reason = (
                f"Outbound bytes ({budget.outbound_bytes_scanned}) "
                f"exceeded limit ({budget.max_outbound_bytes_scanned})"
            )
        elif budget.inbound_bytes_scanned >= budget.max_inbound_bytes_scanned:
            budget.budget_exceeded = True
            budget.exceeded_reason = (
                f"Inbound bytes ({budget.inbound_bytes_scanned}) "
                f"exceeded limit ({budget.max_inbound_bytes_scanned})"
            )

        if budget.budget_exceeded:
            logger.warning(
                "DLP budget exceeded: session=%s reason=%s",
                budget.session_id,
                budget.exceeded_reason,
            )


# Module-level singleton
mcp_session_dlp_budget_tracker = MCPSessionDLPBudgetTracker()
