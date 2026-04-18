"""MCP rug-pull detector — detect mid-session tool description changes.

Sprint 48 — APEP-383: Detects when an MCP server changes tool descriptions,
schemas, or available tools mid-session (a "rug pull"). This can indicate:
  - A compromised MCP server modifying tools after trust is established
  - A malicious server adding injection payloads after initial clean scan
  - Schema changes that could alter tool behavior unexpectedly

The detector maintains per-session snapshots of tool listings and compares
subsequent ``tools/list`` responses to detect changes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

from app.models.mcp_security import (
    RugPullChange,
    RugPullDetectionResult,
    RugPullType,
    ToolDescriptionSnapshot,
)

logger = logging.getLogger(__name__)


class MCPRugPullDetector:
    """Detects mid-session tool description changes (rug pulls).

    Maintains per-session snapshots of tool definitions from ``tools/list``
    responses. When a new ``tools/list`` response arrives, compares it
    against the stored baseline to detect modifications.

    Thread-safe: each session maintains independent state.
    """

    def __init__(self) -> None:
        # session_id -> list of tool snapshots (baseline)
        self._baselines: dict[str, list[ToolDescriptionSnapshot]] = {}

    def set_baseline(
        self, session_id: str, tools: list[dict[str, Any]]
    ) -> list[ToolDescriptionSnapshot]:
        """Store the initial tools/list snapshot as the baseline for a session.

        Args:
            session_id: MCP proxy session ID.
            tools: List of tool definitions from the initial tools/list response.

        Returns:
            List of captured ToolDescriptionSnapshot objects.
        """
        snapshots = self._capture_snapshots(tools)
        self._baselines[session_id] = snapshots
        logger.debug(
            "Rug-pull baseline set: session=%s tools=%d",
            session_id,
            len(snapshots),
        )
        return snapshots

    def has_baseline(self, session_id: str) -> bool:
        """Check if a baseline exists for the given session."""
        return session_id in self._baselines

    def detect(
        self,
        *,
        session_id: str,
        agent_id: str,
        tools: list[dict[str, Any]],
    ) -> RugPullDetectionResult:
        """Compare current tools/list response against stored baseline.

        Args:
            session_id: MCP proxy session ID.
            agent_id: Agent ID for the session.
            tools: Current tools/list response tools array.

        Returns:
            RugPullDetectionResult with any detected changes.
        """
        baseline = self._baselines.get(session_id)
        if baseline is None:
            # No baseline — set one and return clean result
            self.set_baseline(session_id, tools)
            return RugPullDetectionResult(
                session_id=session_id,
                agent_id=agent_id,
            )

        current_snapshots = self._capture_snapshots(tools)
        changes = self._compare(baseline, current_snapshots)

        is_rug_pull = len(changes) > 0
        blocked = any(c.severity == "CRITICAL" for c in changes)

        if is_rug_pull:
            logger.warning(
                "Rug-pull detected: session=%s changes=%d blocked=%s",
                session_id,
                len(changes),
                blocked,
            )
            # Update baseline with current state
            self._baselines[session_id] = current_snapshots

        return RugPullDetectionResult(
            session_id=session_id,
            agent_id=agent_id,
            changes=changes,
            is_rug_pull=is_rug_pull,
            blocked=blocked,
        )

    def clear_session(self, session_id: str) -> None:
        """Remove baseline for a session (called on session end)."""
        self._baselines.pop(session_id, None)

    def _capture_snapshots(
        self, tools: list[dict[str, Any]]
    ) -> list[ToolDescriptionSnapshot]:
        """Capture snapshots from a tools/list response."""
        snapshots = []
        for tool_def in tools:
            snapshots.append(ToolDescriptionSnapshot(
                name=tool_def.get("name", ""),
                description=tool_def.get("description", ""),
                input_schema=tool_def.get(
                    "inputSchema", tool_def.get("input_schema", {})
                ),
            ))
        return snapshots

    def _compare(
        self,
        baseline: list[ToolDescriptionSnapshot],
        current: list[ToolDescriptionSnapshot],
    ) -> list[RugPullChange]:
        """Compare two snapshots and return detected changes."""
        changes: list[RugPullChange] = []

        baseline_map = {s.name: s for s in baseline}
        current_map = {s.name: s for s in current}

        baseline_names = set(baseline_map.keys())
        current_names = set(current_map.keys())

        # Detect removed tools
        for removed in baseline_names - current_names:
            changes.append(RugPullChange(
                tool_name=removed,
                change_type=RugPullType.TOOL_REMOVED,
                severity="HIGH",
                description=f"Tool '{removed}' was removed mid-session",
            ))

        # Detect added tools
        for added in current_names - baseline_names:
            changes.append(RugPullChange(
                tool_name=added,
                change_type=RugPullType.TOOL_ADDED,
                severity="HIGH",
                description=f"Tool '{added}' was added mid-session",
            ))

        # Detect changes in existing tools
        for name in baseline_names & current_names:
            base = baseline_map[name]
            curr = current_map[name]

            if base.description != curr.description:
                changes.append(RugPullChange(
                    tool_name=name,
                    change_type=RugPullType.DESCRIPTION_CHANGED,
                    field="description",
                    old_value=base.description[:200],
                    new_value=curr.description[:200],
                    severity="CRITICAL",
                    description=(
                        f"Tool '{name}' description changed mid-session — "
                        f"possible injection rug-pull"
                    ),
                ))

            base_schema_hash = self._hash_schema(base.input_schema)
            curr_schema_hash = self._hash_schema(curr.input_schema)
            if base_schema_hash != curr_schema_hash:
                changes.append(RugPullChange(
                    tool_name=name,
                    change_type=RugPullType.SCHEMA_CHANGED,
                    field="inputSchema",
                    old_value=base_schema_hash[:16],
                    new_value=curr_schema_hash[:16],
                    severity="HIGH",
                    description=(
                        f"Tool '{name}' input schema changed mid-session"
                    ),
                ))

        return changes

    @staticmethod
    def _hash_schema(schema: dict[str, Any]) -> str:
        """Compute a stable hash of a JSON schema for comparison."""
        canonical = json.dumps(schema, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


# Module-level singleton
mcp_rug_pull_detector = MCPRugPullDetector()
