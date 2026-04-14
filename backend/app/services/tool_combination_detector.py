"""Tool Combination Detector — Sprint 35 (APEP-276).

Maintains a configurable library of suspicious tool pairs (16+) and
problematic sequences (5+).  The detector checks whether the current
tool call, combined with recent session history, forms a known
suspicious pattern.

Suspicious pairs represent two tools that, when used together in a
session, may indicate an attack pattern (e.g. data exfiltration,
privilege escalation, credential theft).  Sequences represent ordered
multi-step attack chains that must occur within a configurable time
window.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Any

from app.db import mongodb as db_module

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ToolCombinationSignature:
    """A suspicious pair of tool patterns."""

    signature_id: str
    tool_a_pattern: str
    tool_b_pattern: str
    risk_boost: float
    category: str
    description: str


@dataclass(frozen=True, slots=True)
class ToolSequenceSignature:
    """A suspicious ordered sequence of tool patterns."""

    signature_id: str
    sequence: tuple[str, ...]
    window_seconds: int
    risk_boost: float
    description: str


@dataclass(frozen=True, slots=True)
class MatchedToolCombination:
    """Result when a suspicious pair is detected."""

    signature_id: str
    tool_a: str
    tool_b: str
    risk_boost: float
    description: str


@dataclass(frozen=True, slots=True)
class MatchedToolSequence:
    """Result when a suspicious sequence is detected."""

    signature_id: str
    matched_tools: tuple[str, ...]
    risk_boost: float
    description: str


@dataclass(frozen=True, slots=True)
class ToolCombinationResult:
    """Aggregated result of all combination checks for a session."""

    matched_pairs: list[MatchedToolCombination] = field(default_factory=list)
    matched_sequences: list[MatchedToolSequence] = field(default_factory=list)
    max_risk_boost: float = 0.0
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ToolCallRecord:
    """Minimal record of a past tool call for sequence analysis."""

    tool_name: str
    timestamp: float
    agent_id: str = ""


# ---------------------------------------------------------------------------
# Suspicious pair library (16+ pairs)
# ---------------------------------------------------------------------------

_SUSPICIOUS_PAIRS: list[ToolCombinationSignature] = [
    ToolCombinationSignature(
        signature_id="TC-001",
        tool_a_pattern="*.read",
        tool_b_pattern="http.post",
        risk_boost=0.8,
        category="data_exfiltration",
        description="File read followed by HTTP POST suggests data exfiltration",
    ),
    ToolCombinationSignature(
        signature_id="TC-002",
        tool_a_pattern="secret.*",
        tool_b_pattern="http.*",
        risk_boost=0.9,
        category="credential_theft",
        description="Secret access combined with HTTP call suggests credential exfiltration",
    ),
    ToolCombinationSignature(
        signature_id="TC-003",
        tool_a_pattern="db.query",
        tool_b_pattern="file.write",
        risk_boost=0.7,
        category="data_exfiltration",
        description="Database query followed by file write suggests data dumping",
    ),
    ToolCombinationSignature(
        signature_id="TC-004",
        tool_a_pattern="admin.list_users",
        tool_b_pattern="file.write",
        risk_boost=0.7,
        category="reconnaissance",
        description="User enumeration dumped to file suggests reconnaissance",
    ),
    ToolCombinationSignature(
        signature_id="TC-005",
        tool_a_pattern="*.read",
        tool_b_pattern="email.send",
        risk_boost=0.8,
        category="data_exfiltration",
        description="File read followed by email send suggests data exfiltration via email",
    ),
    ToolCombinationSignature(
        signature_id="TC-006",
        tool_a_pattern="credential.*",
        tool_b_pattern="http.post",
        risk_boost=0.9,
        category="credential_theft",
        description="Credential access followed by HTTP POST suggests credential theft",
    ),
    ToolCombinationSignature(
        signature_id="TC-007",
        tool_a_pattern="db.query",
        tool_b_pattern="http.post",
        risk_boost=0.8,
        category="data_exfiltration",
        description="Database query followed by HTTP POST suggests DB exfiltration",
    ),
    ToolCombinationSignature(
        signature_id="TC-008",
        tool_a_pattern="file.delete",
        tool_b_pattern="file.delete",
        risk_boost=0.7,
        category="destruction",
        description="Repeated file deletion suggests mass file destruction",
    ),
    ToolCombinationSignature(
        signature_id="TC-009",
        tool_a_pattern="admin.modify_role",
        tool_b_pattern="secret.*",
        risk_boost=0.9,
        category="privilege_escalation",
        description="Role modification followed by secret access suggests privilege escalation",
    ),
    ToolCombinationSignature(
        signature_id="TC-010",
        tool_a_pattern="shell.exec",
        tool_b_pattern="http.post",
        risk_boost=0.9,
        category="data_exfiltration",
        description="Shell execution followed by HTTP POST suggests command output exfiltration",
    ),
    ToolCombinationSignature(
        signature_id="TC-011",
        tool_a_pattern="file.write",
        tool_b_pattern="shell.exec",
        risk_boost=0.9,
        category="malware",
        description="File write followed by shell execution suggests malware drop and execute",
    ),
    ToolCombinationSignature(
        signature_id="TC-012",
        tool_a_pattern="db.drop*",
        tool_b_pattern="db.drop*",
        risk_boost=0.9,
        category="destruction",
        description="Repeated database drop operations suggest mass DB destruction",
    ),
    ToolCombinationSignature(
        signature_id="TC-013",
        tool_a_pattern="admin.create_user",
        tool_b_pattern="admin.modify_role",
        risk_boost=0.8,
        category="privilege_escalation",
        description="User creation followed by role modification suggests backdoor account",
    ),
    ToolCombinationSignature(
        signature_id="TC-014",
        tool_a_pattern="secret.*",
        tool_b_pattern="email.send",
        risk_boost=0.9,
        category="credential_theft",
        description="Secret access followed by email suggests credential leak via email",
    ),
    ToolCombinationSignature(
        signature_id="TC-015",
        tool_a_pattern="file.read",
        tool_b_pattern="file.write",
        risk_boost=0.5,
        category="content_manipulation",
        description="File read followed by file write may indicate content manipulation",
    ),
    ToolCombinationSignature(
        signature_id="TC-016",
        tool_a_pattern="shell.exec",
        tool_b_pattern="file.delete",
        risk_boost=0.8,
        category="cover_tracks",
        description="Shell execution followed by file deletion suggests execute-and-cover-tracks",
    ),
    ToolCombinationSignature(
        signature_id="TC-017",
        tool_a_pattern="admin.list_*",
        tool_b_pattern="http.post",
        risk_boost=0.7,
        category="data_exfiltration",
        description="Admin enumeration followed by HTTP POST suggests recon data exfiltration",
    ),
    ToolCombinationSignature(
        signature_id="TC-018",
        tool_a_pattern="db.query",
        tool_b_pattern="email.send",
        risk_boost=0.8,
        category="data_exfiltration",
        description="Database query followed by email suggests DB exfiltration via email",
    ),
]


# ---------------------------------------------------------------------------
# Suspicious sequence library (5+ sequences)
# ---------------------------------------------------------------------------

_SUSPICIOUS_SEQUENCES: list[ToolSequenceSignature] = [
    ToolSequenceSignature(
        signature_id="TS-001",
        sequence=("secret.*", "*encode*", "http.post"),
        window_seconds=300,
        risk_boost=0.95,
        description="Secret read → encode → HTTP POST: encoded credential exfiltration",
    ),
    ToolSequenceSignature(
        signature_id="TS-002",
        sequence=("db.query", "file.write", "http.post"),
        window_seconds=300,
        risk_boost=0.9,
        description="DB query → file write → HTTP POST: staged data exfiltration",
    ),
    ToolSequenceSignature(
        signature_id="TS-003",
        sequence=("admin.list_*", "admin.create_user", "admin.modify_role"),
        window_seconds=600,
        risk_boost=0.9,
        description="User listing → creation → role change: backdoor account creation",
    ),
    ToolSequenceSignature(
        signature_id="TS-004",
        sequence=("file.write", "shell.exec", "file.delete"),
        window_seconds=300,
        risk_boost=0.95,
        description="File write → exec → delete: malware drop, execute, and clean up",
    ),
    ToolSequenceSignature(
        signature_id="TS-005",
        sequence=("*.read", "*.read", "http.post"),
        window_seconds=300,
        risk_boost=0.8,
        description="Multiple reads → HTTP POST: bulk data collection and exfiltration",
    ),
    ToolSequenceSignature(
        signature_id="TS-006",
        sequence=("admin.modify_role", "secret.*", "http.post"),
        window_seconds=600,
        risk_boost=0.95,
        description="Role escalation → secret access → exfiltration: full privilege escalation chain",
    ),
]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class ToolCombinationDetector:
    """Detects suspicious tool combinations and sequences in sessions.

    Maintains a configurable library of suspicious tool pairs and multi-step
    attack sequences.  The detector is stateless — session history is fetched
    from the audit_decisions collection on each check.
    """

    def __init__(
        self,
        pairs: list[ToolCombinationSignature] | None = None,
        sequences: list[ToolSequenceSignature] | None = None,
    ) -> None:
        self._pairs = pairs if pairs is not None else list(_SUSPICIOUS_PAIRS)
        self._sequences = sequences if sequences is not None else list(_SUSPICIOUS_SEQUENCES)

    @property
    def pairs(self) -> list[ToolCombinationSignature]:
        return list(self._pairs)

    @property
    def sequences(self) -> list[ToolSequenceSignature]:
        return list(self._sequences)

    # -- Pair detection ----------------------------------------------------

    def check_pair(self, tool_a: str, tool_b: str) -> list[MatchedToolCombination]:
        """Check if two tools form any suspicious pair.

        Matches are bidirectional — (tool_a, tool_b) and (tool_b, tool_a) are
        both checked against each signature's (tool_a_pattern, tool_b_pattern).
        """
        matches: list[MatchedToolCombination] = []
        for sig in self._pairs:
            if (
                fnmatch(tool_a, sig.tool_a_pattern) and fnmatch(tool_b, sig.tool_b_pattern)
            ) or (
                fnmatch(tool_b, sig.tool_a_pattern) and fnmatch(tool_a, sig.tool_b_pattern)
            ):
                matches.append(
                    MatchedToolCombination(
                        signature_id=sig.signature_id,
                        tool_a=tool_a,
                        tool_b=tool_b,
                        risk_boost=sig.risk_boost,
                        description=sig.description,
                    )
                )
        return matches

    # -- Sequence detection ------------------------------------------------

    def check_sequence(
        self, tool_history: list[ToolCallRecord]
    ) -> list[MatchedToolSequence]:
        """Scan a tool call history for suspicious sequences.

        Each sequence signature defines an ordered list of glob patterns and a
        time window.  A match requires that the tools appear in order within
        the window.
        """
        if not tool_history:
            return []

        matches: list[MatchedToolSequence] = []
        for sig in self._sequences:
            matched = self._match_sequence(tool_history, sig)
            if matched is not None:
                matches.append(matched)
        return matches

    @staticmethod
    def _match_sequence(
        history: list[ToolCallRecord],
        sig: ToolSequenceSignature,
    ) -> MatchedToolSequence | None:
        """Attempt to match a single sequence signature against history.

        Scans forward through history looking for ordered pattern matches
        within the time window.
        """
        seq_patterns = sig.sequence
        if not seq_patterns:
            return None

        # Try starting from each position where the first pattern matches
        for start_idx, record in enumerate(history):
            if not fnmatch(record.tool_name, seq_patterns[0]):
                continue

            anchor_time = record.timestamp
            matched_tools: list[str] = [record.tool_name]
            pattern_idx = 1

            for subsequent in history[start_idx + 1 :]:
                if subsequent.timestamp - anchor_time > sig.window_seconds:
                    break
                if pattern_idx < len(seq_patterns) and fnmatch(
                    subsequent.tool_name, seq_patterns[pattern_idx]
                ):
                    matched_tools.append(subsequent.tool_name)
                    pattern_idx += 1
                    if pattern_idx == len(seq_patterns):
                        return MatchedToolSequence(
                            signature_id=sig.signature_id,
                            matched_tools=tuple(matched_tools),
                            risk_boost=sig.risk_boost,
                            description=sig.description,
                        )

        return None

    # -- Session-level orchestrator ----------------------------------------

    async def check_session(
        self,
        session_id: str,
        current_tool: str,
    ) -> ToolCombinationResult:
        """Check the current tool against session history for suspicious patterns.

        Fetches recent audit decisions for the session, checks pairs between
        the current tool and all recent tools, and checks for sequence matches
        including the current tool.
        """
        history = await self._fetch_session_history(session_id)

        # -- Pair checks ---------------------------------------------------
        all_pair_matches: list[MatchedToolCombination] = []
        seen_tools: set[str] = set()
        for record in history:
            if record.tool_name not in seen_tools:
                pair_matches = self.check_pair(current_tool, record.tool_name)
                all_pair_matches.extend(pair_matches)
                seen_tools.add(record.tool_name)

        # -- Sequence checks -----------------------------------------------
        # Append the current tool to history for sequence analysis
        full_history = list(history) + [
            ToolCallRecord(tool_name=current_tool, timestamp=time.time())
        ]
        seq_matches = self.check_sequence(full_history)

        # -- Aggregate result ----------------------------------------------
        all_boosts = [m.risk_boost for m in all_pair_matches] + [
            m.risk_boost for m in seq_matches
        ]
        max_boost = max(all_boosts) if all_boosts else 0.0

        detail_parts: list[str] = []
        if all_pair_matches:
            ids = [m.signature_id for m in all_pair_matches]
            detail_parts.append(f"Suspicious pairs: {', '.join(ids)}")
        if seq_matches:
            ids = [m.signature_id for m in seq_matches]
            detail_parts.append(f"Suspicious sequences: {', '.join(ids)}")

        return ToolCombinationResult(
            matched_pairs=all_pair_matches,
            matched_sequences=seq_matches,
            max_risk_boost=max_boost,
            detail="; ".join(detail_parts) if detail_parts else "No suspicious combinations detected",
        )

    @staticmethod
    async def _fetch_session_history(
        session_id: str,
        limit: int = 50,
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
                .limit(limit)
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
            logger.warning("Failed to fetch session history for tool combination check", exc_info=True)
            return []


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

tool_combination_detector = ToolCombinationDetector()
