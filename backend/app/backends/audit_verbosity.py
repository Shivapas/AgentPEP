"""Configurable audit verbosity levels for AgentPEP audit backends.

Sprint 32 — APEP-253: Configurable audit verbosity with three levels:
MINIMAL (outcome only), STANDARD (identity + scope), FULL (all fields).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class AuditVerbosity(StrEnum):
    """Audit record verbosity levels."""

    MINIMAL = "MINIMAL"
    STANDARD = "STANDARD"
    FULL = "FULL"


# Fields included at each verbosity level.
# Hash-chain fields (sequence_number, record_hash, previous_hash) are always
# included at every level to preserve audit integrity verification.

_MINIMAL_FIELDS: frozenset[str] = frozenset(
    {
        "decision_id",
        "decision",
        "timestamp",
        "sequence_number",
        "record_hash",
        "previous_hash",
    }
)

_STANDARD_FIELDS: frozenset[str] = _MINIMAL_FIELDS | frozenset(
    {
        "agent_id",
        "agent_role",
        "session_id",
        "tool_name",
        "matched_rule_id",
        "risk_score",
        "escalation_id",
    }
)

FIELD_SETS: dict[AuditVerbosity, frozenset[str]] = {
    AuditVerbosity.MINIMAL: _MINIMAL_FIELDS,
    AuditVerbosity.STANDARD: _STANDARD_FIELDS,
    # FULL is a sentinel — all fields pass through unfiltered.
    AuditVerbosity.FULL: frozenset(),
}


def filter_record(
    record: dict[str, Any],
    verbosity: AuditVerbosity,
) -> dict[str, Any]:
    """Return a filtered copy of *record* containing only the fields
    permitted by *verbosity*.

    At FULL verbosity the record is returned as-is (shallow copy).
    """
    if verbosity == AuditVerbosity.FULL:
        return dict(record)

    allowed = FIELD_SETS[verbosity]
    return {k: v for k, v in record.items() if k in allowed}
