"""TRUST_VIOLATION event — stub OCSF schema (formalised in Sprint S-E07).

Emitted whenever trust enforcement detects a violation in a delegation chain:
  - Subagent claims permissions beyond the root principal's permission set
    (PERMISSION_ESCALATION)
  - Computed trust score falls below the minimum threshold
    (TRUST_BELOW_THRESHOLD)
  - Delegation chain exceeds the configured maximum hop count
    (MAX_HOP_COUNT_EXCEEDED)
  - Delegation chain is structurally invalid (empty, malformed)
    (INVALID_DELEGATION_CHAIN)

The full OCSF schema and Kafka transport are formalised in Sprint S-E07.
This stub emits synchronously to the structured log for immediate audit
visibility.

Sprint S-E06 (E06-T05)
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from app.core.structured_logging import get_logger

logger = get_logger(__name__)

_OCSF_CLASS_UID_SECURITY_FINDING = 4002
_OCSF_ACTIVITY_DENY = 2


class TrustViolationReason(str, Enum):
    """Enumerated reasons for TRUST_VIOLATION events."""

    PERMISSION_ESCALATION = "PERMISSION_ESCALATION"
    TRUST_BELOW_THRESHOLD = "TRUST_BELOW_THRESHOLD"
    MAX_HOP_COUNT_EXCEEDED = "MAX_HOP_COUNT_EXCEEDED"
    INVALID_DELEGATION_CHAIN = "INVALID_DELEGATION_CHAIN"


def emit_trust_violation_event(
    reason: TrustViolationReason,
    detail: str,
    principal_chain: list[str],
    hop_count: int,
    trust_score: float,
    root_principal: str = "",
    agent_id: str = "",
    session_id: str = "",
    request_id: str = "",
    tool_name: str = "",
    escalated_permissions: list[str] | None = None,
) -> dict[str, Any]:
    """Build, log, and return a TRUST_VIOLATION event.

    Args:
        reason:                TrustViolationReason enum value.
        detail:                Human-readable explanation of the violation.
        principal_chain:       Ordered list from root to current agent.
        hop_count:             Number of delegation hops at the violation point.
        trust_score:           Computed trust score at the violation point.
        root_principal:        Identity of the originating root principal.
        agent_id:              Current (leaf) agent identity.
        session_id:            Session identifier for correlation.
        request_id:            Request identifier for correlation.
        tool_name:             Tool call that triggered the evaluation.
        escalated_permissions: Permissions claimed beyond root — populated for
                               PERMISSION_ESCALATION violations only.

    Returns:
        The event dict (useful in tests to inspect emitted events).
    """
    now_ms = int(time.time() * 1000)

    event: dict[str, Any] = {
        # OCSF envelope
        "class_uid": _OCSF_CLASS_UID_SECURITY_FINDING,
        "class_name": "TRUST_VIOLATION",
        "category_uid": 4,
        "category_name": "FINDINGS",
        "activity_id": _OCSF_ACTIVITY_DENY,
        "activity_name": "DENY",
        "severity_id": 5,
        "severity": "CRITICAL",
        "type_uid": 400203,
        "time": now_ms,
        "start_time": now_ms,
        # Metadata
        "metadata": {
            "version": "1.0.0",
            "product": {
                "name": "AgentPEP",
                "vendor_name": "TrustFabric",
            },
            "event_code": "TRUST_VIOLATION",
        },
        # Actor context
        "actor": {
            "agent_id": agent_id,
            "session_id": session_id,
            "principal_chain": principal_chain,
            "root_principal": root_principal,
        },
        # Resource under evaluation
        "resources": [
            {
                "type": "tool_call",
                "name": tool_name or "unknown",
            }
        ],
        # Finding details
        "finding_info": {
            "title": f"Trust enforcement violation: {reason.value}",
            "uid": request_id,
            "reason": reason.value,
            "detail": detail,
            "hop_count": hop_count,
            "trust_score": trust_score,
            "principal_chain": principal_chain,
            "escalated_permissions": escalated_permissions or [],
        },
        # Decision — trust enforcement FAIL_CLOSED: tool call denied
        "decision": "DENY",
        "trust_enforcement_fail_closed": True,
    }

    logger.error(
        "TRUST_VIOLATION",
        event_class="TRUST_VIOLATION",
        reason=reason.value,
        detail=detail,
        hop_count=hop_count,
        trust_score=trust_score,
        principal_chain=principal_chain,
        root_principal=root_principal,
        agent_id=agent_id,
        session_id=session_id,
        escalated_permissions=escalated_permissions or [],
    )

    return event
