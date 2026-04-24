"""PostToolUse OCSF event schema — full TrustFabric OCSF Profile implementation.

Emitted after every tool call (ALLOW and DENY) as part of the tamper-evident
PostToolUse event stream delivered to TrustSOC via Kafka.

OCSF class assignment:
  class_uid  = 4001   (Tool Activity — TrustFabric AgentPEP extension)
  class_name = "TOOL_ACTIVITY"
  category   = 4 / FINDINGS

Activity IDs:
  1 → EXECUTE  (tool ran after ALLOW decision)
  2 → DENY     (tool blocked before execution)
  3 → ERROR    (tool ran but threw an exception)
  4 → TIMEOUT  (tool or evaluation timed out)

Sequence ID:
  Derived from ToolCallRequest.request_id — shared with the PreToolUse
  enforcement decision event so TrustSOC consumers can join the full
  invocation lifecycle.

Blast radius score:
  Included as a placeholder field (null until Sprint S-E08 integrates the
  AAPM Blast Radius Calculator API).

Sprint S-E07 (E07-T01, E07-T02, E07-T03, E07-T04)
"""

from __future__ import annotations

import time
from typing import Any

from app.core.structured_logging import get_logger
from app.events.event_signer import try_sign_event
from app.events.sequence_id import sequence_id_from_request

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# OCSF constants
# ---------------------------------------------------------------------------

_OCSF_CLASS_UID = 4001
_OCSF_CLASS_NAME = "TOOL_ACTIVITY"
_OCSF_CATEGORY_UID = 4
_OCSF_CATEGORY_NAME = "FINDINGS"

_ACTIVITY_EXECUTE = 1
_ACTIVITY_DENY = 2
_ACTIVITY_ERROR = 3
_ACTIVITY_TIMEOUT = 4

_ACTIVITY_NAME = {
    _ACTIVITY_EXECUTE: "EXECUTE",
    _ACTIVITY_DENY: "DENY",
    _ACTIVITY_ERROR: "ERROR",
    _ACTIVITY_TIMEOUT: "TIMEOUT",
}

_SEVERITY_INFO = 1
_SEVERITY_HIGH = 3

_OCSF_PROFILE = "TrustFabric/AgentPEP/v1.0"

# Tool outcomes and their OCSF activity mappings
OUTCOME_EXECUTED = "EXECUTED"
OUTCOME_DENIED = "DENIED"
OUTCOME_ERROR = "ERROR"
OUTCOME_TIMEOUT = "TIMEOUT"

_OUTCOME_TO_ACTIVITY = {
    OUTCOME_EXECUTED: _ACTIVITY_EXECUTE,
    OUTCOME_DENIED: _ACTIVITY_DENY,
    OUTCOME_ERROR: _ACTIVITY_ERROR,
    OUTCOME_TIMEOUT: _ACTIVITY_TIMEOUT,
}


def build_post_tool_use_event(
    *,
    request_id: str,
    session_id: str,
    agent_id: str,
    tool_name: str,
    tool_outcome: str,
    decision: str,
    risk_score: float = 0.0,
    taint_flags: list[str] | None = None,
    matched_rule_id: str | None = None,
    latency_ms: int = 0,
    delegation_chain: list[str] | None = None,
    tenant_id: str = "default",
    bundle_version: str = "",
    tool_result_summary: str | None = None,
    tool_result_error: str | None = None,
    pre_decision_time_ms: int = 0,
    blast_radius_score: float | None = None,
) -> dict[str, Any]:
    """Build a full OCSF PostToolUse event dict.

    Args:
        request_id:           ToolCallRequest.request_id — used as sequence_id.
        session_id:           Session identifier for correlation.
        agent_id:             Agent that made the tool call.
        tool_name:            Name of the tool that was invoked.
        tool_outcome:         One of EXECUTED, DENIED, ERROR, TIMEOUT.
        decision:             Policy decision (ALLOW, DENY, MODIFY, …).
        risk_score:           Risk score from policy evaluation [0.0, 1.0].
        taint_flags:          Taint level flags from the decision response.
        matched_rule_id:      Rule that produced the decision (str or None).
        latency_ms:           PreToolUse evaluation latency in milliseconds.
        delegation_chain:     Principal chain from root to current agent.
        tenant_id:            Tenant identifier for multi-tenant deployments.
        bundle_version:       AAPM policy bundle version active at decision time.
        tool_result_summary:  Redacted/summarised tool output (EXECUTED only).
        tool_result_error:    Error message (ERROR outcome only).
        pre_decision_time_ms: Epoch ms when the PreToolUse decision was made.
        blast_radius_score:   AAPM blast radius score (null until S-E08).

    Returns:
        A signed OCSF event dict ready for Kafka publication.
    """
    now_ms = int(time.time() * 1000)
    sequence_id = sequence_id_from_request(request_id)

    activity_id = _OUTCOME_TO_ACTIVITY.get(tool_outcome, _ACTIVITY_DENY)
    activity_name = _ACTIVITY_NAME[activity_id]
    severity_id = _SEVERITY_INFO if tool_outcome == OUTCOME_EXECUTED else _SEVERITY_HIGH
    severity = "INFO" if tool_outcome == OUTCOME_EXECUTED else "HIGH"
    type_uid = _OCSF_CLASS_UID * 100 + activity_id

    event: dict[str, Any] = {
        # OCSF envelope
        "class_uid": _OCSF_CLASS_UID,
        "class_name": _OCSF_CLASS_NAME,
        "category_uid": _OCSF_CATEGORY_UID,
        "category_name": _OCSF_CATEGORY_NAME,
        "activity_id": activity_id,
        "activity_name": activity_name,
        "severity_id": severity_id,
        "severity": severity,
        "type_uid": type_uid,
        "time": now_ms,
        "start_time": pre_decision_time_ms or now_ms,
        # Metadata
        "metadata": {
            "version": "1.0.0",
            "product": {
                "name": "AgentPEP",
                "vendor_name": "TrustFabric",
            },
            "event_code": "POSTTOOLUSE",
            "profile": _OCSF_PROFILE,
            "bundle_version": bundle_version,
        },
        # Actor context
        "actor": {
            "agent_id": agent_id,
            "session_id": session_id,
            "tenant_id": tenant_id,
            "delegation_chain": delegation_chain or [],
        },
        # Resource under evaluation
        "resources": [
            {
                "type": "tool_call",
                "name": tool_name,
                "uid": sequence_id,
            }
        ],
        # Correlation
        "observables": [
            {
                "name": "sequence_id",
                "value": sequence_id,
                "type": "Resource UID",
            }
        ],
        # Finding details
        "finding_info": {
            "title": f"PostToolUse event for tool '{tool_name}'",
            "uid": sequence_id,
            "sequence_id": sequence_id,
            "related_events": [sequence_id],
        },
        # Policy decision context
        "decision": decision,
        "tool_outcome": tool_outcome,
        "risk_score": risk_score,
        "taint_flags": taint_flags or [],
        "matched_rule_id": matched_rule_id,
        "latency_ms": latency_ms,
        # PostToolUse-specific fields
        "tool_name": tool_name,
        "tool_args_included": False,
        "tool_result_summary": tool_result_summary,
        "tool_result_error": tool_result_error,
        # Blast radius score — placeholder until Sprint S-E08
        "blast_radius_score": blast_radius_score,
    }

    # HMAC sign the event (tamper-evident stream)
    event = try_sign_event(event)

    return event


def emit_post_tool_use_event(
    *,
    request_id: str,
    session_id: str,
    agent_id: str,
    tool_name: str,
    tool_outcome: str,
    decision: str,
    risk_score: float = 0.0,
    taint_flags: list[str] | None = None,
    matched_rule_id: str | None = None,
    latency_ms: int = 0,
    delegation_chain: list[str] | None = None,
    tenant_id: str = "default",
    bundle_version: str = "",
    tool_result_summary: str | None = None,
    tool_result_error: str | None = None,
    pre_decision_time_ms: int = 0,
    blast_radius_score: float | None = None,
) -> dict[str, Any]:
    """Build, log, and return a PostToolUse OCSF event.

    Kafka publication is handled separately by the PostToolUse hook invoker
    so this function stays synchronous and usable in non-async contexts.

    Returns the event dict (useful in tests to inspect the emitted event).
    """
    event = build_post_tool_use_event(
        request_id=request_id,
        session_id=session_id,
        agent_id=agent_id,
        tool_name=tool_name,
        tool_outcome=tool_outcome,
        decision=decision,
        risk_score=risk_score,
        taint_flags=taint_flags,
        matched_rule_id=matched_rule_id,
        latency_ms=latency_ms,
        delegation_chain=delegation_chain,
        tenant_id=tenant_id,
        bundle_version=bundle_version,
        tool_result_summary=tool_result_summary,
        tool_result_error=tool_result_error,
        pre_decision_time_ms=pre_decision_time_ms,
        blast_radius_score=blast_radius_score,
    )

    logger.info(
        "POSTTOOLUSE",
        event_class="POSTTOOLUSE",
        tool_name=tool_name,
        tool_outcome=tool_outcome,
        decision=decision,
        session_id=session_id,
        agent_id=agent_id,
        risk_score=risk_score,
        sequence_id=event["finding_info"]["sequence_id"],
        signed=bool(event["metadata"].get("hmac_signature")),
    )

    return event
