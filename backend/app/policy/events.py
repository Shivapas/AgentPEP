"""SECURITY_VIOLATION event — stub OCSF schema (formalised in Sprint S-E07).

Emitted whenever the trusted policy loader detects a security-relevant
failure:
  - Invalid or unverifiable cosign signature on a policy bundle
  - Untrusted source path (URL not on the AAPM registry allowlist)
  - Attempt to override the policy source via environment variable

Sprint S-E03 (E03-T04)
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from app.core.structured_logging import get_logger

logger = get_logger(__name__)

_OCSF_CLASS_UID_SECURITY_FINDING = 4002
_OCSF_ACTIVITY_DENY = 2


class SecurityViolationReason(str, Enum):
    """Enumerated reasons for SECURITY_VIOLATION events."""

    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    UNTRUSTED_SOURCE = "UNTRUSTED_SOURCE"
    ENV_VAR_OVERRIDE_ATTEMPT = "ENV_VAR_OVERRIDE_ATTEMPT"
    SIGNATURE_VERIFICATION_ERROR = "SIGNATURE_VERIFICATION_ERROR"
    BUNDLE_FETCH_FROM_UNTRUSTED_HOST = "BUNDLE_FETCH_FROM_UNTRUSTED_HOST"


def emit_security_violation_event(
    reason: SecurityViolationReason,
    detail: str,
    source_url: str = "",
    bundle_version: str = "",
    session_id: str = "",
    agent_id: str = "",
    request_id: str = "",
) -> dict[str, Any]:
    """Build, log, and return a SECURITY_VIOLATION event.

    The full OCSF schema and Kafka transport are formalised in Sprint S-E07.
    This stub ensures the event is synchronously logged for immediate audit
    visibility.

    Returns the event dict (useful in tests to inspect emitted events).
    """
    now_ms = int(time.time() * 1000)

    event: dict[str, Any] = {
        # OCSF envelope
        "class_uid": _OCSF_CLASS_UID_SECURITY_FINDING,
        "class_name": "SECURITY_VIOLATION",
        "category_uid": 4,
        "category_name": "FINDINGS",
        "activity_id": _OCSF_ACTIVITY_DENY,
        "activity_name": "DENY",
        "severity_id": 5,
        "severity": "CRITICAL",
        "type_uid": 400202,
        "time": now_ms,
        "start_time": now_ms,
        # Metadata
        "metadata": {
            "version": "1.0.0",
            "product": {
                "name": "AgentPEP",
                "vendor_name": "TrustFabric",
            },
            "event_code": "SECURITY_VIOLATION",
        },
        # Actor context
        "actor": {
            "agent_id": agent_id,
            "session_id": session_id,
        },
        # Resource under evaluation
        "resources": [
            {
                "type": "policy_bundle",
                "name": source_url or "unknown",
                "version": bundle_version,
            }
        ],
        # Finding details
        "finding_info": {
            "title": f"Security violation in trusted policy loader: {reason.value}",
            "uid": request_id,
            "reason": reason.value,
            "detail": detail,
            "source_url": source_url,
            "bundle_version": bundle_version,
        },
        # Decision — policy loader FAIL_CLOSED: bundle not loaded
        "decision": "DENY",
        "policy_loader_fail_closed": True,
    }

    logger.error(
        "SECURITY_VIOLATION",
        event_class="SECURITY_VIOLATION",
        reason=reason.value,
        detail=detail,
        source_url=source_url,
        bundle_version=bundle_version,
        session_id=session_id,
        agent_id=agent_id,
    )

    return event
