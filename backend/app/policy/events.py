"""SECURITY_VIOLATION event — full OCSF schema (Sprint S-E07, E07-T06).

Emitted whenever the trusted policy loader detects a security-relevant
failure:
  - Invalid or unverifiable cosign signature on a policy bundle
  - Untrusted source path (URL not on the AAPM registry allowlist)
  - Attempt to override the policy source via environment variable

Upgraded from stub (S-E03) to full TrustFabric OCSF Profile in Sprint S-E07:
  - HMAC signing for tamper-evident stream
  - sequence_id field for Pre/PostToolUse correlation
  - profile and bundle_version metadata fields

Sprint S-E03 (E03-T04)
Sprint S-E07 (E07-T06)
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
    """Build, sign, and return a SECURITY_VIOLATION OCSF event.

    Upgraded to full TrustFabric OCSF Profile in Sprint S-E07: adds HMAC
    signing, sequence_id linking, and profile metadata.

    Returns the signed event dict (useful in tests to inspect emitted events).
    """
    from app.events.event_signer import try_sign_event
    from app.events.sequence_id import sequence_id_from_request

    now_ms = int(time.time() * 1000)
    sequence_id = sequence_id_from_request(request_id) if request_id else ""

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
        # Metadata (full profile)
        "metadata": {
            "version": "1.0.0",
            "product": {
                "name": "AgentPEP",
                "vendor_name": "TrustFabric",
            },
            "event_code": "SECURITY_VIOLATION",
            "profile": "TrustFabric/AgentPEP/v1.0",
            "bundle_version": bundle_version,
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
                "uid": sequence_id,
            }
        ],
        # Finding details — includes sequence_id for correlation
        "finding_info": {
            "title": f"Security violation in trusted policy loader: {reason.value}",
            "uid": sequence_id,
            "sequence_id": sequence_id,
            "reason": reason.value,
            "detail": detail,
            "source_url": source_url,
            "bundle_version": bundle_version,
        },
        # Decision — policy loader FAIL_CLOSED: bundle not loaded
        "decision": "DENY",
        "policy_loader_fail_closed": True,
    }

    # HMAC sign for tamper-evident stream (S-E07)
    event = try_sign_event(event)

    logger.error(
        "SECURITY_VIOLATION",
        event_class="SECURITY_VIOLATION",
        reason=reason.value,
        detail=detail,
        source_url=source_url,
        bundle_version=bundle_version,
        session_id=session_id,
        agent_id=agent_id,
        sequence_id=sequence_id,
        signed=bool(event["metadata"].get("hmac_signature")),
    )

    return event
