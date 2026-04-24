"""PDP response parser — OPA output → ALLOW / DENY / MODIFY + reason code.

Converts the raw dict returned by the OPA engine into a typed PDPResponse.
The parser is FAIL_CLOSED: any ambiguous, malformed, or missing result is
treated as DENY to satisfy the Evaluation Guarantee Invariant.

Sprint S-E04 (E04-T03)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.core.structured_logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Decision types
# ---------------------------------------------------------------------------


class PDPDecision(str, Enum):
    """Three-valued policy decision returned by the PDP."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    MODIFY = "MODIFY"     # Permit with argument transformation (future use)


# ---------------------------------------------------------------------------
# Reason codes
# ---------------------------------------------------------------------------


class ReasonCode(str, Enum):
    """Canonical reason codes surfaced in enforcement decision events."""

    # Allow reasons
    TOOL_ALLOWED = "TOOL_ALLOWED"
    POLICY_EVALUATED = "POLICY_EVALUATED"

    # Deny reasons — policy
    TOOL_NOT_PERMITTED = "TOOL_NOT_PERMITTED"
    TAINTED_INPUT = "TAINTED_INPUT"
    INSUFFICIENT_TRUST = "INSUFFICIENT_TRUST"
    PRINCIPAL_NOT_AUTHORISED = "PRINCIPAL_NOT_AUTHORISED"
    BLAST_RADIUS_ELEVATED = "BLAST_RADIUS_ELEVATED"

    # Deny reasons — evaluation failures (FAIL_CLOSED)
    EVALUATION_ERROR = "EVALUATION_ERROR"
    RESULT_PARSE_ERROR = "RESULT_PARSE_ERROR"
    UNDEFINED = "UNDEFINED"
    EVALUATION_TIMEOUT = "EVALUATION_TIMEOUT"
    COMPLEXITY_EXCEEDED = "COMPLEXITY_EXCEEDED"

    # Modify reasons
    ARGS_SANITISED = "ARGS_SANITISED"

    # Unknown / catch-all
    UNKNOWN = "UNKNOWN"


def _normalise_reason_code(raw: str) -> ReasonCode:
    """Map a raw reason code string to a canonical ReasonCode.

    Unknown codes are mapped to ``ReasonCode.UNKNOWN`` to prevent crashes
    while still surfacing the raw value through the ``details`` field.
    """
    try:
        return ReasonCode(raw)
    except ValueError:
        return ReasonCode.UNKNOWN


# ---------------------------------------------------------------------------
# Parsed response
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PDPResponse:
    """Typed result of a single PDP evaluation."""

    decision: PDPDecision
    reason_code: ReasonCode
    details: str = ""
    evaluator: str = ""
    # Populated only when decision == MODIFY
    modified_args: dict[str, Any] | None = None

    @property
    def is_allow(self) -> bool:
        return self.decision == PDPDecision.ALLOW

    @property
    def is_deny(self) -> bool:
        return self.decision == PDPDecision.DENY

    @property
    def is_modify(self) -> bool:
        return self.decision == PDPDecision.MODIFY


# ---------------------------------------------------------------------------
# Sentinel deny responses for FAIL_CLOSED paths
# ---------------------------------------------------------------------------

DENY_EVALUATION_ERROR = PDPResponse(
    decision=PDPDecision.DENY,
    reason_code=ReasonCode.EVALUATION_ERROR,
    details="PDP evaluation raised an unhandled error; FAIL_CLOSED applied",
)

DENY_TIMEOUT = PDPResponse(
    decision=PDPDecision.DENY,
    reason_code=ReasonCode.EVALUATION_TIMEOUT,
    details="PDP evaluation exceeded the configured timeout; FAIL_CLOSED applied",
)

DENY_COMPLEXITY = PDPResponse(
    decision=PDPDecision.DENY,
    reason_code=ReasonCode.COMPLEXITY_EXCEEDED,
    details="Request rejected by complexity budget checker before OPA evaluation",
)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class PDPResponseParser:
    """Converts OPA engine output dicts into typed PDPResponse objects.

    FAIL_CLOSED contract: any input that cannot be unambiguously parsed as
    ALLOW is returned as DENY.
    """

    def parse(self, raw: dict[str, Any]) -> PDPResponse:
        """Parse the raw engine result dict into a PDPResponse.

        Args:
            raw: Dict returned by OPAEngineProtocol.evaluate().

        Returns:
            Typed PDPResponse.  Never raises — parse errors produce DENY.
        """
        try:
            return self._parse_inner(raw)
        except Exception as exc:
            logger.error(
                "pdp_response_parse_failed",
                error=str(exc),
                raw_keys=list(raw.keys()) if isinstance(raw, dict) else [],
            )
            return PDPResponse(
                decision=PDPDecision.DENY,
                reason_code=ReasonCode.RESULT_PARSE_ERROR,
                details=f"Parser raised exception: {exc}",
                evaluator=raw.get("evaluator", "") if isinstance(raw, dict) else "",
            )

    def _parse_inner(self, raw: dict[str, Any]) -> PDPResponse:
        if not isinstance(raw, dict):
            return DENY_EVALUATION_ERROR

        evaluator = str(raw.get("evaluator", ""))
        reason_code_raw = str(raw.get("reason_code", "UNKNOWN"))
        details = str(raw.get("details", ""))
        reason_code = _normalise_reason_code(reason_code_raw)

        # Explicit MODIFY decision (future — not yet issued by stub bundle)
        if raw.get("modify", False):
            modified_args = raw.get("modified_args")
            return PDPResponse(
                decision=PDPDecision.MODIFY,
                reason_code=ReasonCode.ARGS_SANITISED,
                details=details,
                evaluator=evaluator,
                modified_args=modified_args if isinstance(modified_args, dict) else None,
            )

        # Explicit allow/deny booleans from the engine
        allow = raw.get("allow", False)
        deny = raw.get("deny", not allow)

        # Ambiguity guard: both true → FAIL_CLOSED
        if allow and deny:
            logger.warning(
                "pdp_ambiguous_result",
                allow=allow,
                deny=deny,
                reason_code=reason_code_raw,
            )
            return PDPResponse(
                decision=PDPDecision.DENY,
                reason_code=ReasonCode.EVALUATION_ERROR,
                details="Ambiguous OPA result: both allow and deny are true",
                evaluator=evaluator,
            )

        decision = PDPDecision.ALLOW if allow else PDPDecision.DENY
        return PDPResponse(
            decision=decision,
            reason_code=reason_code,
            details=details,
            evaluator=evaluator,
        )

    def parse_or_deny(self, raw: dict[str, Any] | None) -> PDPResponse:
        """Parse *raw*, returning ``DENY_EVALUATION_ERROR`` when *raw* is None."""
        if raw is None:
            return DENY_EVALUATION_ERROR
        return self.parse(raw)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

response_parser = PDPResponseParser()
