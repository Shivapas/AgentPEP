"""Complexity budget checker — pre-evaluation gate implementing FEATURE-03.

Implements the Evaluation Guarantee Invariant: any request that exceeds
complexity thresholds is unconditionally DENIED.  No operator configuration
can produce ALLOW on budget exceeded.

Checks three dimensions of complexity:
  - Argument byte size (serialised JSON)
  - Subcommand count (shell metacharacters in string values)
  - Nesting depth (max depth of dict/list structure)

Sprint S-E02 (E02-T01, E02-T02, E02-T04)
Sprint S-E07 (E07-T06): Upgraded COMPLEXITY_EXCEEDED from stub to full OCSF schema
  with HMAC signing and sequence ID support.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.structured_logging import get_logger

logger = get_logger(__name__)

# Shell metacharacters that introduce subcommands.
# Each match counts as +1 subcommand boundary.
_SUBCOMMAND_PATTERN = re.compile(
    r"(\|\||&&|[|;&`]|\$\()",
)


@dataclass(frozen=True)
class ComplexityViolation:
    """A single complexity constraint violation."""

    dimension: str        # "arg_bytes" | "subcommand_count" | "nesting_depth"
    limit: int | float
    actual: int | float
    detail: str


@dataclass
class ComplexityCheckResult:
    """Result of a complexity budget check."""

    allowed: bool
    violations: list[ComplexityViolation] = field(default_factory=list)

    @property
    def reason(self) -> str:
        if not self.violations:
            return "Within complexity budget"
        parts = [v.detail for v in self.violations]
        return "; ".join(parts)


def _max_nesting_depth(obj: Any, current: int = 0) -> int:
    """Recursively compute the maximum nesting depth of a dict/list structure."""
    if isinstance(obj, dict):
        if not obj:
            return current
        return max(_max_nesting_depth(v, current + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return current
        return max(_max_nesting_depth(item, current + 1) for item in obj)
    return current


def _count_subcommands(obj: Any) -> int:
    """Count shell metacharacter occurrences across all string values (recursive)."""
    count = 0
    if isinstance(obj, str):
        count += len(_SUBCOMMAND_PATTERN.findall(obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            count += _count_subcommands(v)
    elif isinstance(obj, list):
        for item in obj:
            count += _count_subcommands(item)
    return count


class ComplexityBudgetChecker:
    """Evaluates tool call arguments against operator-configured complexity limits.

    All budget violations unconditionally produce ``allowed=False``.
    There is no permissive fallback — the DENY outcome is hardcoded.
    """

    def __init__(
        self,
        max_arg_bytes: int,
        max_subcommand_count: int,
        max_nesting_depth: int,
    ) -> None:
        self._max_arg_bytes = max_arg_bytes
        self._max_subcommand_count = max_subcommand_count
        self._max_nesting_depth = max_nesting_depth

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, tool_name: str, tool_args: dict[str, Any]) -> ComplexityCheckResult:
        """Check tool_args against all complexity dimensions.

        Returns ComplexityCheckResult with allowed=True only when every
        dimension is within its configured limit.
        """
        violations: list[ComplexityViolation] = []

        arg_bytes = self._measure_arg_bytes(tool_args)
        if arg_bytes > self._max_arg_bytes:
            violations.append(
                ComplexityViolation(
                    dimension="arg_bytes",
                    limit=self._max_arg_bytes,
                    actual=arg_bytes,
                    detail=(
                        f"Argument size {arg_bytes} bytes exceeds limit "
                        f"{self._max_arg_bytes} bytes"
                    ),
                )
            )

        subcommand_count = _count_subcommands(tool_args)
        if subcommand_count > self._max_subcommand_count:
            violations.append(
                ComplexityViolation(
                    dimension="subcommand_count",
                    limit=self._max_subcommand_count,
                    actual=subcommand_count,
                    detail=(
                        f"Subcommand count {subcommand_count} exceeds limit "
                        f"{self._max_subcommand_count}"
                    ),
                )
            )

        nesting_depth = _max_nesting_depth(tool_args)
        if nesting_depth > self._max_nesting_depth:
            violations.append(
                ComplexityViolation(
                    dimension="nesting_depth",
                    limit=self._max_nesting_depth,
                    actual=nesting_depth,
                    detail=(
                        f"Nesting depth {nesting_depth} exceeds limit "
                        f"{self._max_nesting_depth}"
                    ),
                )
            )

        result = ComplexityCheckResult(allowed=len(violations) == 0, violations=violations)

        if not result.allowed:
            logger.warning(
                "complexity_budget_exceeded",
                tool_name=tool_name,
                violations=[v.dimension for v in violations],
                reason=result.reason,
            )
            emit_complexity_exceeded_event(
                tool_name=tool_name,
                violations=violations,
            )

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _measure_arg_bytes(tool_args: dict[str, Any]) -> int:
        """Serialise tool_args to JSON and return byte length."""
        try:
            return len(json.dumps(tool_args, separators=(",", ":")).encode())
        except (TypeError, ValueError):
            # Non-serialisable args are treated as maximally complex.
            return 2**31


# ---------------------------------------------------------------------------
# COMPLEXITY_EXCEEDED event — full OCSF schema (Sprint S-E07, E07-T06)
# ---------------------------------------------------------------------------

_OCSF_CLASS_UID_COMPLIANCE_FINDING = 4003
_OCSF_ACTIVITY_DENY = 2


def emit_complexity_exceeded_event(
    tool_name: str,
    violations: list[ComplexityViolation],
    session_id: str = "",
    agent_id: str = "",
    request_id: str = "",
) -> dict[str, Any]:
    """Build, sign, and log a COMPLEXITY_EXCEEDED OCSF event.

    Upgraded from a stub (S-E02) to the full TrustFabric OCSF Profile in
    Sprint S-E07 (E07-T06): adds sequence_id, HMAC signing, and the
    profile / bundle_version metadata fields.

    Returns the signed event dict (useful for testing).
    """
    from app.events.event_signer import try_sign_event
    from app.events.sequence_id import sequence_id_from_request

    now_ms = int(time.time() * 1000)
    sequence_id = sequence_id_from_request(request_id) if request_id else ""

    event: dict[str, Any] = {
        # OCSF envelope
        "class_uid": _OCSF_CLASS_UID_COMPLIANCE_FINDING,
        "class_name": "COMPLEXITY_EXCEEDED",
        "category_uid": 4,
        "category_name": "FINDINGS",
        "activity_id": _OCSF_ACTIVITY_DENY,
        "activity_name": "DENY",
        "severity_id": 3,
        "severity": "HIGH",
        "type_uid": 400302,
        "time": now_ms,
        "start_time": now_ms,
        # Metadata (full profile)
        "metadata": {
            "version": "1.0.0",
            "product": {
                "name": "AgentPEP",
                "vendor_name": "TrustFabric",
            },
            "event_code": "COMPLEXITY_EXCEEDED",
            "profile": "TrustFabric/AgentPEP/v1.0",
        },
        # Actor context
        "actor": {
            "agent_id": agent_id,
            "session_id": session_id,
        },
        # Resource under evaluation
        "resources": [
            {
                "type": "tool_call",
                "name": tool_name,
                "uid": sequence_id,
            }
        ],
        # Finding details — includes sequence_id for Pre/PostToolUse correlation
        "finding_info": {
            "title": "Complexity budget exceeded — request denied",
            "uid": sequence_id,
            "sequence_id": sequence_id,
            "violations": [
                {
                    "dimension": v.dimension,
                    "limit": v.limit,
                    "actual": v.actual,
                    "detail": v.detail,
                }
                for v in violations
            ],
        },
        # Decision — hardcoded DENY (Evaluation Guarantee Invariant)
        "decision": "DENY",
        "evaluation_guarantee_invariant": True,
    }

    # HMAC sign for tamper-evident stream (S-E07)
    event = try_sign_event(event)

    logger.info(
        "COMPLEXITY_EXCEEDED",
        event_class="COMPLEXITY_EXCEEDED",
        tool_name=tool_name,
        session_id=session_id,
        agent_id=agent_id,
        violation_count=len(violations),
        violations=[v.dimension for v in violations],
        sequence_id=sequence_id,
        signed=bool(event["metadata"].get("hmac_signature")),
    )

    return event


# ---------------------------------------------------------------------------
# Module-level singleton — configured lazily from app.core.config
# ---------------------------------------------------------------------------

def _build_checker() -> ComplexityBudgetChecker:
    """Build checker from current settings."""
    from app.core.config import settings

    return ComplexityBudgetChecker(
        max_arg_bytes=settings.complexity_budget_max_arg_bytes,
        max_subcommand_count=settings.complexity_budget_max_subcommand_count,
        max_nesting_depth=settings.complexity_budget_max_nesting_depth,
    )


class _LazyChecker:
    """Lazy singleton that reads config on first use."""

    _instance: ComplexityBudgetChecker | None = None

    def check(self, tool_name: str, tool_args: dict[str, Any]) -> ComplexityCheckResult:
        if self._instance is None:
            self._instance = _build_checker()
        return self._instance.check(tool_name, tool_args)

    def reconfigure(self) -> None:
        """Force re-read of config (useful in tests)."""
        self._instance = None


complexity_checker = _LazyChecker()
