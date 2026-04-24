"""Enforcement Posture Matrix — taint level × deployment tier × blast radius.

Implements the 3×3 enforcement posture matrix from PRD v2.1 FEATURE-06.

Primary matrix dimensions:
  Taint level    — CLEAN (L1) | TAINTED (L2) | SENSITIVE (L3)
  Deployment tier — ENTERPRISE | MANAGED | HOMEGROWN

Base posture lookup table:

  +----------+-----------+---------+----------+
  |          | ENTERPRISE| MANAGED |HOMEGROWN |
  +----------+-----------+---------+----------+
  | CLEAN    | MONITOR   | MONITOR | MONITOR  |
  | TAINTED  |MONITOR_LOG| RESTRICT| RESTRICT |
  | SENSITIVE| RESTRICT  |DENY_ALERT|DENY_ALERT|
  +----------+-----------+---------+----------+

Blast Radius Elevation:
  If blast_radius_score ≥ 0.75 the base posture is elevated one tier:
    MONITOR → MONITOR_LOG → RESTRICT → DENY_ALERT

Posture Actions:
  MONITOR     — ALLOW with full PostToolUse event emission
  MONITOR_LOG — ALLOW with enhanced logging (full arg capture) + TrustSOC flag
  RESTRICT    — ALLOW only if explicit role-based permit exists; HITL stub triggered
  DENY_ALERT  — Hard DENY + immediate TrustSOC alert event within 500 ms SLA

Sprint S-E08 (E08-T04, E08-T05, E08-T06, E08-T07)
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.core.structured_logging import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PostureLevel(str, Enum):
    """Ordered enforcement posture levels (ascending restrictiveness)."""

    MONITOR = "MONITOR"
    MONITOR_LOG = "MONITOR_LOG"
    RESTRICT = "RESTRICT"
    DENY_ALERT = "DENY_ALERT"


_POSTURE_ORDER: list[PostureLevel] = [
    PostureLevel.MONITOR,
    PostureLevel.MONITOR_LOG,
    PostureLevel.RESTRICT,
    PostureLevel.DENY_ALERT,
]


class TaintLevel(str, Enum):
    """Taint level classification used in the posture matrix."""

    CLEAN = "CLEAN"       # L1
    TAINTED = "TAINTED"   # L2
    SENSITIVE = "SENSITIVE"  # L3


class DeploymentTierLabel(str, Enum):
    """Deployment tier labels used in the posture matrix."""

    ENTERPRISE = "ENTERPRISE"
    MANAGED = "MANAGED"
    HOMEGROWN = "HOMEGROWN"


# ---------------------------------------------------------------------------
# Blast radius elevation threshold
# ---------------------------------------------------------------------------

BLAST_RADIUS_ELEVATION_THRESHOLD: float = 0.75


# ---------------------------------------------------------------------------
# Base posture matrix
# ---------------------------------------------------------------------------

_BASE_MATRIX: dict[tuple[TaintLevel, DeploymentTierLabel], PostureLevel] = {
    # CLEAN (L1)
    (TaintLevel.CLEAN, DeploymentTierLabel.ENTERPRISE): PostureLevel.MONITOR,
    (TaintLevel.CLEAN, DeploymentTierLabel.MANAGED):    PostureLevel.MONITOR,
    (TaintLevel.CLEAN, DeploymentTierLabel.HOMEGROWN):  PostureLevel.MONITOR,
    # TAINTED (L2)
    (TaintLevel.TAINTED, DeploymentTierLabel.ENTERPRISE): PostureLevel.MONITOR_LOG,
    (TaintLevel.TAINTED, DeploymentTierLabel.MANAGED):    PostureLevel.RESTRICT,
    (TaintLevel.TAINTED, DeploymentTierLabel.HOMEGROWN):  PostureLevel.RESTRICT,
    # SENSITIVE (L3)
    (TaintLevel.SENSITIVE, DeploymentTierLabel.ENTERPRISE): PostureLevel.RESTRICT,
    (TaintLevel.SENSITIVE, DeploymentTierLabel.MANAGED):    PostureLevel.DENY_ALERT,
    (TaintLevel.SENSITIVE, DeploymentTierLabel.HOMEGROWN):  PostureLevel.DENY_ALERT,
}


# ---------------------------------------------------------------------------
# Posture resolution result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PostureResolution:
    """Result of a posture matrix lookup for a single evaluation.

    Attributes:
        base_posture:      The posture before blast radius elevation.
        effective_posture: The posture after blast radius elevation (final decision input).
        blast_elevated:    True if blast radius elevation was applied.
        taint_level:       The resolved taint level used in the lookup.
        deployment_tier:   The resolved deployment tier used in the lookup.
        blast_radius_score: The blast radius score at the time of evaluation.
    """

    base_posture: PostureLevel
    effective_posture: PostureLevel
    blast_elevated: bool
    taint_level: str
    deployment_tier: str
    blast_radius_score: float


# ---------------------------------------------------------------------------
# Posture matrix
# ---------------------------------------------------------------------------


class PostureMatrix:
    """Enforcement posture matrix implementation.

    Usage::

        matrix = PostureMatrix()
        resolution = matrix.resolve(
            taint_level="SENSITIVE",
            deployment_tier="MANAGED",
            blast_radius_score=0.80,
        )
        action = matrix.apply_posture(resolution, ...)
    """

    # ---------------------------------------------------------------------------
    # Tier / taint normalisation helpers
    # ---------------------------------------------------------------------------

    @staticmethod
    def _normalise_taint(taint_level: str) -> TaintLevel:
        """Normalise a raw taint level string to a TaintLevel enum.

        Unknown values are treated as SENSITIVE (most restrictive) to
        satisfy the Evaluation Guarantee Invariant.
        """
        mapping: dict[str, TaintLevel] = {
            "CLEAN": TaintLevel.CLEAN,
            "L1": TaintLevel.CLEAN,
            "TAINTED": TaintLevel.TAINTED,
            "L2": TaintLevel.TAINTED,
            "SENSITIVE": TaintLevel.SENSITIVE,
            "L3": TaintLevel.SENSITIVE,
            "RESTRICTED": TaintLevel.SENSITIVE,
        }
        return mapping.get(taint_level.upper().strip(), TaintLevel.SENSITIVE)

    @staticmethod
    def _normalise_tier(deployment_tier: str) -> DeploymentTierLabel:
        """Normalise a raw deployment tier string to a DeploymentTierLabel.

        Unknown values default to HOMEGROWN (most restrictive) — satisfies
        the ambiguous-tier-defaults-to-HOMEGROWN acceptance criterion.
        """
        mapping: dict[str, DeploymentTierLabel] = {
            "ENTERPRISE": DeploymentTierLabel.ENTERPRISE,
            "MANAGED": DeploymentTierLabel.MANAGED,
            "HOMEGROWN": DeploymentTierLabel.HOMEGROWN,
        }
        return mapping.get(deployment_tier.upper().strip(), DeploymentTierLabel.HOMEGROWN)

    # ---------------------------------------------------------------------------
    # Matrix resolution
    # ---------------------------------------------------------------------------

    def resolve(
        self,
        taint_level: str,
        deployment_tier: str,
        blast_radius_score: float,
    ) -> PostureResolution:
        """Look up the effective posture for a given evaluation context.

        Args:
            taint_level:        Taint classification of the request context.
                                Accepts canonical names (CLEAN/TAINTED/SENSITIVE)
                                or L-notation (L1/L2/L3).
            deployment_tier:    Deployment tier (ENTERPRISE/MANAGED/HOMEGROWN).
                                Unknown values default to HOMEGROWN.
            blast_radius_score: AAPM blast radius score [0.0, 1.0].
                                Score ≥ 0.75 elevates the base posture one tier.

        Returns:
            PostureResolution capturing base, effective posture, and elevation flag.
        """
        norm_taint = self._normalise_taint(taint_level)
        norm_tier = self._normalise_tier(deployment_tier)

        base = _BASE_MATRIX[(norm_taint, norm_tier)]
        effective, elevated = _apply_blast_elevation(base, blast_radius_score)

        resolution = PostureResolution(
            base_posture=base,
            effective_posture=effective,
            blast_elevated=elevated,
            taint_level=norm_taint.value,
            deployment_tier=norm_tier.value,
            blast_radius_score=max(0.0, min(1.0, float(blast_radius_score))),
        )

        logger.debug(
            "posture_resolved",
            taint_level=norm_taint.value,
            deployment_tier=norm_tier.value,
            blast_radius_score=resolution.blast_radius_score,
            base_posture=base.value,
            effective_posture=effective.value,
            blast_elevated=elevated,
        )

        return resolution

    # ---------------------------------------------------------------------------
    # Posture action execution
    # ---------------------------------------------------------------------------

    def apply_posture(
        self,
        resolution: PostureResolution,
        *,
        agent_id: str = "",
        session_id: str = "",
        request_id: str = "",
        tool_name: str = "",
        agent_permissions: frozenset[str] | None = None,
        required_permission: str = "",
    ) -> "PostureDecision":
        """Execute the posture action and return a PostureDecision.

        Args:
            resolution:          Result of resolve().
            agent_id:            Agent identifier for event emission.
            session_id:          Session identifier for event emission.
            request_id:          Request identifier for sequence ID correlation.
            tool_name:           Tool under evaluation.
            agent_permissions:   Permission set held by the agent (for RESTRICT check).
            required_permission: Minimum permission required to pass RESTRICT.

        Returns:
            PostureDecision with allow/deny and any emitted events.
        """
        posture = resolution.effective_posture

        if posture == PostureLevel.MONITOR:
            return _action_monitor(resolution)

        if posture == PostureLevel.MONITOR_LOG:
            return _action_monitor_log(resolution, tool_name=tool_name)

        if posture == PostureLevel.RESTRICT:
            return _action_restrict(
                resolution,
                agent_id=agent_id,
                session_id=session_id,
                request_id=request_id,
                tool_name=tool_name,
                agent_permissions=agent_permissions or frozenset(),
                required_permission=required_permission,
            )

        # DENY_ALERT
        return _action_deny_alert(
            resolution,
            agent_id=agent_id,
            session_id=session_id,
            request_id=request_id,
            tool_name=tool_name,
        )


# ---------------------------------------------------------------------------
# PostureDecision
# ---------------------------------------------------------------------------


@dataclass
class PostureDecision:
    """Result of applying a posture action.

    Attributes:
        allowed:           True if the tool call may proceed.
        posture:           The effective PostureLevel applied.
        reason:            Human-readable explanation for the decision.
        hitl_triggered:    True if a HITL approval workflow was triggered (RESTRICT).
        alert_emitted:     True if a TrustSOC alert was emitted (DENY_ALERT).
        enhanced_logging:  True if full argument capture is active (MONITOR_LOG).
        alert_event:       The POSTURE_ALERT OCSF event dict (DENY_ALERT only; else None).
    """

    allowed: bool
    posture: PostureLevel
    reason: str
    hitl_triggered: bool = False
    alert_emitted: bool = False
    enhanced_logging: bool = False
    alert_event: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Internal posture action implementations
# ---------------------------------------------------------------------------


def _action_monitor(resolution: PostureResolution) -> PostureDecision:
    """MONITOR — allow with standard PostToolUse event emission."""
    return PostureDecision(
        allowed=True,
        posture=PostureLevel.MONITOR,
        reason="MONITOR posture: allowed with standard event emission",
    )


def _action_monitor_log(
    resolution: PostureResolution,
    tool_name: str = "",
) -> PostureDecision:
    """MONITOR + LOG — allow with enhanced logging, flagged for TrustSOC review."""
    logger.info(
        "posture_monitor_log",
        tool_name=tool_name,
        taint_level=resolution.taint_level,
        deployment_tier=resolution.deployment_tier,
        blast_radius_score=resolution.blast_radius_score,
    )
    return PostureDecision(
        allowed=True,
        posture=PostureLevel.MONITOR_LOG,
        reason="MONITOR_LOG posture: allowed with enhanced logging; flagged for TrustSOC review",
        enhanced_logging=True,
    )


def _action_restrict(
    resolution: PostureResolution,
    *,
    agent_id: str,
    session_id: str,
    request_id: str,
    tool_name: str,
    agent_permissions: frozenset[str],
    required_permission: str,
) -> PostureDecision:
    """RESTRICT — allow only if agent holds the required permission; trigger HITL stub."""
    permitted = (not required_permission) or (required_permission in agent_permissions)

    logger.info(
        "posture_restrict_evaluated",
        agent_id=agent_id,
        session_id=session_id,
        tool_name=tool_name,
        required_permission=required_permission or "(none)",
        agent_has_permission=permitted,
        blast_elevated=resolution.blast_elevated,
    )

    if permitted:
        _trigger_hitl_stub(
            agent_id=agent_id,
            session_id=session_id,
            request_id=request_id,
            tool_name=tool_name,
            resolution=resolution,
        )
        return PostureDecision(
            allowed=True,
            posture=PostureLevel.RESTRICT,
            reason=(
                "RESTRICT posture: role-based permit found; "
                "HITL approval workflow triggered"
            ),
            hitl_triggered=True,
        )

    return PostureDecision(
        allowed=False,
        posture=PostureLevel.RESTRICT,
        reason=(
            f"RESTRICT posture: agent lacks required permission "
            f"'{required_permission}' — tool call denied"
        ),
        hitl_triggered=True,
    )


def _action_deny_alert(
    resolution: PostureResolution,
    *,
    agent_id: str,
    session_id: str,
    request_id: str,
    tool_name: str,
) -> PostureDecision:
    """DENY + ALERT — hard deny; emit immediate TrustSOC alert event (E08-T06)."""
    alert = emit_posture_alert_event(
        agent_id=agent_id,
        session_id=session_id,
        request_id=request_id,
        tool_name=tool_name,
        taint_level=resolution.taint_level,
        deployment_tier=resolution.deployment_tier,
        blast_radius_score=resolution.blast_radius_score,
        blast_elevated=resolution.blast_elevated,
    )
    return PostureDecision(
        allowed=False,
        posture=PostureLevel.DENY_ALERT,
        reason=(
            "DENY_ALERT posture: hard deny — TrustSOC alert emitted; "
            "session flagged for human review"
        ),
        alert_emitted=True,
        alert_event=alert,
    )


# ---------------------------------------------------------------------------
# Blast radius elevation
# ---------------------------------------------------------------------------


def _apply_blast_elevation(
    base: PostureLevel,
    blast_radius_score: float,
) -> tuple[PostureLevel, bool]:
    """Elevate the posture one tier if blast_radius_score ≥ threshold.

    Returns:
        (effective_posture, elevated)
    """
    if blast_radius_score < BLAST_RADIUS_ELEVATION_THRESHOLD:
        return base, False

    idx = _POSTURE_ORDER.index(base)
    if idx < len(_POSTURE_ORDER) - 1:
        elevated = _POSTURE_ORDER[idx + 1]
        logger.debug(
            "blast_radius_elevation_applied",
            base_posture=base.value,
            elevated_posture=elevated.value,
            blast_radius_score=blast_radius_score,
            threshold=BLAST_RADIUS_ELEVATION_THRESHOLD,
        )
        return elevated, True

    # Already at maximum posture — no further elevation possible
    return base, True


# ---------------------------------------------------------------------------
# HITL workflow stub (E08-T07)
# ---------------------------------------------------------------------------


def _trigger_hitl_stub(
    agent_id: str,
    session_id: str,
    request_id: str,
    tool_name: str,
    resolution: PostureResolution,
) -> None:
    """Trigger the HITL approval workflow stub for RESTRICT posture.

    The full async human approval flow is a post-v2.1 backlog item.
    This stub logs the HITL trigger event so TrustSOC can track
    borderline cases awaiting human review.
    """
    logger.warning(
        "HITL_WORKFLOW_TRIGGERED",
        agent_id=agent_id,
        session_id=session_id,
        request_id=request_id,
        tool_name=tool_name,
        posture=PostureLevel.RESTRICT.value,
        taint_level=resolution.taint_level,
        deployment_tier=resolution.deployment_tier,
        blast_radius_score=resolution.blast_radius_score,
        blast_elevated=resolution.blast_elevated,
        note="HITL full workflow is a post-v2.1 backlog item; stub triggers logging only",
    )


# ---------------------------------------------------------------------------
# POSTURE_ALERT OCSF event (E08-T06) — DENY + ALERT
# ---------------------------------------------------------------------------

_OCSF_CLASS_UID_COMPLIANCE_FINDING = 4003
_OCSF_ACTIVITY_DENY_ALERT = 6


def emit_posture_alert_event(
    agent_id: str,
    session_id: str,
    request_id: str,
    tool_name: str,
    taint_level: str,
    deployment_tier: str,
    blast_radius_score: float,
    blast_elevated: bool,
) -> dict[str, Any]:
    """Build, sign, log, and return a POSTURE_ALERT OCSF event.

    Emitted on DENY + ALERT posture decisions.  TrustSOC consumers
    MUST process this event within the 500 ms SLA defined in the
    TrustSOC integration contract.

    Returns:
        The signed event dict (useful in tests to inspect the event).
    """
    from app.events.event_signer import try_sign_event
    from app.events.sequence_id import sequence_id_from_request

    now_ms = int(time.time() * 1000)
    sequence_id = sequence_id_from_request(request_id) if request_id else ""

    event: dict[str, Any] = {
        # OCSF envelope
        "class_uid": _OCSF_CLASS_UID_COMPLIANCE_FINDING,
        "class_name": "POSTURE_ALERT",
        "category_uid": 4,
        "category_name": "FINDINGS",
        "activity_id": _OCSF_ACTIVITY_DENY_ALERT,
        "activity_name": "DENY_ALERT",
        "severity_id": 5,
        "severity": "CRITICAL",
        "type_uid": _OCSF_CLASS_UID_COMPLIANCE_FINDING * 100 + _OCSF_ACTIVITY_DENY_ALERT,
        "time": now_ms,
        "start_time": now_ms,
        # Metadata
        "metadata": {
            "version": "1.0.0",
            "product": {
                "name": "AgentPEP",
                "vendor_name": "TrustFabric",
            },
            "event_code": "POSTURE_ALERT",
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
            "title": "Enforcement posture DENY + ALERT — session flagged for human review",
            "uid": sequence_id,
            "sequence_id": sequence_id,
            "posture": PostureLevel.DENY_ALERT.value,
            "taint_level": taint_level,
            "deployment_tier": deployment_tier,
            "blast_radius_score": blast_radius_score,
            "blast_elevated": blast_elevated,
            "elevation_threshold": BLAST_RADIUS_ELEVATION_THRESHOLD,
        },
        # Decision
        "decision": "DENY",
        "posture": PostureLevel.DENY_ALERT.value,
        "trustsoc_alert": True,
        "session_flagged_for_review": True,
    }

    event = try_sign_event(event)

    logger.error(
        "POSTURE_ALERT",
        event_class="POSTURE_ALERT",
        agent_id=agent_id,
        session_id=session_id,
        tool_name=tool_name,
        taint_level=taint_level,
        deployment_tier=deployment_tier,
        blast_radius_score=blast_radius_score,
        blast_elevated=blast_elevated,
        sequence_id=sequence_id,
        signed=bool(event["metadata"].get("hmac_signature")),
        trustsoc_alert=True,
    )

    return event


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

posture_matrix = PostureMatrix()
