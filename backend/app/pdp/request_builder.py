"""Authorization request builder — PreToolUse context → OPA input JSON.

Maps the PreToolUse interceptor context to the structured OPA input document
defined in PRD v2.1.  Every field required by the Rego policy evaluation is
present in the output.  Missing caller fields are filled with safe defaults.

The ``blast_radius_score`` field is included as a placeholder (value 0.0)
until Sprint S-E08 wires in the AAPM Blast Radius API.

Sprint S-E04 (E04-T02)
Sprint S-E06 (E06-T04) — delegation_hop_count added; DelegationContext support
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from app.policy.bundle_version import bundle_version_tracker

if TYPE_CHECKING:
    from app.trust.delegation_context import DelegationContext


# ---------------------------------------------------------------------------
# Input document schema (PRD v2.1 §5.1)
# ---------------------------------------------------------------------------


@dataclass
class AuthorizationRequest:
    """Structured OPA input document for a single tool call evaluation."""

    # Identity
    agent_id: str
    session_id: str
    request_id: str

    # Tool under evaluation
    tool_name: str
    tool_args: dict[str, Any]

    # Trust context
    taint_level: str                 # "CLEAN" | "TAINTED" | "SENSITIVE"
    trust_score: float               # 0.0 – 1.0
    principal_chain: list[str]       # Delegation chain from root to current agent

    # Deployment and risk context
    deployment_tier: str             # "ENTERPRISE" | "MANAGED" | "HOMEGROWN"
    blast_radius_score: float        # 0.0 – 1.0; placeholder until S-E08

    # Bundle metadata (set at build time from version tracker)
    bundle_version: str

    # Delegation depth — number of hops from root principal (0 = root itself).
    # Derived from principal_chain length when not explicitly supplied.
    # Included in OPA input so Rego policies can enforce hop-count limits.
    delegation_hop_count: int = 0

    # Request timestamp
    timestamp_ms: int = field(default_factory=lambda: int(time.time() * 1000))

    def to_opa_input(self) -> dict[str, Any]:
        """Serialise to the OPA ``input`` document format."""
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "taint_level": self.taint_level,
            "trust_score": self.trust_score,
            "principal_chain": self.principal_chain,
            "delegation_hop_count": self.delegation_hop_count,
            "deployment_tier": self.deployment_tier,
            "blast_radius_score": self.blast_radius_score,
            "bundle_version": self.bundle_version,
            "timestamp_ms": self.timestamp_ms,
        }


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class AuthorizationRequestBuilder:
    """Constructs AuthorizationRequest objects from PreToolUse interceptor data.

    Applies safe defaults for optional fields so that no caller is required
    to supply every field; the resulting OPA input is always schema-complete.
    """

    # Default values applied when the caller omits a field
    _DEFAULT_TAINT_LEVEL: str = "CLEAN"
    _DEFAULT_TRUST_SCORE: float = 1.0
    _DEFAULT_DEPLOYMENT_TIER: str = "HOMEGROWN"
    _DEFAULT_BLAST_RADIUS_SCORE: float = 0.0   # placeholder until S-E08

    # Valid taint levels — unknown values are normalised to CLEAN (fail-safe)
    _VALID_TAINT_LEVELS: frozenset[str] = frozenset(
        {"CLEAN", "TAINTED", "SENSITIVE", "RESTRICTED"}
    )

    # Valid deployment tiers — unknown values are normalised to HOMEGROWN
    _VALID_DEPLOYMENT_TIERS: frozenset[str] = frozenset(
        {"ENTERPRISE", "MANAGED", "HOMEGROWN"}
    )

    def build(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        *,
        agent_id: str = "",
        session_id: str = "",
        request_id: str = "",
        taint_level: str = "",
        trust_score: float | None = None,
        principal_chain: list[str] | None = None,
        delegation_context: "DelegationContext | None" = None,
        deployment_tier: str = "",
        blast_radius_score: float | None = None,
    ) -> AuthorizationRequest:
        """Build a fully-populated AuthorizationRequest.

        Args:
            tool_name:           Name of the tool being invoked.
            tool_args:           Arguments passed to the tool (must be a dict).
            agent_id:            Calling agent identifier.
            session_id:          Session identifier for correlation.
            request_id:          Unique identifier for this evaluation request.
                                 Auto-generated (UUID4) when empty.
            taint_level:         Taint classification of the request context.
                                 Defaults to ``"CLEAN"``; unknown values are
                                 normalised to ``"CLEAN"``.
            trust_score:         Degraded trust score from the delegation chain.
                                 Ignored when ``delegation_context`` is supplied
                                 (score is computed from the context hop count).
                                 Defaults to 1.0 (full trust, no degradation).
            principal_chain:     Ordered list of agent IDs from root to current.
                                 Ignored when ``delegation_context`` is supplied.
                                 Defaults to ``[agent_id]``.
            delegation_context:  Full DelegationContext carrying the principal
                                 chain and root permissions (Sprint S-E06).
                                 When supplied, ``principal_chain``,
                                 ``trust_score``, and ``delegation_hop_count``
                                 are derived from the context using the
                                 TrustScoreCalculator; explicit values for
                                 those fields are ignored.
            deployment_tier:     Operator-configured deployment tier.
                                 Defaults to ``"HOMEGROWN"``; unknown values are
                                 normalised to ``"HOMEGROWN"``.
            blast_radius_score:  Risk score from AAPM Blast Radius API.
                                 Defaults to 0.0 (placeholder until S-E08).

        Returns:
            Fully-populated AuthorizationRequest ready for OPA evaluation.
        """
        if not request_id:
            request_id = str(uuid.uuid4())

        resolved_taint = (
            taint_level.upper()
            if taint_level.upper() in self._VALID_TAINT_LEVELS
            else self._DEFAULT_TAINT_LEVEL
        )

        resolved_tier = (
            deployment_tier.upper()
            if deployment_tier.upper() in self._VALID_DEPLOYMENT_TIERS
            else self._DEFAULT_DEPLOYMENT_TIER
        )

        resolved_blast = (
            float(blast_radius_score)
            if blast_radius_score is not None
            else self._DEFAULT_BLAST_RADIUS_SCORE
        )

        # S-E06: DelegationContext takes precedence over loose chain + trust_score.
        if delegation_context is not None:
            from app.trust.trust_score import trust_score_calculator
            ts = trust_score_calculator.from_context(delegation_context)
            chain = delegation_context.chain_as_list()
            resolved_trust = ts.score
            hop_count = delegation_context.hop_count
            resolved_agent_id = agent_id or delegation_context.current_agent
        else:
            chain = list(principal_chain) if principal_chain else (
                [agent_id] if agent_id else []
            )
            resolved_trust = (
                float(trust_score)
                if trust_score is not None
                else self._DEFAULT_TRUST_SCORE
            )
            hop_count = max(0, len(chain) - 1)
            resolved_agent_id = agent_id

        return AuthorizationRequest(
            agent_id=resolved_agent_id,
            session_id=session_id,
            request_id=request_id,
            tool_name=tool_name,
            tool_args=tool_args if isinstance(tool_args, dict) else {},
            taint_level=resolved_taint,
            trust_score=max(0.0, min(1.0, resolved_trust)),
            principal_chain=chain,
            delegation_hop_count=hop_count,
            deployment_tier=resolved_tier,
            blast_radius_score=max(0.0, min(1.0, resolved_blast)),
            bundle_version=bundle_version_tracker.version_string,
        )

    def from_intercept_payload(self, payload: dict[str, Any]) -> AuthorizationRequest:
        """Build from a raw PreToolUse intercept API payload dict.

        Accepts the same field names used by the ``/api/v1/intercept`` endpoint
        so that the PDP client can be called directly from the intercept handler.
        """
        req = self.build(
            tool_name=str(payload.get("tool_name", payload.get("action", ""))),
            tool_args=payload.get("tool_args", payload.get("args", {})),
            agent_id=str(payload.get("agent_id", "")),
            session_id=str(payload.get("session_id", "")),
            request_id=str(payload.get("request_id", "")),
            taint_level=str(payload.get("taint_level", "")),
            trust_score=payload.get("trust_score"),
            principal_chain=payload.get("principal_chain"),
            deployment_tier=str(payload.get("deployment_tier", "")),
            blast_radius_score=payload.get("blast_radius_score"),
        )
        # Allow callers to explicitly supply delegation_hop_count (S-E06).
        # When omitted it is derived from principal_chain length in build().
        if "delegation_hop_count" in payload:
            req.delegation_hop_count = int(payload["delegation_hop_count"])
        return req


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

request_builder = AuthorizationRequestBuilder()
