"""Risk Scoring Engine — Sprint 8 (APEP-063 through APEP-069).

Configurable risk model producing [0–1] scores per tool call.
Five individual scorers feed into a weighted RiskAggregator:

  APEP-064: OperationTypeScorer   — classify tool call risk by verb
  APEP-065: DataSensitivityScorer — detect PII / credential / financial patterns
  APEP-066: TaintScorer           — elevate risk based on taint levels
  APEP-067: SessionAccumulatedRiskScorer — cumulative risk from session history
  APEP-068: DelegationDepthScorer — higher risk for deeper chains
  APEP-069: RiskAggregator        — weighted sum with per-role overrides
"""

from __future__ import annotations

import logging
import re
from typing import Any
from uuid import UUID

from app.db import mongodb as db_module
from app.models.policy import (
    RiskFactor,
    RiskModelConfig,
    TaintLevel,
)
from app.services.taint_graph import session_graph_manager

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# APEP-064: OperationTypeScorer
# ---------------------------------------------------------------------------

# Verb categories ordered by risk (highest first).
_DELETE_VERBS = re.compile(
    r"(delete|remove|destroy|drop|purge|truncate|erase|kill|terminate|revoke)",
    re.IGNORECASE,
)
_WRITE_VERBS = re.compile(
    r"(write|create|update|put|patch|insert|set|modify|upload"
    r"|send|post|execute|run|invoke|deploy|push|publish)",
    re.IGNORECASE,
)
_READ_VERBS = re.compile(
    r"(read|get|fetch|list|describe|query|search|download|view|show|head|select)",
    re.IGNORECASE,
)

# Well-known dangerous tool names (exact or substring match).
_HIGH_RISK_TOOLS = re.compile(
    r"(rm_rf|drop_table|exec_command|shell|sudo|chmod|chown|format_disk|truncate_table)",
    re.IGNORECASE,
)


class OperationTypeScorer:
    """Classify a tool call's risk by its verb semantics (APEP-064).

    Scoring:
      - delete / destructive operations → 0.9
      - write / mutating operations     → 0.5
      - read / safe operations          → 0.1
      - unknown                         → 0.3
      - known high-risk tool name       → 1.0  (overrides verb score)
    """

    def score(self, tool_name: str, tool_args: dict[str, Any] | None = None) -> RiskFactor:
        # Check for known high-risk tool names first
        if _HIGH_RISK_TOOLS.search(tool_name):
            return RiskFactor(
                factor_name="operation_type",
                score=1.0,
                detail=f"High-risk tool: {tool_name}",
            )

        if _DELETE_VERBS.search(tool_name):
            return RiskFactor(
                factor_name="operation_type",
                score=0.9,
                detail=f"Destructive operation: {tool_name}",
            )

        if _WRITE_VERBS.search(tool_name):
            return RiskFactor(
                factor_name="operation_type",
                score=0.5,
                detail=f"Write/mutating operation: {tool_name}",
            )

        if _READ_VERBS.search(tool_name):
            return RiskFactor(
                factor_name="operation_type",
                score=0.1,
                detail=f"Read-only operation: {tool_name}",
            )

        return RiskFactor(
            factor_name="operation_type",
            score=0.3,
            detail=f"Unknown operation type: {tool_name}",
        )


# ---------------------------------------------------------------------------
# APEP-065: DataSensitivityScorer
# ---------------------------------------------------------------------------

# Patterns that indicate sensitive data in tool arguments.
_PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),                          # SSN
    re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b"),  # IBAN
    re.compile(r"\b\d{12,16}\b"),                                    # Credit card (loose)
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # Email
    re.compile(r"\b\d{10}\b"),                                       # Phone (10-digit)
    re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"),              # Phone (US format)
    re.compile(r"\b[A-Z]\d{7}\b"),                                   # Passport (US-style)
]

_CREDENTIAL_PATTERNS = [
    re.compile(
        r"(password|passwd|secret|token|api_key|apikey|auth_token|access_key|private_key)",
        re.IGNORECASE,
    ),
    re.compile(r"(AKIA[0-9A-Z]{16})"),                              # AWS access key
    re.compile(r"(ghp_[A-Za-z0-9_]{36})"),                          # GitHub PAT
    re.compile(r"(sk-[A-Za-z0-9]{32,})"),                           # OpenAI-style key
    re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),        # PEM private key
    re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),  # Bearer token
]

_FINANCIAL_PATTERNS = [
    re.compile(
        r"(account_number|routing_number|swift_code|bank_account|credit_card)",
        re.IGNORECASE,
    ),
    re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"),   # Credit card formatted
    re.compile(r"(amount|balance|transaction|payment|invoice)\s*[:=]\s*\$?\d+", re.IGNORECASE),
]


class DataSensitivityScorer:
    """Detect PII, credentials, and financial data in tool arguments (APEP-065).

    Scoring:
      - credentials detected  → 0.95
      - PII detected          → 0.8
      - financial data         → 0.7
      - none                   → 0.0
    Uses max across all categories.
    """

    def score(self, tool_args: dict[str, Any] | None = None) -> RiskFactor:
        if not tool_args:
            return RiskFactor(factor_name="data_sensitivity", score=0.0, detail="No arguments")

        args_str = _flatten_args(tool_args)

        found_categories: list[str] = []
        max_score = 0.0

        # Check credentials first (highest risk)
        for pat in _CREDENTIAL_PATTERNS:
            if pat.search(args_str):
                max_score = max(max_score, 0.95)
                found_categories.append("credentials")
                break

        for pat in _PII_PATTERNS:
            if pat.search(args_str):
                max_score = max(max_score, 0.8)
                found_categories.append("PII")
                break

        for pat in _FINANCIAL_PATTERNS:
            if pat.search(args_str):
                max_score = max(max_score, 0.7)
                found_categories.append("financial")
                break

        if not found_categories:
            return RiskFactor(
                factor_name="data_sensitivity",
                score=0.0,
                detail="No sensitive data detected",
            )

        return RiskFactor(
            factor_name="data_sensitivity",
            score=max_score,
            detail=f"Sensitive data detected: {', '.join(found_categories)}",
        )


# ---------------------------------------------------------------------------
# APEP-066: TaintScorer
# ---------------------------------------------------------------------------


class TaintScorer:
    """Elevate risk score based on argument taint levels (APEP-066).

    Scoring:
      - QUARANTINE nodes present → 1.0
      - UNTRUSTED nodes present  → 0.7
      - TRUSTED only             → 0.0
      - No taint info            → 0.0
    """

    def score(
        self, session_id: str, taint_node_ids: list[UUID] | None = None
    ) -> RiskFactor:
        if not taint_node_ids:
            return RiskFactor(factor_name="taint", score=0.0, detail="No taint nodes")

        graph = session_graph_manager.get_session(session_id)
        if graph is None:
            return RiskFactor(factor_name="taint", score=0.0, detail="No taint session")

        max_level = TaintLevel.TRUSTED
        for nid in taint_node_ids:
            node = graph.get_node(nid)
            if node is None:
                continue
            if node.taint_level == TaintLevel.QUARANTINE:
                max_level = TaintLevel.QUARANTINE
                break  # Can't get higher
            if node.taint_level == TaintLevel.UNTRUSTED:
                max_level = TaintLevel.UNTRUSTED

        score_map = {
            TaintLevel.QUARANTINE: 1.0,
            TaintLevel.UNTRUSTED: 0.7,
            TaintLevel.TRUSTED: 0.0,
        }

        s = score_map[max_level]
        return RiskFactor(
            factor_name="taint",
            score=s,
            detail=f"Max taint level: {max_level.value}",
        )


# ---------------------------------------------------------------------------
# APEP-067: SessionAccumulatedRiskScorer
# ---------------------------------------------------------------------------


class SessionAccumulatedRiskScorer:
    """Cumulative risk score from session history (APEP-067).

    Queries recent audit decisions for the session and computes a running
    average of past risk scores.  A session with many high-risk calls
    accumulates a higher baseline.

    Scoring:
      - mean(past_risk_scores) → capped at 1.0
      - no history             → 0.0
    """

    async def score(self, session_id: str) -> RiskFactor:
        db = db_module.get_database()
        cursor = db[db_module.AUDIT_DECISIONS].find(
            {"session_id": session_id},
            {"risk_score": 1, "_id": 0},
        ).sort("timestamp", -1).limit(50)

        scores: list[float] = []
        async for doc in cursor:
            rs = doc.get("risk_score", 0.0)
            if isinstance(rs, (int, float)):
                scores.append(float(rs))

        if not scores:
            return RiskFactor(
                factor_name="session_accumulated",
                score=0.0,
                detail="No session history",
            )

        avg = sum(scores) / len(scores)
        # Boost slightly when there are many high-risk calls
        count_factor = min(len(scores) / 50.0, 1.0)
        accumulated = min(avg * (1.0 + 0.3 * count_factor), 1.0)

        return RiskFactor(
            factor_name="session_accumulated",
            score=round(accumulated, 4),
            detail=f"Session history: {len(scores)} calls, avg={avg:.3f}",
        )


# ---------------------------------------------------------------------------
# APEP-068: DelegationDepthScorer
# ---------------------------------------------------------------------------


class DelegationDepthScorer:
    """Higher risk for deeper delegation chains (APEP-068).

    Scoring:
      - depth 0 (direct call) → 0.0
      - depth 1               → 0.2
      - depth 2               → 0.4
      - depth 3               → 0.6
      - depth 4               → 0.8
      - depth ≥ 5             → 1.0
    Linear interpolation: min(depth / 5, 1.0).
    """

    def score(self, delegation_hops: list[Any] | None = None) -> RiskFactor:
        depth = len(delegation_hops) if delegation_hops else 0

        s = min(depth / 5.0, 1.0)
        return RiskFactor(
            factor_name="delegation_depth",
            score=round(s, 4),
            detail=f"Delegation depth: {depth}",
        )


# ---------------------------------------------------------------------------
# Sprint 33 — APEP-265: ContextAuthorityScorer
# ---------------------------------------------------------------------------


class ContextAuthorityScorer:
    """Adjust risk based on context authority distribution (APEP-265).

    Scoring:
      - All AUTHORITATIVE → 0.0
      - Mix with DERIVED (no UNTRUSTED) → 0.3 scaled by derived proportion
      - Any UNTRUSTED present → 0.7
      - Majority UNTRUSTED → 0.9
      - No entries → 0.0
    """

    async def score(self, session_id: str) -> RiskFactor:
        from app.services.context_authority import context_authority_tracker

        authority_score = await context_authority_tracker.get_authority_score(session_id)

        if authority_score >= 0.9:
            detail = "Majority UNTRUSTED context"
        elif authority_score >= 0.7:
            detail = "UNTRUSTED context present"
        elif authority_score > 0.0:
            detail = f"DERIVED context present (score={authority_score:.4f})"
        else:
            detail = "All context AUTHORITATIVE or no context"

        return RiskFactor(
            factor_name="context_authority",
            score=authority_score,
            detail=detail,
        )


# ---------------------------------------------------------------------------
# APEP-069: RiskAggregator
# ---------------------------------------------------------------------------


class RiskAggregator:
    """Weighted-sum aggregation of risk factors (APEP-069).

    Loads configuration from MongoDB (``risk_model_configs`` collection).
    Falls back to default weights if no config is found.
    Supports per-role weight overrides.
    """

    def __init__(self) -> None:
        self._cached_config: RiskModelConfig | None = None

    async def load_config(self) -> RiskModelConfig:
        """Load the active risk model config from MongoDB."""
        db = db_module.get_database()
        doc = await db[db_module.RISK_MODEL_CONFIGS].find_one(
            {"model_id": "default", "enabled": True}
        )
        if doc is not None:
            doc.pop("_id", None)
            self._cached_config = RiskModelConfig(**doc)
        else:
            self._cached_config = RiskModelConfig()
        return self._cached_config

    def get_config(self) -> RiskModelConfig:
        """Return cached config or default."""
        if self._cached_config is None:
            return RiskModelConfig()
        return self._cached_config

    def aggregate(
        self,
        factors: list[RiskFactor],
        agent_roles: list[str] | None = None,
        config: RiskModelConfig | None = None,
    ) -> float:
        """Compute weighted sum of risk factors, returning a score in [0, 1].

        If ``agent_roles`` is provided, checks for per-role weight overrides
        in the config (first matching role wins).
        """
        cfg = config or self.get_config()

        # Determine weights: check role overrides first
        weights = cfg.default_weights
        if agent_roles:
            for role in agent_roles:
                if role in cfg.role_overrides:
                    weights = cfg.role_overrides[role]
                    break

        weight_map = {
            "operation_type": weights.operation_type,
            "data_sensitivity": weights.data_sensitivity,
            "taint": weights.taint,
            "session_accumulated": weights.session_accumulated,
            "delegation_depth": weights.delegation_depth,
            "context_authority": weights.context_authority,
        }

        total_weight = sum(weight_map.values())
        if total_weight == 0:
            return 0.0

        weighted_sum = 0.0
        for factor in factors:
            w = weight_map.get(factor.factor_name, 0.0)
            weighted_sum += factor.score * w

        # Normalise by total weight so weights don't need to sum to 1
        score = weighted_sum / total_weight
        return round(min(max(score, 0.0), 1.0), 4)


# ---------------------------------------------------------------------------
# Composite scorer — orchestrates all individual scorers
# ---------------------------------------------------------------------------


class RiskScoringEngine:
    """Orchestrates all risk scorers and aggregates the result.

    Usage:
        score, factors = await risk_engine.compute(request, agent_roles)
    """

    def __init__(self) -> None:
        self.operation_type_scorer = OperationTypeScorer()
        self.data_sensitivity_scorer = DataSensitivityScorer()
        self.taint_scorer = TaintScorer()
        self.session_accumulated_scorer = SessionAccumulatedRiskScorer()
        self.delegation_depth_scorer = DelegationDepthScorer()
        self.context_authority_scorer = ContextAuthorityScorer()
        self.aggregator = RiskAggregator()

    async def compute(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        session_id: str,
        taint_node_ids: list[UUID] | None = None,
        delegation_hops: list[Any] | None = None,
        agent_roles: list[str] | None = None,
    ) -> tuple[float, list[RiskFactor]]:
        """Compute composite risk score.

        Returns (score, list_of_factors).
        """
        # Load config from DB (cached after first call)
        await self.aggregator.load_config()

        factors: list[RiskFactor] = []

        # Synchronous scorers
        factors.append(self.operation_type_scorer.score(tool_name, tool_args))
        factors.append(self.data_sensitivity_scorer.score(tool_args))
        factors.append(self.taint_scorer.score(session_id, taint_node_ids))
        factors.append(self.delegation_depth_scorer.score(delegation_hops))

        # Async scorers
        factors.append(await self.session_accumulated_scorer.score(session_id))
        factors.append(await self.context_authority_scorer.score(session_id))

        score = self.aggregator.aggregate(factors, agent_roles)
        return score, factors


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _flatten_args(args: dict[str, Any]) -> str:
    """Recursively flatten argument dict values to a single string for pattern matching."""
    parts: list[str] = []
    for key, val in args.items():
        parts.append(str(key))
        if isinstance(val, dict):
            parts.append(_flatten_args(val))
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    parts.append(_flatten_args(item))
                else:
                    parts.append(str(item))
        else:
            parts.append(str(val))
    return " ".join(parts)


# Module-level singleton
risk_engine = RiskScoringEngine()
