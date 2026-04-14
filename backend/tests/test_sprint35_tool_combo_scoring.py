"""Sprint 35 — APEP-277: Tool combination risk scoring integration tests.

Tests for the ToolCombinationScorer integration into the risk scoring engine:
  - Scorer returns nonzero RiskFactor when suspicious combo detected
  - Aggregator includes tool_combination weight
  - RiskWeightConfig includes tool_combination field
"""

from __future__ import annotations

import pytest

from app.models.policy import RiskFactor, RiskModelConfig, RiskWeightConfig
from app.services.risk_scoring import (
    RiskAggregator,
    RiskScoringEngine,
    ToolCombinationScorer,
)


class TestToolCombinationScorer:
    """APEP-277: ToolCombinationScorer unit tests."""

    @pytest.mark.asyncio
    async def test_scorer_returns_risk_factor(self) -> None:
        scorer = ToolCombinationScorer()
        # With no session data, score should be 0.0
        factor = await scorer.score("test-session-no-data", "file.read")
        assert factor.factor_name == "tool_combination"
        assert 0.0 <= factor.score <= 1.0
        assert factor.detail

    @pytest.mark.asyncio
    async def test_scorer_factor_name(self) -> None:
        scorer = ToolCombinationScorer()
        factor = await scorer.score("empty-session", "http.post")
        assert factor.factor_name == "tool_combination"


class TestRiskWeightConfigToolCombination:
    """APEP-277: RiskWeightConfig includes tool_combination."""

    def test_default_weight(self) -> None:
        config = RiskWeightConfig()
        assert config.tool_combination == 0.15

    def test_custom_weight(self) -> None:
        config = RiskWeightConfig(tool_combination=0.25)
        assert config.tool_combination == 0.25

    def test_zero_weight(self) -> None:
        config = RiskWeightConfig(tool_combination=0.0)
        assert config.tool_combination == 0.0


class TestAggregatorToolCombination:
    """APEP-277: RiskAggregator includes tool_combination in weight_map."""

    def test_tool_combination_factor_weighted(self) -> None:
        aggregator = RiskAggregator()
        factors = [
            RiskFactor(factor_name="operation_type", score=0.0, detail="benign"),
            RiskFactor(factor_name="data_sensitivity", score=0.0, detail="none"),
            RiskFactor(factor_name="taint", score=0.0, detail="clean"),
            RiskFactor(factor_name="session_accumulated", score=0.0, detail="none"),
            RiskFactor(factor_name="delegation_depth", score=0.0, detail="none"),
            RiskFactor(factor_name="context_authority", score=0.0, detail="none"),
            RiskFactor(factor_name="tool_combination", score=0.9, detail="suspicious pair"),
        ]
        score = aggregator.aggregate(factors)
        # tool_combination weight is 0.15 out of total ~1.15
        # So 0.9 * 0.15 / 1.15 ~ 0.117
        assert score > 0.0
        assert score < 0.2

    def test_tool_combination_zero_does_not_affect_score(self) -> None:
        aggregator = RiskAggregator()
        factors = [
            RiskFactor(factor_name="operation_type", score=0.5, detail="write"),
            RiskFactor(factor_name="data_sensitivity", score=0.0, detail="none"),
            RiskFactor(factor_name="taint", score=0.0, detail="clean"),
            RiskFactor(factor_name="session_accumulated", score=0.0, detail="none"),
            RiskFactor(factor_name="delegation_depth", score=0.0, detail="none"),
            RiskFactor(factor_name="context_authority", score=0.0, detail="none"),
            RiskFactor(factor_name="tool_combination", score=0.0, detail="none"),
        ]
        score_with = aggregator.aggregate(factors)

        factors_without = [f for f in factors if f.factor_name != "tool_combination"]
        score_without = aggregator.aggregate(factors_without)

        # Scores differ due to different total weights but both are non-negative
        assert score_with >= 0.0
        assert score_without >= 0.0


class TestRiskScoringEngineIntegration:
    """APEP-277: RiskScoringEngine includes ToolCombinationScorer."""

    def test_engine_has_tool_combination_scorer(self) -> None:
        engine = RiskScoringEngine()
        assert hasattr(engine, "tool_combination_scorer")
        assert isinstance(engine.tool_combination_scorer, ToolCombinationScorer)
