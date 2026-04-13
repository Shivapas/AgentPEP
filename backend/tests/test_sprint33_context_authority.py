"""Tests for Sprint 33 ContextAuthorityTracker (APEP-264) and risk integration (APEP-265).

Tests context authority classification, entry tracking, session distribution,
authority scoring, and risk scoring engine integration.
"""

from uuid import uuid4

import pytest

from app.db import mongodb as db_module
from app.models.policy import RiskFactor, TaintSource
from app.services.context_authority import (
    ContextAuthority,
    ContextAuthorityTracker,
    ContextEntry,
    context_authority_tracker,
)
from app.services.risk_scoring import ContextAuthorityScorer, RiskScoringEngine


# ---------------------------------------------------------------------------
# APEP-264: ContextAuthorityTracker — classify
# ---------------------------------------------------------------------------


class TestClassify:
    """APEP-264: Source → authority classification."""

    def test_classify_user_prompt_authoritative(self) -> None:
        result = context_authority_tracker.classify(TaintSource.USER_PROMPT)
        assert result == ContextAuthority.AUTHORITATIVE

    def test_classify_system_prompt_authoritative(self) -> None:
        result = context_authority_tracker.classify(TaintSource.SYSTEM_PROMPT)
        assert result == ContextAuthority.AUTHORITATIVE

    def test_classify_tool_output_derived(self) -> None:
        result = context_authority_tracker.classify(TaintSource.TOOL_OUTPUT)
        assert result == ContextAuthority.DERIVED

    def test_classify_agent_msg_derived(self) -> None:
        result = context_authority_tracker.classify(TaintSource.AGENT_MSG)
        assert result == ContextAuthority.DERIVED

    def test_classify_cross_agent_derived(self) -> None:
        result = context_authority_tracker.classify(TaintSource.CROSS_AGENT)
        assert result == ContextAuthority.DERIVED

    def test_classify_sanitised_derived(self) -> None:
        result = context_authority_tracker.classify(TaintSource.SANITISED)
        assert result == ContextAuthority.DERIVED

    def test_classify_web_untrusted(self) -> None:
        result = context_authority_tracker.classify(TaintSource.WEB)
        assert result == ContextAuthority.UNTRUSTED

    def test_classify_email_untrusted(self) -> None:
        result = context_authority_tracker.classify(TaintSource.EMAIL)
        assert result == ContextAuthority.UNTRUSTED


# ---------------------------------------------------------------------------
# APEP-264: ContextAuthorityTracker — track_entry
# ---------------------------------------------------------------------------


class TestTrackEntry:
    """APEP-264: Track and persist context entries."""

    async def test_track_entry_persists(self, mock_mongodb) -> None:
        entry = await context_authority_tracker.track_entry(
            session_id="sess-1",
            source=TaintSource.USER_PROMPT,
            content_hash="abc123",
            agent_id="agent-alpha",
        )
        assert isinstance(entry, ContextEntry)
        assert entry.authority == ContextAuthority.AUTHORITATIVE
        assert entry.session_id == "sess-1"
        assert entry.content_hash == "abc123"

        # Verify persisted in DB
        doc = await mock_mongodb[db_module.CONTEXT_ENTRIES].find_one(
            {"session_id": "sess-1"}
        )
        assert doc is not None
        assert doc["authority"] == "AUTHORITATIVE"

    async def test_track_entry_untrusted_source(self, mock_mongodb) -> None:
        entry = await context_authority_tracker.track_entry(
            session_id="sess-2",
            source=TaintSource.WEB,
        )
        assert entry.authority == ContextAuthority.UNTRUSTED

    async def test_track_entry_derived_source(self, mock_mongodb) -> None:
        entry = await context_authority_tracker.track_entry(
            session_id="sess-3",
            source=TaintSource.TOOL_OUTPUT,
        )
        assert entry.authority == ContextAuthority.DERIVED


# ---------------------------------------------------------------------------
# APEP-264: ContextAuthorityTracker — get_session_authorities
# ---------------------------------------------------------------------------


class TestSessionAuthorities:
    """APEP-264: Session authority distribution counts."""

    async def test_session_authority_distribution(self, mock_mongodb) -> None:
        # Track a mix of sources
        await context_authority_tracker.track_entry("sess-mix", TaintSource.USER_PROMPT)
        await context_authority_tracker.track_entry("sess-mix", TaintSource.USER_PROMPT)
        await context_authority_tracker.track_entry("sess-mix", TaintSource.TOOL_OUTPUT)
        await context_authority_tracker.track_entry("sess-mix", TaintSource.WEB)

        counts = await context_authority_tracker.get_session_authorities("sess-mix")
        assert counts[ContextAuthority.AUTHORITATIVE] == 2
        assert counts[ContextAuthority.DERIVED] == 1
        assert counts[ContextAuthority.UNTRUSTED] == 1

    async def test_empty_session_returns_zeros(self, mock_mongodb) -> None:
        counts = await context_authority_tracker.get_session_authorities("empty-sess")
        assert counts[ContextAuthority.AUTHORITATIVE] == 0
        assert counts[ContextAuthority.DERIVED] == 0
        assert counts[ContextAuthority.UNTRUSTED] == 0


# ---------------------------------------------------------------------------
# APEP-265: ContextAuthorityTracker — get_authority_score
# ---------------------------------------------------------------------------


class TestAuthorityScore:
    """APEP-265: Authority-based risk scoring."""

    async def test_all_authoritative_zero(self, mock_mongodb) -> None:
        await context_authority_tracker.track_entry("sess-auth", TaintSource.USER_PROMPT)
        await context_authority_tracker.track_entry("sess-auth", TaintSource.SYSTEM_PROMPT)
        score = await context_authority_tracker.get_authority_score("sess-auth")
        assert score == 0.0

    async def test_mixed_derived_scaled(self, mock_mongodb) -> None:
        await context_authority_tracker.track_entry("sess-der", TaintSource.USER_PROMPT)
        await context_authority_tracker.track_entry("sess-der", TaintSource.TOOL_OUTPUT)
        score = await context_authority_tracker.get_authority_score("sess-der")
        # 1 derived out of 2 → 0.3 * 0.5 = 0.15
        assert score == 0.15

    async def test_all_derived_max(self, mock_mongodb) -> None:
        await context_authority_tracker.track_entry("sess-all-der", TaintSource.TOOL_OUTPUT)
        await context_authority_tracker.track_entry("sess-all-der", TaintSource.AGENT_MSG)
        score = await context_authority_tracker.get_authority_score("sess-all-der")
        # 2 derived out of 2 → 0.3 * 1.0 = 0.3
        assert score == 0.3

    async def test_any_untrusted_high(self, mock_mongodb) -> None:
        await context_authority_tracker.track_entry("sess-untrust", TaintSource.USER_PROMPT)
        await context_authority_tracker.track_entry("sess-untrust", TaintSource.USER_PROMPT)
        await context_authority_tracker.track_entry("sess-untrust", TaintSource.WEB)
        score = await context_authority_tracker.get_authority_score("sess-untrust")
        # 1 untrusted out of 3 (< 50%) → 0.7
        assert score == 0.7

    async def test_majority_untrusted_very_high(self, mock_mongodb) -> None:
        await context_authority_tracker.track_entry("sess-maj", TaintSource.WEB)
        await context_authority_tracker.track_entry("sess-maj", TaintSource.EMAIL)
        await context_authority_tracker.track_entry("sess-maj", TaintSource.USER_PROMPT)
        score = await context_authority_tracker.get_authority_score("sess-maj")
        # 2 untrusted out of 3 (> 50%) → 0.9
        assert score == 0.9

    async def test_no_entries_zero(self, mock_mongodb) -> None:
        score = await context_authority_tracker.get_authority_score("no-entries")
        assert score == 0.0


# ---------------------------------------------------------------------------
# APEP-265: ContextAuthorityScorer (risk scoring integration)
# ---------------------------------------------------------------------------


class TestContextAuthorityScorer:
    """APEP-265: Scorer produces correct RiskFactor for aggregation."""

    async def test_scorer_all_authoritative_zero(self, mock_mongodb) -> None:
        await context_authority_tracker.track_entry("scorer-auth", TaintSource.USER_PROMPT)
        scorer = ContextAuthorityScorer()
        factor = await scorer.score("scorer-auth")
        assert factor.factor_name == "context_authority"
        assert factor.score == 0.0
        assert "AUTHORITATIVE" in factor.detail

    async def test_scorer_untrusted_high(self, mock_mongodb) -> None:
        await context_authority_tracker.track_entry("scorer-untrust", TaintSource.WEB)
        scorer = ContextAuthorityScorer()
        factor = await scorer.score("scorer-untrust")
        assert factor.score == 0.9  # Only untrusted → majority
        assert "UNTRUSTED" in factor.detail

    async def test_scorer_mixed_derived(self, mock_mongodb) -> None:
        await context_authority_tracker.track_entry("scorer-der", TaintSource.USER_PROMPT)
        await context_authority_tracker.track_entry("scorer-der", TaintSource.TOOL_OUTPUT)
        scorer = ContextAuthorityScorer()
        factor = await scorer.score("scorer-der")
        assert factor.score == 0.15
        assert "DERIVED" in factor.detail

    async def test_scorer_no_entries(self, mock_mongodb) -> None:
        scorer = ContextAuthorityScorer()
        factor = await scorer.score("no-session")
        assert factor.score == 0.0


# ---------------------------------------------------------------------------
# APEP-265: RiskScoringEngine integration
# ---------------------------------------------------------------------------


class TestRiskEngineIntegration:
    """APEP-265: Context authority factor included in risk engine output."""

    async def test_risk_engine_includes_context_authority(self, mock_mongodb) -> None:
        # Track an untrusted context entry
        await context_authority_tracker.track_entry("risk-sess", TaintSource.WEB)

        engine = RiskScoringEngine()
        score, factors = await engine.compute(
            tool_name="read_data",
            tool_args={},
            session_id="risk-sess",
        )

        factor_names = [f.factor_name for f in factors]
        assert "context_authority" in factor_names

        ctx_factor = next(f for f in factors if f.factor_name == "context_authority")
        assert ctx_factor.score == 0.9  # Sole untrusted entry → majority

    async def test_risk_engine_no_context_entries(self, mock_mongodb) -> None:
        engine = RiskScoringEngine()
        score, factors = await engine.compute(
            tool_name="read_data",
            tool_args={},
            session_id="empty-risk-sess",
        )

        factor_names = [f.factor_name for f in factors]
        assert "context_authority" in factor_names

        ctx_factor = next(f for f in factors if f.factor_name == "context_authority")
        assert ctx_factor.score == 0.0
