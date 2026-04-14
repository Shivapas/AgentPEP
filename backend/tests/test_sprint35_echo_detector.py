"""Sprint 35 — APEP-279: EchoDetector tests.

Tests for the echo detection engine covering:
  - Exact repetition detection
  - Near-duplicate detection via Jaccard similarity
  - Risk scoring logic
  - Async check method
  - Edge cases (empty args, single call)
"""

from __future__ import annotations

import pytest

from app.services.echo_detector import (
    EchoDetector,
    EchoResult,
    echo_detector,
)


class TestExactRepetition:
    """APEP-279: Exact repetition detection."""

    def test_no_repeats(self) -> None:
        detector = EchoDetector()
        current = detector._hash_args('{"key": "value1"}')
        recent = [
            detector._hash_args('{"key": "value2"}'),
            detector._hash_args('{"key": "value3"}'),
        ]
        count = detector._detect_exact_repetition(current, recent)
        assert count == 0

    def test_two_exact_repeats(self) -> None:
        detector = EchoDetector()
        current = detector._hash_args('{"key": "value1"}')
        recent = [current, current, detector._hash_args('{"other": "val"}')]
        count = detector._detect_exact_repetition(current, recent)
        assert count == 2

    def test_three_exact_repeats(self) -> None:
        detector = EchoDetector()
        current = detector._hash_args('{"key": "value1"}')
        recent = [current, current, current]
        count = detector._detect_exact_repetition(current, recent)
        assert count == 3


class TestNearDuplicateDetection:
    """APEP-279: Near-duplicate detection via Jaccard similarity."""

    def test_identical_strings_not_near_duplicate(self) -> None:
        """Exact matches are counted as exact repeats, not near-duplicates."""
        detector = EchoDetector(similarity_threshold=0.85)
        similar = detector._detect_near_duplicates(
            '{"name": "alice"}',
            ['{"name": "alice"}'],
        )
        # Similarity = 1.0 which is exact, not near-duplicate
        assert len(similar) == 0

    def test_similar_strings_detected(self) -> None:
        detector = EchoDetector(similarity_threshold=0.5)
        # Two strings that share many tokens
        current = "read file /etc/passwd and return contents"
        past = "read file /etc/passwd and return data"
        similar = detector._detect_near_duplicates(current, [past])
        assert len(similar) == 1
        assert similar[0] >= 0.5

    def test_dissimilar_strings_not_detected(self) -> None:
        detector = EchoDetector(similarity_threshold=0.85)
        current = "create new user account"
        past = "delete old database records permanently"
        similar = detector._detect_near_duplicates(current, [past])
        assert len(similar) == 0


class TestJaccardSimilarity:
    """APEP-279: Jaccard similarity computation."""

    def test_identical_similarity_is_one(self) -> None:
        sim = EchoDetector._compute_similarity("hello world", "hello world")
        assert sim == 1.0

    def test_no_overlap_similarity_is_zero(self) -> None:
        sim = EchoDetector._compute_similarity("aaa bbb ccc", "ddd eee fff")
        assert sim == 0.0

    def test_partial_overlap(self) -> None:
        # Tokens: {hello, world} vs {hello, there}
        # Intersection: {hello}, Union: {hello, world, there}
        sim = EchoDetector._compute_similarity("hello world", "hello there")
        assert sim == pytest.approx(1 / 3, abs=0.01)

    def test_empty_strings(self) -> None:
        assert EchoDetector._compute_similarity("", "") == 0.0
        assert EchoDetector._compute_similarity("hello", "") == 0.0
        assert EchoDetector._compute_similarity("", "hello") == 0.0

    def test_case_insensitive(self) -> None:
        sim = EchoDetector._compute_similarity("Hello World", "hello world")
        assert sim == 1.0


class TestRiskScoring:
    """APEP-279: Echo risk score computation."""

    def test_three_plus_repeats_high_risk(self) -> None:
        score = EchoDetector._compute_risk_score(3, 0, 20)
        assert score == 0.9

    def test_two_repeats_medium_risk(self) -> None:
        score = EchoDetector._compute_risk_score(2, 0, 20)
        assert score == 0.6

    def test_one_repeat_zero_risk(self) -> None:
        score = EchoDetector._compute_risk_score(1, 0, 20)
        assert score == 0.0

    def test_near_duplicates_scaled_risk(self) -> None:
        score = EchoDetector._compute_risk_score(0, 5, 20)
        assert score == pytest.approx(0.4 * 5 / 20, abs=0.01)

    def test_no_echoes_zero_risk(self) -> None:
        score = EchoDetector._compute_risk_score(0, 0, 20)
        assert score == 0.0

    def test_near_duplicates_capped_at_04(self) -> None:
        score = EchoDetector._compute_risk_score(0, 100, 20)
        assert score <= 0.4


class TestEchoDetectorAsync:
    """APEP-279: Async check method."""

    @pytest.mark.asyncio
    async def test_check_returns_echo_result(self) -> None:
        detector = EchoDetector()
        result = await detector.check("test-session", "file.read", {"path": "/tmp"})
        assert isinstance(result, EchoResult)
        assert 0.0 <= result.risk_score <= 1.0

    @pytest.mark.asyncio
    async def test_check_empty_session(self) -> None:
        detector = EchoDetector()
        result = await detector.check("empty-session", "file.read", {"path": "/tmp"})
        assert not result.is_echo
        assert result.risk_score == 0.0
        assert result.exact_repeats == 0


class TestArgsConversion:
    """APEP-279: Argument serialisation helpers."""

    def test_args_to_string_deterministic(self) -> None:
        detector = EchoDetector()
        args = {"b": 2, "a": 1}
        s1 = detector._args_to_string(args)
        s2 = detector._args_to_string(args)
        assert s1 == s2

    def test_args_to_string_sorted_keys(self) -> None:
        detector = EchoDetector()
        s = detector._args_to_string({"z": 1, "a": 2})
        assert s.index('"a"') < s.index('"z"')

    def test_hash_consistency(self) -> None:
        detector = EchoDetector()
        h1 = detector._hash_args('{"key": "value"}')
        h2 = detector._hash_args('{"key": "value"}')
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest


class TestEchoSingleton:
    """Module-level singleton."""

    def test_singleton_exists(self) -> None:
        assert echo_detector is not None
        assert isinstance(echo_detector, EchoDetector)

    def test_default_config(self) -> None:
        assert echo_detector.similarity_threshold == 0.85
        assert echo_detector.window_size == 20
