"""Sprint 35 — APEP-276: ToolCombinationDetector tests.

Tests for the tool combination detection engine covering:
  - Pair detection (exact match, glob match, bidirectional, no match)
  - Sequence detection (within/outside time window, partial match)
  - Session-level orchestration
  - Library completeness (16+ pairs, 5+ sequences)
"""

from __future__ import annotations

import time

import pytest

from app.services.tool_combination_detector import (
    MatchedToolCombination,
    MatchedToolSequence,
    ToolCallRecord,
    ToolCombinationDetector,
    ToolCombinationResult,
    ToolCombinationSignature,
    ToolSequenceSignature,
    tool_combination_detector,
)


class TestPairDetection:
    """APEP-276: Suspicious tool pair detection."""

    def test_exact_pair_match(self) -> None:
        detector = ToolCombinationDetector()
        matches = detector.check_pair("file.read", "http.post")
        assert len(matches) >= 1
        assert any(m.signature_id == "TC-001" for m in matches)

    def test_glob_pair_match(self) -> None:
        detector = ToolCombinationDetector()
        # secret.* pattern should match secret.get
        matches = detector.check_pair("secret.get", "http.post")
        assert len(matches) >= 1
        assert any(m.signature_id == "TC-002" for m in matches)

    def test_bidirectional_match(self) -> None:
        """Pairs should match regardless of order."""
        detector = ToolCombinationDetector()
        matches_ab = detector.check_pair("file.read", "http.post")
        matches_ba = detector.check_pair("http.post", "file.read")
        # Both orderings should produce the same signature matches
        ids_ab = {m.signature_id for m in matches_ab}
        ids_ba = {m.signature_id for m in matches_ba}
        assert ids_ab == ids_ba

    def test_no_match_benign_pair(self) -> None:
        detector = ToolCombinationDetector()
        matches = detector.check_pair("file.read", "file.list")
        assert len(matches) == 0

    def test_self_pair_destructive(self) -> None:
        """file.delete + file.delete should match TC-008."""
        detector = ToolCombinationDetector()
        matches = detector.check_pair("file.delete", "file.delete")
        assert any(m.signature_id == "TC-008" for m in matches)

    def test_privilege_escalation_pair(self) -> None:
        detector = ToolCombinationDetector()
        matches = detector.check_pair("admin.modify_role", "secret.read")
        assert any(m.signature_id == "TC-009" for m in matches)

    def test_all_pair_signatures_have_required_fields(self) -> None:
        detector = ToolCombinationDetector()
        for sig in detector.pairs:
            assert sig.signature_id
            assert sig.tool_a_pattern
            assert sig.tool_b_pattern
            assert 0.0 < sig.risk_boost <= 1.0
            assert sig.category
            assert sig.description

    def test_custom_pairs(self) -> None:
        custom = [
            ToolCombinationSignature(
                signature_id="CUSTOM-001",
                tool_a_pattern="foo",
                tool_b_pattern="bar",
                risk_boost=0.5,
                category="test",
                description="Custom test pair",
            )
        ]
        detector = ToolCombinationDetector(pairs=custom, sequences=[])
        matches = detector.check_pair("foo", "bar")
        assert len(matches) == 1
        assert matches[0].signature_id == "CUSTOM-001"
        # Original pairs should not be present
        assert detector.check_pair("file.read", "http.post") == []


class TestSequenceDetection:
    """APEP-276: Suspicious tool sequence detection."""

    def test_sequence_match_within_window(self) -> None:
        detector = ToolCombinationDetector()
        now = time.time()
        history = [
            ToolCallRecord(tool_name="secret.read", timestamp=now - 60),
            ToolCallRecord(tool_name="base64.encode", timestamp=now - 30),
            ToolCallRecord(tool_name="http.post", timestamp=now),
        ]
        matches = detector.check_sequence(history)
        assert any(m.signature_id == "TS-001" for m in matches)

    def test_sequence_no_match_outside_window(self) -> None:
        detector = ToolCombinationDetector()
        now = time.time()
        history = [
            ToolCallRecord(tool_name="secret.read", timestamp=now - 600),
            ToolCallRecord(tool_name="base64.encode", timestamp=now - 400),
            ToolCallRecord(tool_name="http.post", timestamp=now),
        ]
        matches = detector.check_sequence(history)
        # TS-001 has a 300s window; 600s gap should not match
        assert not any(m.signature_id == "TS-001" for m in matches)

    def test_sequence_partial_no_match(self) -> None:
        """Incomplete sequence should not trigger a match."""
        detector = ToolCombinationDetector()
        now = time.time()
        history = [
            ToolCallRecord(tool_name="secret.read", timestamp=now - 60),
            ToolCallRecord(tool_name="base64.encode", timestamp=now),
            # Missing the final http.post
        ]
        matches = detector.check_sequence(history)
        assert not any(m.signature_id == "TS-001" for m in matches)

    def test_sequence_with_interleaved_benign_calls(self) -> None:
        """Sequence should match even with benign calls interleaved."""
        detector = ToolCombinationDetector()
        now = time.time()
        history = [
            ToolCallRecord(tool_name="db.query", timestamp=now - 100),
            ToolCallRecord(tool_name="file.list", timestamp=now - 80),  # benign
            ToolCallRecord(tool_name="file.write", timestamp=now - 50),
            ToolCallRecord(tool_name="log.info", timestamp=now - 30),  # benign
            ToolCallRecord(tool_name="http.post", timestamp=now),
        ]
        matches = detector.check_sequence(history)
        assert any(m.signature_id == "TS-002" for m in matches)

    def test_empty_history(self) -> None:
        detector = ToolCombinationDetector()
        matches = detector.check_sequence([])
        assert matches == []

    def test_malware_sequence(self) -> None:
        """TS-004: file.write → shell.exec → file.delete."""
        detector = ToolCombinationDetector()
        now = time.time()
        history = [
            ToolCallRecord(tool_name="file.write", timestamp=now - 100),
            ToolCallRecord(tool_name="shell.exec", timestamp=now - 50),
            ToolCallRecord(tool_name="file.delete", timestamp=now),
        ]
        matches = detector.check_sequence(history)
        assert any(m.signature_id == "TS-004" for m in matches)

    def test_all_sequence_signatures_have_required_fields(self) -> None:
        detector = ToolCombinationDetector()
        for sig in detector.sequences:
            assert sig.signature_id
            assert len(sig.sequence) >= 2
            assert sig.window_seconds > 0
            assert 0.0 < sig.risk_boost <= 1.0
            assert sig.description


class TestToolCombinationResult:
    """Result aggregation tests."""

    def test_max_risk_boost_from_pairs(self) -> None:
        result = ToolCombinationResult(
            matched_pairs=[
                MatchedToolCombination("TC-001", "a", "b", 0.5, "test1"),
                MatchedToolCombination("TC-002", "c", "d", 0.9, "test2"),
            ],
            matched_sequences=[],
            max_risk_boost=0.9,
            detail="test",
        )
        assert result.max_risk_boost == 0.9

    def test_empty_result(self) -> None:
        result = ToolCombinationResult()
        assert result.max_risk_boost == 0.0
        assert result.matched_pairs == []
        assert result.matched_sequences == []


class TestLibraryCompleteness:
    """Verify the library meets minimum requirements."""

    def test_minimum_16_pairs(self) -> None:
        detector = ToolCombinationDetector()
        assert len(detector.pairs) >= 16, (
            f"Expected at least 16 suspicious pairs, got {len(detector.pairs)}"
        )

    def test_minimum_5_sequences(self) -> None:
        detector = ToolCombinationDetector()
        assert len(detector.sequences) >= 5, (
            f"Expected at least 5 suspicious sequences, got {len(detector.sequences)}"
        )

    def test_unique_pair_ids(self) -> None:
        detector = ToolCombinationDetector()
        ids = [sig.signature_id for sig in detector.pairs]
        assert len(ids) == len(set(ids)), "Duplicate pair signature IDs found"

    def test_unique_sequence_ids(self) -> None:
        detector = ToolCombinationDetector()
        ids = [sig.signature_id for sig in detector.sequences]
        assert len(ids) == len(set(ids)), "Duplicate sequence signature IDs found"

    def test_singleton_exists(self) -> None:
        assert tool_combination_detector is not None
        assert isinstance(tool_combination_detector, ToolCombinationDetector)

    def test_category_coverage(self) -> None:
        """Pairs should cover multiple attack categories."""
        detector = ToolCombinationDetector()
        categories = {sig.category for sig in detector.pairs}
        assert len(categories) >= 4, (
            f"Expected at least 4 categories, got {categories}"
        )
