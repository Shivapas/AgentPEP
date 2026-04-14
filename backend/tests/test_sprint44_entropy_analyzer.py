"""Unit tests for Sprint 44 EntropyAnalyzer (APEP-352)."""

import pytest

from app.services.entropy_analyzer import EntropyAnalyzer, shannon_entropy


class TestShannonEntropy:
    """Tests for the Shannon entropy calculation."""

    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars(self):
        ent = shannon_entropy("ab")
        assert abs(ent - 1.0) < 0.001

    def test_high_entropy_random(self):
        # Simulated random hex string
        text = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        ent = shannon_entropy(text)
        assert ent > 3.5

    def test_low_entropy_repetitive(self):
        text = "aaaaaabbbbbb"
        ent = shannon_entropy(text)
        assert ent < 2.0

    def test_english_text_moderate_entropy(self):
        text = "The quick brown fox jumps over the lazy dog"
        ent = shannon_entropy(text)
        assert 3.0 < ent < 5.0


class TestEntropyAnalyzer:
    """Tests for the EntropyAnalyzer service."""

    def setup_method(self):
        self.analyzer = EntropyAnalyzer(threshold=4.0, high_threshold=5.0)

    def test_analyse_token_below_threshold(self):
        result = self.analyzer.analyse_token("aaaaaabbbbbb1234")
        assert not result.is_suspicious

    def test_analyse_token_above_threshold(self):
        # High entropy token (simulated API key)
        token = "aK3bL5cM7dN9eP1fQ3gR5hS7tU9vW1x"
        result = self.analyzer.analyse_token(token)
        assert result.is_suspicious
        assert result.entropy > 4.0

    def test_analyse_text_finds_suspicious_tokens(self):
        text = "normal text here key=aK3bL5cM7dN9eP1fQ3gR5hS7tU9vW1x more text"
        results = self.analyzer.analyse_text(text)
        assert len(results) > 0

    def test_analyse_text_skips_short_tokens(self):
        text = "short abc123"
        results = self.analyzer.analyse_text(text)
        assert len(results) == 0

    def test_scan_returns_findings(self):
        text = "token=aK3bL5cM7dN9eP1fQ3gR5hS7tU9vW1x"
        findings = self.analyzer.scan(text)
        for f in findings:
            assert f.scanner == "EntropyAnalyzer"
            assert f.rule_id == "ENTROPY-001"

    def test_scan_empty_text(self):
        findings = self.analyzer.scan("")
        assert findings == []

    def test_scan_no_suspicious_tokens(self):
        findings = self.analyzer.scan("hello world this is normal text")
        assert findings == []
