"""Unit tests for Sprint 44 per-domain rate limiting and data budget (APEP-354)."""

import pytest

from app.services.domain_rate_limiter import DomainRateLimiter


class TestDomainRateLimiter:
    """Tests for per-domain rate limiting and data budget enforcement."""

    def setup_method(self):
        self.limiter = DomainRateLimiter(
            default_request_limit=5,
            default_data_budget_bytes=1000,
            window_seconds=60,
        )

    def test_allows_first_request(self):
        state = self.limiter.check_and_record("example.com")
        assert not state.exceeded
        assert state.request_count == 1

    def test_counts_requests(self):
        for _ in range(3):
            self.limiter.check_and_record("example.com")
        state = self.limiter.check_and_record("example.com")
        assert state.request_count == 4
        assert not state.exceeded

    def test_blocks_after_limit(self):
        for _ in range(5):
            self.limiter.check_and_record("example.com")
        state = self.limiter.check_and_record("example.com")
        assert state.exceeded
        assert "rate limit exceeded" in state.reason.lower()

    def test_separate_domains(self):
        for _ in range(5):
            self.limiter.check_and_record("a.com")
        state = self.limiter.check_and_record("b.com")
        assert not state.exceeded

    def test_data_budget_enforcement(self):
        state = self.limiter.check_and_record("example.com", data_bytes=1001)
        assert state.exceeded
        assert "budget exceeded" in state.reason.lower()

    def test_data_budget_accumulates(self):
        self.limiter.check_and_record("example.com", data_bytes=500)
        state = self.limiter.check_and_record("example.com", data_bytes=501)
        assert state.exceeded

    def test_custom_domain_limits(self):
        self.limiter.set_domain_limits("special.com", request_limit=2)
        self.limiter.check_and_record("special.com")
        self.limiter.check_and_record("special.com")
        state = self.limiter.check_and_record("special.com")
        assert state.exceeded

    def test_reset_domain(self):
        for _ in range(5):
            self.limiter.check_and_record("example.com")
        self.limiter.reset("example.com")
        state = self.limiter.check_and_record("example.com")
        assert not state.exceeded
        assert state.request_count == 1

    def test_reset_all(self):
        self.limiter.check_and_record("a.com")
        self.limiter.check_and_record("b.com")
        self.limiter.reset()
        state = self.limiter.check_and_record("a.com")
        assert state.request_count == 1

    def test_get_state(self):
        self.limiter.check_and_record("example.com")
        state = self.limiter.get_state("example.com")
        assert state.request_count == 1
        assert state.domain == "example.com"

    def test_get_state_unknown_domain(self):
        state = self.limiter.get_state("unknown.com")
        assert state.request_count == 0

    def test_scan_returns_findings(self):
        for _ in range(5):
            self.limiter.check_and_record("example.com")
        findings = self.limiter.scan("example.com")
        assert len(findings) == 1
        assert findings[0].rule_id == "RATELIMIT-001"

    def test_scan_no_findings(self):
        findings = self.limiter.scan("example.com")
        assert len(findings) == 0

    def test_case_insensitive(self):
        self.limiter.check_and_record("Example.COM")
        state = self.limiter.get_state("example.com")
        assert state.request_count == 1
