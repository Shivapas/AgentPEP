"""Unit tests for Sprint 44 Domain Blocklist (APEP-350)."""

import pytest

from app.services.domain_blocklist import DomainBlocklist


class TestDomainBlocklist:
    """Tests for domain blocklist lookup service."""

    def setup_method(self):
        self.blocklist = DomainBlocklist()

    def test_blocks_known_malware_domain(self):
        blocked, reason = self.blocklist.is_blocked("evil.com")
        assert blocked
        assert "blocklisted" in reason

    def test_blocks_pastebin(self):
        blocked, _ = self.blocklist.is_blocked("pastebin.com")
        assert blocked

    def test_blocks_url_shortener(self):
        blocked, _ = self.blocklist.is_blocked("bit.ly")
        assert blocked

    def test_blocks_dns_tunneling_domain(self):
        blocked, _ = self.blocklist.is_blocked("burpcollaborator.net")
        assert blocked

    def test_blocks_onion_suffix(self):
        blocked, reason = self.blocklist.is_blocked("hidden.onion")
        assert blocked
        assert "wildcard" in reason

    def test_blocks_i2p_suffix(self):
        blocked, _ = self.blocklist.is_blocked("darksite.i2p")
        assert blocked

    def test_allows_legitimate_domain(self):
        blocked, _ = self.blocklist.is_blocked("google.com")
        assert not blocked

    def test_allows_empty_string(self):
        blocked, _ = self.blocklist.is_blocked("")
        assert not blocked

    def test_blocks_subdomain_of_blocklisted(self):
        blocked, reason = self.blocklist.is_blocked("sub.evil.com")
        assert blocked
        assert "Parent domain" in reason

    def test_add_custom_domain(self):
        self.blocklist.add("custom-bad.com")
        blocked, _ = self.blocklist.is_blocked("custom-bad.com")
        assert blocked

    def test_remove_domain(self):
        self.blocklist.add("to-remove.com")
        self.blocklist.remove("to-remove.com")
        blocked, _ = self.blocklist.is_blocked("to-remove.com")
        assert not blocked

    def test_add_wildcard(self):
        self.blocklist.add_wildcard(".badzone")
        blocked, _ = self.blocklist.is_blocked("anything.badzone")
        assert blocked

    def test_case_insensitive(self):
        blocked, _ = self.blocklist.is_blocked("EVIL.COM")
        assert blocked

    def test_scan_returns_finding(self):
        findings = self.blocklist.scan("evil.com")
        assert len(findings) == 1
        assert findings[0].rule_id == "BLOCKLIST-001"

    def test_scan_clean_domain(self):
        findings = self.blocklist.scan("google.com")
        assert len(findings) == 0

    def test_size_property(self):
        bl = DomainBlocklist(blocklist={"a.com", "b.com"}, wildcard_suffixes=set())
        assert bl.size == 2

    def test_empty_blocklist(self):
        bl = DomainBlocklist(blocklist=set(), wildcard_suffixes=set())
        blocked, _ = bl.is_blocked("anything.com")
        assert not blocked
