"""Unit tests for Sprint 47 — Hostname-level Blocking (APEP-374).

Tests cover:
  - Default blocklist entries (proxy abuse patterns)
  - Exact hostname matching
  - Regex pattern matching
  - Allowlist override
  - Per-hostname policy
  - Integration with domain_blocklist (Sprint 44)
  - SSRF prevention (private IPs, metadata endpoints)
"""

import pytest

from app.models.forward_proxy import (
    ForwardProxyBlocklistEntry,
    ForwardProxyHostnamePolicy,
)
from app.services.hostname_blocker import ForwardProxyHostnameBlocker


class TestForwardProxyHostnameBlocker:
    """Tests for the hostname-level blocking service (APEP-374)."""

    def setup_method(self):
        self.blocker = ForwardProxyHostnameBlocker()

    # ------------------------------------------------------------------
    # Default blocks
    # ------------------------------------------------------------------

    def test_blocks_localhost(self):
        blocked, reason = self.blocker.is_blocked("localhost")
        assert blocked is True
        assert "Localhost" in reason

    def test_blocks_loopback_ipv4(self):
        blocked, reason = self.blocker.is_blocked("127.0.0.1")
        assert blocked is True

    def test_blocks_loopback_ipv6(self):
        blocked, reason = self.blocker.is_blocked("[::1]")
        assert blocked is True

    def test_blocks_cloud_metadata(self):
        blocked, reason = self.blocker.is_blocked("169.254.169.254")
        assert blocked is True
        assert "metadata" in reason.lower()

    def test_blocks_gcp_metadata(self):
        blocked, reason = self.blocker.is_blocked("metadata.google.internal")
        assert blocked is True

    def test_blocks_private_10x(self):
        blocked, reason = self.blocker.is_blocked("10.0.0.1")
        assert blocked is True
        assert "private" in reason.lower()

    def test_blocks_private_172x(self):
        blocked, reason = self.blocker.is_blocked("172.16.0.1")
        assert blocked is True

    def test_blocks_private_192x(self):
        blocked, reason = self.blocker.is_blocked("192.168.1.1")
        assert blocked is True

    def test_blocks_onion_domain(self):
        blocked, reason = self.blocker.is_blocked("hidden.onion")
        assert blocked is True

    def test_blocks_i2p_domain(self):
        blocked, reason = self.blocker.is_blocked("service.i2p")
        assert blocked is True

    # ------------------------------------------------------------------
    # Standard domain blocklist integration (Sprint 44)
    # ------------------------------------------------------------------

    def test_blocks_known_malware_domain(self):
        blocked, reason = self.blocker.is_blocked("evil.com")
        assert blocked is True

    def test_blocks_pastebin(self):
        blocked, reason = self.blocker.is_blocked("pastebin.com")
        assert blocked is True

    # ------------------------------------------------------------------
    # Allowed domains pass through
    # ------------------------------------------------------------------

    def test_allows_legitimate_domain(self):
        blocked, reason = self.blocker.is_blocked("api.github.com")
        assert blocked is False
        assert reason == ""

    def test_allows_public_ip(self):
        blocked, reason = self.blocker.is_blocked("8.8.8.8")
        assert blocked is False

    # ------------------------------------------------------------------
    # Custom block entries
    # ------------------------------------------------------------------

    def test_add_exact_block(self):
        entry = ForwardProxyBlocklistEntry(
            pattern="blocked.example.com",
            action="block",
            reason="Custom block",
        )
        self.blocker.add_block(entry)
        blocked, reason = self.blocker.is_blocked("blocked.example.com")
        assert blocked is True

    def test_add_regex_block(self):
        entry = ForwardProxyBlocklistEntry(
            pattern=r".*\.badtld$",
            is_regex=True,
            action="block",
            reason="Custom TLD block",
        )
        self.blocker.add_block(entry)

        blocked, _ = self.blocker.is_blocked("anything.badtld")
        assert blocked is True

        blocked, _ = self.blocker.is_blocked("safe.com")
        assert blocked is False

    # ------------------------------------------------------------------
    # Allowlist override
    # ------------------------------------------------------------------

    def test_allowlist_overrides_blocklist(self):
        # localhost is blocked by default
        blocked, _ = self.blocker.is_blocked("localhost")
        assert blocked is True

        # Add to allowlist
        self.blocker.add_allowed_hostname("localhost")
        blocked, _ = self.blocker.is_blocked("localhost")
        assert blocked is False

    def test_allow_entry_overrides_block(self):
        # Block a domain
        self.blocker.add_block(ForwardProxyBlocklistEntry(
            pattern="special.example.com", action="block"
        ))
        blocked, _ = self.blocker.is_blocked("special.example.com")
        assert blocked is True

        # Add allow entry for same domain
        self.blocker.add_allow(ForwardProxyBlocklistEntry(
            pattern="special.example.com", action="allow"
        ))
        blocked, _ = self.blocker.is_blocked("special.example.com")
        assert blocked is False

    # ------------------------------------------------------------------
    # Per-hostname policy
    # ------------------------------------------------------------------

    def test_hostname_policy_allows(self):
        policy = ForwardProxyHostnamePolicy(
            hostname="policy-allowed.example.com",
            allowed=True,
        )
        self.blocker.add_hostname_policy(policy)
        blocked, _ = self.blocker.is_blocked("policy-allowed.example.com")
        assert blocked is False

    def test_hostname_policy_denies(self):
        policy = ForwardProxyHostnamePolicy(
            hostname="policy-denied.example.com",
            allowed=False,
        )
        self.blocker.add_hostname_policy(policy)
        blocked, reason = self.blocker.is_blocked("policy-denied.example.com")
        assert blocked is True
        assert "policy" in reason.lower()

    # ------------------------------------------------------------------
    # Case insensitivity
    # ------------------------------------------------------------------

    def test_case_insensitive(self):
        blocked, _ = self.blocker.is_blocked("LOCALHOST")
        assert blocked is True

        blocked, _ = self.blocker.is_blocked("Evil.Com")
        assert blocked is True

    # ------------------------------------------------------------------
    # Scan method (pipeline integration)
    # ------------------------------------------------------------------

    def test_scan_blocked_returns_findings(self):
        findings = self.blocker.scan("localhost")
        assert len(findings) > 0
        assert findings[0].rule_id == "PROXY-BLOCK-001"
        assert findings[0].scanner == "ForwardProxyHostnameBlocker"

    def test_scan_allowed_returns_empty(self):
        findings = self.blocker.scan("api.github.com")
        assert len(findings) == 0

    # ------------------------------------------------------------------
    # Counts
    # ------------------------------------------------------------------

    def test_block_count(self):
        initial_count = self.blocker.block_count
        self.blocker.add_block(ForwardProxyBlocklistEntry(
            pattern="new-block.example.com", action="block"
        ))
        assert self.blocker.block_count == initial_count + 1

    def test_allow_count(self):
        initial_count = self.blocker.allow_count
        self.blocker.add_allow(ForwardProxyBlocklistEntry(
            pattern="new-allow.example.com", action="allow"
        ))
        assert self.blocker.allow_count == initial_count + 1
