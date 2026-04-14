"""Hostname-level Blocking for Forward Proxy.

Sprint 47 — APEP-374: Implements hostname-level access control for the forward
proxy CONNECT tunnel handler.  Extends the existing domain_blocklist (Sprint 44)
with forward-proxy-specific features: regex patterns, per-hostname policies,
and wildcard matching.

APEP-374.b: Core logic — hostname-level blocking in forward proxy.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.models.forward_proxy import (
    ForwardProxyBlocklistEntry,
    ForwardProxyHostnamePolicy,
)
from app.models.network_scan import ScanFinding, ScanSeverity
from app.services.domain_blocklist import domain_blocklist

logger = logging.getLogger(__name__)


class ForwardProxyHostnameBlocker:
    """Hostname-level access control for the forward proxy.

    Combines:
      1. The existing DomainBlocklist (Sprint 44) for standard domain blocking.
      2. Additional regex-based patterns for forward-proxy-specific rules.
      3. Per-hostname policy overrides (connection limits, rate limits, etc).
      4. An explicit allowlist that bypasses blocklist checks.

    Thread-safe for reads after initialization.  The blocklist can be modified
    at runtime via ``add_block()`` and ``add_allow()`` methods.
    """

    def __init__(self) -> None:
        self._block_entries: list[ForwardProxyBlocklistEntry] = []
        self._allow_entries: list[ForwardProxyBlocklistEntry] = []
        self._compiled_block_patterns: list[tuple[re.Pattern[str], ForwardProxyBlocklistEntry]] = []
        self._compiled_allow_patterns: list[tuple[re.Pattern[str], ForwardProxyBlocklistEntry]] = []
        self._hostname_policies: dict[str, ForwardProxyHostnamePolicy] = {}

        # Additional blocked hostnames beyond the standard domain blocklist
        self._extra_blocked: set[str] = set()
        self._extra_allowed: set[str] = set()

        # Initialize with common proxy-abuse patterns
        self._init_default_blocks()

    def _init_default_blocks(self) -> None:
        """Add default blocking patterns for common proxy abuse."""
        default_blocks = [
            ForwardProxyBlocklistEntry(
                pattern=r".*\.onion$",
                is_regex=True,
                action="block",
                reason="Tor hidden service",
            ),
            ForwardProxyBlocklistEntry(
                pattern=r".*\.i2p$",
                is_regex=True,
                action="block",
                reason="I2P network",
            ),
            ForwardProxyBlocklistEntry(
                pattern="localhost",
                action="block",
                reason="Localhost access via proxy",
            ),
            ForwardProxyBlocklistEntry(
                pattern="127.0.0.1",
                action="block",
                reason="Loopback address via proxy",
            ),
            ForwardProxyBlocklistEntry(
                pattern="[::1]",
                action="block",
                reason="IPv6 loopback via proxy",
            ),
            ForwardProxyBlocklistEntry(
                pattern=r"^10\.\d+\.\d+\.\d+$",
                is_regex=True,
                action="block",
                reason="RFC 1918 private network",
            ),
            ForwardProxyBlocklistEntry(
                pattern=r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$",
                is_regex=True,
                action="block",
                reason="RFC 1918 private network",
            ),
            ForwardProxyBlocklistEntry(
                pattern=r"^192\.168\.\d+\.\d+$",
                is_regex=True,
                action="block",
                reason="RFC 1918 private network",
            ),
            ForwardProxyBlocklistEntry(
                pattern="169.254.169.254",
                action="block",
                reason="Cloud metadata endpoint",
            ),
            ForwardProxyBlocklistEntry(
                pattern="metadata.google.internal",
                action="block",
                reason="GCP metadata endpoint",
            ),
        ]
        for entry in default_blocks:
            self._add_compiled_entry(entry, is_block=True)
            self._block_entries.append(entry)

    def _add_compiled_entry(
        self, entry: ForwardProxyBlocklistEntry, *, is_block: bool
    ) -> None:
        """Compile and store a blocklist/allowlist entry."""
        if entry.is_regex:
            try:
                compiled = re.compile(entry.pattern, re.IGNORECASE)
            except re.error:
                logger.warning(
                    "Invalid regex pattern in blocklist: %s", entry.pattern
                )
                return
        else:
            # Exact match: escape special chars and anchor
            escaped = re.escape(entry.pattern)
            compiled = re.compile(f"^{escaped}$", re.IGNORECASE)

        target = self._compiled_block_patterns if is_block else self._compiled_allow_patterns
        target.append((compiled, entry))

    def is_blocked(self, hostname: str) -> tuple[bool, str]:
        """Check if a hostname is blocked for forward proxy access.

        Returns (is_blocked, reason).

        Resolution order:
          1. Explicit allowlist (overrides blocklist)
          2. Per-hostname policy (overrides blocklist)
          3. Regex/wildcard blocklist patterns
          4. DomainBlocklist (Sprint 44)
          5. Default: allow
        """
        h = hostname.lower().strip()

        # 1. Explicit allowlist
        if h in self._extra_allowed:
            return False, ""

        for pattern, entry in self._compiled_allow_patterns:
            if pattern.match(h):
                return False, ""

        # 2. Per-hostname policy
        policy = self._hostname_policies.get(h)
        if policy is not None:
            if not policy.allowed:
                return True, f"Hostname policy denies access: {h}"
            return False, ""

        # 3. Extra blocked set
        if h in self._extra_blocked:
            return True, f"Hostname is explicitly blocked: {h}"

        # 4. Regex/wildcard block patterns
        for pattern, entry in self._compiled_block_patterns:
            if pattern.match(h):
                return True, entry.reason or f"Matched block pattern: {entry.pattern}"

        # 5. Upstream domain blocklist (Sprint 44)
        blocked, reason = domain_blocklist.is_blocked(h)
        if blocked:
            return True, reason

        # 6. Default: allow
        return False, ""

    def add_block(self, entry: ForwardProxyBlocklistEntry) -> None:
        """Add a new blocking entry."""
        self._block_entries.append(entry)
        self._add_compiled_entry(entry, is_block=True)

    def add_allow(self, entry: ForwardProxyBlocklistEntry) -> None:
        """Add a new allowlist entry."""
        entry.action = "allow"
        self._allow_entries.append(entry)
        self._add_compiled_entry(entry, is_block=False)

    def add_hostname_policy(self, policy: ForwardProxyHostnamePolicy) -> None:
        """Add or update a per-hostname policy."""
        self._hostname_policies[policy.hostname.lower()] = policy

    def add_blocked_hostname(self, hostname: str) -> None:
        """Add a single hostname to the blocked set."""
        self._extra_blocked.add(hostname.lower().strip())

    def add_allowed_hostname(self, hostname: str) -> None:
        """Add a single hostname to the explicit allowlist."""
        self._extra_allowed.add(hostname.lower().strip())

    def scan(self, hostname: str) -> list[ScanFinding]:
        """Scan a hostname and return findings if blocked.

        Used as a layer compatible with the URL scanner pipeline.
        """
        blocked, reason = self.is_blocked(hostname)
        if not blocked:
            return []
        return [
            ScanFinding(
                rule_id="PROXY-BLOCK-001",
                scanner="ForwardProxyHostnameBlocker",
                severity=ScanSeverity.HIGH,
                description=reason,
                matched_text=hostname[:200],
                mitre_technique_id="T1090.001",
                metadata={"hostname": hostname},
            )
        ]

    async def load_from_db(self) -> int:
        """Load proxy-specific blocklist entries from MongoDB."""
        try:
            from app.db.mongodb import get_database

            db = get_database()
            collection = db["forward_proxy_blocklist"]
            count = 0
            async for doc in collection.find({"active": True}):
                entry = ForwardProxyBlocklistEntry(
                    pattern=doc.get("pattern", ""),
                    is_regex=doc.get("is_regex", False),
                    action=doc.get("action", "block"),
                    reason=doc.get("reason", ""),
                )
                if entry.action == "allow":
                    self.add_allow(entry)
                else:
                    self.add_block(entry)
                count += 1
            logger.info("forward_proxy_blocklist_loaded", count=count)
            return count
        except Exception:
            logger.exception("Failed to load forward proxy blocklist from DB")
            return 0

    @property
    def block_count(self) -> int:
        return len(self._block_entries)

    @property
    def allow_count(self) -> int:
        return len(self._allow_entries)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

hostname_blocker = ForwardProxyHostnameBlocker()
