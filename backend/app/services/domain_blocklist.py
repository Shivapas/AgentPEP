"""Domain blocklist lookup service.

Sprint 44 — APEP-350: Provides fast domain blocklist checking for the URL
scanner pipeline.  Supports exact-match, wildcard suffix matching, and MongoDB-
backed blocklist persistence.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from app.models.network_scan import ScanFinding, ScanSeverity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Built-in blocklist (commonly abused domains / categories)
# ---------------------------------------------------------------------------

_DEFAULT_BLOCKLIST: set[str] = {
    # Known malware / phishing aggregators
    "evil.com",
    "malware.example.com",
    # Pastebin-like services often used for exfiltration
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "ghostbin.co",
    # File-sharing services used for C2 or exfiltration
    "transfer.sh",
    "file.io",
    # URL shorteners (obfuscation)
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "v.gd",
    "ow.ly",
    "rebrand.ly",
    # Known DNS tunneling domains
    "dnslog.cn",
    "ceye.io",
    "burpcollaborator.net",
    "oastify.com",
    "interact.sh",
    "canarytokens.com",
    # Crypto mining pools
    "coinhive.com",
    "coin-hive.com",
    "cryptoloot.pro",
}

# Wildcard suffixes: any subdomain of these is blocked
_DEFAULT_WILDCARD_SUFFIXES: set[str] = {
    ".onion",
    ".i2p",
    ".bit",
}


# ---------------------------------------------------------------------------
# DomainBlocklist
# ---------------------------------------------------------------------------


class DomainBlocklist:
    """Fast domain blocklist with exact and suffix matching.

    Thread-safe for reads after initialisation.  The blocklist can be extended
    at runtime via ``add()`` and ``add_wildcard()``.
    """

    def __init__(
        self,
        blocklist: set[str] | None = None,
        wildcard_suffixes: set[str] | None = None,
    ) -> None:
        self._exact: set[str] = set(blocklist or _DEFAULT_BLOCKLIST)
        self._suffixes: set[str] = set(wildcard_suffixes or _DEFAULT_WILDCARD_SUFFIXES)

    def add(self, domain: str) -> None:
        """Add an exact domain to the blocklist."""
        self._exact.add(domain.lower().strip())

    def remove(self, domain: str) -> None:
        """Remove an exact domain from the blocklist."""
        self._exact.discard(domain.lower().strip())

    def add_wildcard(self, suffix: str) -> None:
        """Add a wildcard suffix (e.g. '.onion')."""
        s = suffix.lower().strip()
        if not s.startswith("."):
            s = "." + s
        self._suffixes.add(s)

    def is_blocked(self, domain: str) -> tuple[bool, str]:
        """Check if *domain* is blocklisted.

        Returns (is_blocked, reason).
        """
        d = domain.lower().strip()

        # Exact match
        if d in self._exact:
            return True, f"Domain is blocklisted: {d}"

        # Suffix / wildcard match
        for suffix in self._suffixes:
            if d.endswith(suffix):
                return True, f"Domain matches blocklist wildcard: {suffix}"

        # Check if any parent domain is blocked (e.g. sub.evil.com -> evil.com)
        parts = d.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self._exact:
                return True, f"Parent domain is blocklisted: {parent}"

        return False, ""

    def scan(self, domain: str) -> list[ScanFinding]:
        """Scan a domain and return findings if blocklisted.

        Used as a layer in the URL scanner pipeline.
        """
        blocked, reason = self.is_blocked(domain)
        if not blocked:
            return []
        return [
            ScanFinding(
                rule_id="BLOCKLIST-001",
                scanner="DomainBlocklist",
                severity=ScanSeverity.HIGH,
                description=reason,
                matched_text=domain[:200],
                mitre_technique_id="T1071.001",
                metadata={"domain": domain},
            )
        ]

    @property
    def size(self) -> int:
        """Number of exact entries in the blocklist."""
        return len(self._exact)

    async def load_from_db(self) -> int:
        """Load additional blocklist entries from MongoDB.

        Returns count of entries loaded.
        """
        try:
            from app.db.mongodb import get_database

            db = get_database()
            collection = db["domain_blocklist"]
            count = 0
            async for doc in collection.find({"active": True}):
                domain = doc.get("domain", "")
                if doc.get("wildcard", False):
                    self.add_wildcard(domain)
                else:
                    self.add(domain)
                count += 1
            logger.info("domain_blocklist_loaded", count=count)
            return count
        except Exception:
            logger.exception("Failed to load domain blocklist from DB")
            return 0


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

domain_blocklist = DomainBlocklist()
