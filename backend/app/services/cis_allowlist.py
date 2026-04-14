"""CISAllowlist — content allowlist for injection scanning bypass.

Sprint 52 — APEP-416: Maintains a set of pre-approved content hashes that
should always be considered safe, independent of TTL.  Unlike
:class:`CISTrustCache` (which auto-expires), allowlist entries are permanent
until explicitly removed.

Use cases:
  - Known-safe system prompts that would otherwise trigger injection patterns.
  - Pre-scanned template strings approved during CI.
  - Per-tenant allowlists for domain-specific content.

Security guards:
  - Entries are keyed by SHA-256 content hash (not raw content).
  - Maximum entry count is bounded to prevent memory exhaustion.
  - ``reason`` field provides audit trail for each allowlist addition.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime


# ---------------------------------------------------------------------------
# Allowlist entry
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    """A single allowlisted content hash."""

    content_hash: str
    reason: str
    added_by: str  # e.g. "system", "admin@tenant", "ci-pipeline"
    added_at: datetime
    tenant_id: str = ""  # empty = global


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------


class CISAllowlist:
    """Permanent content allowlist for injection scan bypass.

    Parameters
    ----------
    max_entries:
        Upper bound on allowlist size to prevent abuse (default 50 000).
    """

    def __init__(self, max_entries: int = 50_000) -> None:
        self._max_entries = max_entries
        self._entries: dict[str, AllowlistEntry] = {}
        self._lock = threading.Lock()

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def content_hash(text: str) -> str:
        """Return the SHA-256 hex digest of *text*."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    # -- Public API ---------------------------------------------------------

    def is_allowed(self, text: str, tenant_id: str = "") -> bool:
        """Return ``True`` if *text* is on the allowlist.

        Checks both global entries (tenant_id="") and tenant-specific entries.
        """
        h = self.content_hash(text)
        with self._lock:
            entry = self._entries.get(h)
            if entry is None:
                return False
            # Global entry matches all tenants; tenant-specific must match.
            if entry.tenant_id == "" or entry.tenant_id == tenant_id:
                return True
            return False

    def add(
        self,
        text: str,
        *,
        reason: str,
        added_by: str = "system",
        tenant_id: str = "",
    ) -> bool:
        """Add *text* to the allowlist.  Returns ``False`` if at capacity."""
        h = self.content_hash(text)
        entry = AllowlistEntry(
            content_hash=h,
            reason=reason,
            added_by=added_by,
            added_at=datetime.now(UTC),
            tenant_id=tenant_id,
        )
        with self._lock:
            if h not in self._entries and len(self._entries) >= self._max_entries:
                return False
            self._entries[h] = entry
            return True

    def remove(self, text: str) -> bool:
        """Remove *text* from the allowlist.  Returns ``True`` if it was present."""
        h = self.content_hash(text)
        with self._lock:
            if h in self._entries:
                del self._entries[h]
                return True
            return False

    def get_entry(self, text: str) -> AllowlistEntry | None:
        """Return the allowlist entry for *text*, or ``None``."""
        h = self.content_hash(text)
        with self._lock:
            return self._entries.get(h)

    def list_entries(self, tenant_id: str | None = None) -> list[AllowlistEntry]:
        """Return all entries, optionally filtered by *tenant_id*."""
        with self._lock:
            if tenant_id is None:
                return list(self._entries.values())
            return [e for e in self._entries.values() if e.tenant_id == tenant_id or e.tenant_id == ""]

    def clear(self, tenant_id: str | None = None) -> int:
        """Remove entries.  If *tenant_id* given, only remove that tenant's entries.

        Returns the number of entries removed.
        """
        with self._lock:
            if tenant_id is None:
                count = len(self._entries)
                self._entries.clear()
                return count
            to_remove = [h for h, e in self._entries.items() if e.tenant_id == tenant_id]
            for h in to_remove:
                del self._entries[h]
            return len(to_remove)

    # -- Metrics / introspection -------------------------------------------

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._entries)

    def __repr__(self) -> str:
        return f"<CISAllowlist entries={self.size} max={self._max_entries}>"


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

cis_allowlist = CISAllowlist()
