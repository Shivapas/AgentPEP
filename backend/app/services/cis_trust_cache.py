"""CISTrustCache — content-hash trust cache for injection scanning.

Sprint 52 — APEP-415: A TTL-based cache keyed by the SHA-256 hash of input
content.  When content has been scanned and found clean, its hash is stored
so that subsequent identical content can skip the full signature scan.

Features:
  - SHA-256 content hashing for deduplication.
  - Configurable TTL (default 300 s) — cached trust expires automatically.
  - Bounded LRU eviction to cap memory usage.
  - Thread-safe via :class:`threading.Lock`.
  - ``invalidate()`` / ``clear()`` for manual cache management.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Cache entry
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _TrustEntry:
    """A cached trust decision for a content hash."""

    content_hash: str
    scanned_at: float  # monotonic timestamp
    categories_checked: int  # how many categories were active when scanned


# ---------------------------------------------------------------------------
# Trust cache
# ---------------------------------------------------------------------------


class CISTrustCache:
    """Content-hash trust cache with TTL and LRU eviction.

    Parameters
    ----------
    ttl_seconds:
        How long a cache entry is considered valid (default 300 s).
    max_size:
        Maximum number of entries before LRU eviction (default 10 000).
    """

    def __init__(
        self,
        ttl_seconds: float = 300.0,
        max_size: int = 10_000,
    ) -> None:
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._cache: OrderedDict[str, _TrustEntry] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    # -- Public API ---------------------------------------------------------

    @staticmethod
    def content_hash(text: str) -> str:
        """Return the SHA-256 hex digest of *text*."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def is_trusted(self, text: str) -> bool:
        """Return ``True`` if *text* was previously scanned clean and TTL is valid."""
        h = self.content_hash(text)
        with self._lock:
            entry = self._cache.get(h)
            if entry is None:
                self._misses += 1
                return False
            if (time.monotonic() - entry.scanned_at) > self._ttl:
                # Expired — remove and report miss.
                del self._cache[h]
                self._misses += 1
                return False
            # Move to end (most recently used).
            self._cache.move_to_end(h)
            self._hits += 1
            return True

    def mark_trusted(self, text: str, categories_checked: int = 0) -> None:
        """Record *text* as scanned clean."""
        h = self.content_hash(text)
        entry = _TrustEntry(
            content_hash=h,
            scanned_at=time.monotonic(),
            categories_checked=categories_checked,
        )
        with self._lock:
            self._cache[h] = entry
            self._cache.move_to_end(h)
            # Evict oldest if over capacity.
            while len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def invalidate(self, text: str) -> bool:
        """Remove *text* from the cache.  Returns ``True`` if it was present."""
        h = self.content_hash(text)
        with self._lock:
            if h in self._cache:
                del self._cache[h]
                return True
            return False

    def clear(self) -> None:
        """Remove all entries."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    # -- Metrics / introspection -------------------------------------------

    @property
    def size(self) -> int:
        """Current number of cached entries."""
        with self._lock:
            return len(self._cache)

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def misses(self) -> int:
        return self._misses

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def __repr__(self) -> str:
        return (
            f"<CISTrustCache size={self.size} ttl={self._ttl}s "
            f"hit_rate={self.hit_rate:.1%}>"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

cis_trust_cache = CISTrustCache()
