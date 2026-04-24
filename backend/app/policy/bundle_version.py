"""Bundle version tracker — thread-safe in-memory state.

Tracks the currently loaded AAPM policy bundle version and its metadata.
The version is reported in every enforcement decision event so that audit
logs record which exact bundle was in force at evaluation time.

Sprint S-E03 (E03-T07)
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BundleVersion:
    """Metadata for the currently loaded policy bundle."""

    version: str
    bundle_name: str
    tenant_id: str
    loaded_at_ms: int = field(default_factory=lambda: int(time.time() * 1000))
    source_url: str = ""
    etag: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "bundle_name": self.bundle_name,
            "tenant_id": self.tenant_id,
            "loaded_at_ms": self.loaded_at_ms,
            "source_url": self.source_url,
            "etag": self.etag,
        }


_UNLOADED = BundleVersion(
    version="unloaded",
    bundle_name="",
    tenant_id="",
    loaded_at_ms=0,
    source_url="",
    etag="",
)


class BundleVersionTracker:
    """Thread-safe store for the active policy bundle version.

    Callers read ``current`` to include bundle version in enforcement events.
    The policy loader calls ``update()`` after each successful bundle load.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._current: BundleVersion = _UNLOADED

    @property
    def current(self) -> BundleVersion:
        """Return a snapshot of the current bundle version (thread-safe)."""
        with self._lock:
            return self._current

    @property
    def version_string(self) -> str:
        """Return just the version string, for use in log fields."""
        return self.current.version

    @property
    def is_loaded(self) -> bool:
        """True once a real bundle has been loaded (not the unloaded sentinel)."""
        return self.current.version != "unloaded"

    def update(self, bundle: BundleVersion) -> None:
        """Atomically replace the tracked version."""
        with self._lock:
            self._current = bundle

    def reset(self) -> None:
        """Reset to the unloaded sentinel (used in tests)."""
        with self._lock:
            self._current = _UNLOADED


# ---------------------------------------------------------------------------
# Module-level singleton — shared by loader, webhook, poll, and evaluator
# ---------------------------------------------------------------------------

bundle_version_tracker = BundleVersionTracker()
