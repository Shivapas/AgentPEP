"""Unit tests for agentpep/policy/bundle_version.py.

Sprint S-E03 — E03-T08b
Covers:
  - BundleVersion dataclass fields and defaults
  - BundleVersionTracker.current returns the sentinel before any load
  - BundleVersionTracker.update() replaces the tracked version atomically
  - BundleVersionTracker.is_loaded returns False before first update
  - BundleVersionTracker.version_string returns the right string
  - BundleVersionTracker.reset() restores sentinel
  - Module-level singleton is shared
  - Thread safety: concurrent updates do not corrupt state
"""

from __future__ import annotations

import threading
import time

import pytest

from app.policy.bundle_version import BundleVersion, BundleVersionTracker, bundle_version_tracker


# ---------------------------------------------------------------------------
# BundleVersion dataclass
# ---------------------------------------------------------------------------


class TestBundleVersion:
    def test_defaults(self):
        bv = BundleVersion(version="1.0.0", bundle_name="core", tenant_id="global")
        assert bv.version == "1.0.0"
        assert bv.bundle_name == "core"
        assert bv.tenant_id == "global"
        assert bv.source_url == ""
        assert bv.etag == ""
        assert bv.loaded_at_ms > 0

    def test_as_dict_keys(self):
        bv = BundleVersion(version="2.3.1", bundle_name="taint", tenant_id="acme")
        d = bv.as_dict()
        for key in ("version", "bundle_name", "tenant_id", "loaded_at_ms", "source_url", "etag"):
            assert key in d, f"Missing key: {key}"

    def test_as_dict_values(self):
        bv = BundleVersion(
            version="3.0.0",
            bundle_name="posture",
            tenant_id="tenant-1",
            source_url="https://example.com/bundle.tar.gz",
            etag='"abc123"',
        )
        d = bv.as_dict()
        assert d["version"] == "3.0.0"
        assert d["source_url"] == "https://example.com/bundle.tar.gz"
        assert d["etag"] == '"abc123"'


# ---------------------------------------------------------------------------
# BundleVersionTracker
# ---------------------------------------------------------------------------


class TestBundleVersionTracker:
    def setup_method(self):
        """Fresh tracker for each test."""
        self.tracker = BundleVersionTracker()

    def test_initial_version_is_unloaded(self):
        assert self.tracker.current.version == "unloaded"

    def test_is_loaded_false_before_update(self):
        assert self.tracker.is_loaded is False

    def test_version_string_before_load(self):
        assert self.tracker.version_string == "unloaded"

    def test_update_replaces_version(self):
        bv = BundleVersion(version="1.2.3", bundle_name="core", tenant_id="global")
        self.tracker.update(bv)
        assert self.tracker.current.version == "1.2.3"
        assert self.tracker.is_loaded is True

    def test_version_string_after_update(self):
        bv = BundleVersion(version="5.0.0", bundle_name="b", tenant_id="t")
        self.tracker.update(bv)
        assert self.tracker.version_string == "5.0.0"

    def test_update_is_atomic(self):
        """Successive updates replace each other; no partial state visible."""
        bv1 = BundleVersion(version="1.0.0", bundle_name="b", tenant_id="t")
        bv2 = BundleVersion(version="2.0.0", bundle_name="b", tenant_id="t")
        self.tracker.update(bv1)
        self.tracker.update(bv2)
        assert self.tracker.current.version == "2.0.0"

    def test_reset_restores_sentinel(self):
        bv = BundleVersion(version="9.9.9", bundle_name="b", tenant_id="t")
        self.tracker.update(bv)
        self.tracker.reset()
        assert self.tracker.current.version == "unloaded"
        assert self.tracker.is_loaded is False

    def test_current_returns_snapshot(self):
        """current property returns a snapshot — modifying local ref doesn't affect tracker."""
        bv = BundleVersion(version="1.0.0", bundle_name="b", tenant_id="t")
        self.tracker.update(bv)
        snapshot = self.tracker.current
        # Update to a new version
        bv2 = BundleVersion(version="2.0.0", bundle_name="b", tenant_id="t")
        self.tracker.update(bv2)
        # Old snapshot is unchanged
        assert snapshot.version == "1.0.0"
        assert self.tracker.current.version == "2.0.0"


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestBundleVersionTrackerThreadSafety:
    def test_concurrent_updates_do_not_corrupt(self):
        """200 threads updating the tracker simultaneously; all reads are valid versions."""
        tracker = BundleVersionTracker()
        versions_seen: list[str] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def updater(i: int) -> None:
            try:
                bv = BundleVersion(version=f"{i}.0.0", bundle_name="b", tenant_id="t")
                tracker.update(bv)
                v = tracker.version_string
                with lock:
                    versions_seen.append(v)
            except Exception as exc:
                with lock:
                    errors.append(exc)

        threads = [threading.Thread(target=updater, args=(i,)) for i in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent update: {errors}"
        assert all(v.endswith(".0.0") for v in versions_seen)

    def test_concurrent_reads_always_return_valid_version(self):
        """Reader threads always see a complete BundleVersion (never partial)."""
        tracker = BundleVersionTracker()
        sentinel_or_real = {"ok": True}

        def reader() -> None:
            for _ in range(50):
                v = tracker.current
                if v.version not in ("unloaded",) and not v.version.endswith(".0.0"):
                    sentinel_or_real["ok"] = False

        def writer() -> None:
            for i in range(50):
                bv = BundleVersion(version=f"{i}.0.0", bundle_name="b", tenant_id="t")
                tracker.update(bv)

        threads = (
            [threading.Thread(target=reader) for _ in range(5)]
            + [threading.Thread(target=writer) for _ in range(3)]
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert sentinel_or_real["ok"]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------


class TestBundleVersionTrackerSingleton:
    def test_singleton_is_shared(self):
        """Importing bundle_version_tracker from different paths yields the same object."""
        from app.policy.bundle_version import bundle_version_tracker as t1
        from app.policy import bundle_version as bv_mod

        assert t1 is bv_mod.bundle_version_tracker

    def test_singleton_reset_between_tests(self):
        """Confirm reset() clears tracker for clean test isolation."""
        bundle_version_tracker.reset()
        assert bundle_version_tracker.version_string == "unloaded"
