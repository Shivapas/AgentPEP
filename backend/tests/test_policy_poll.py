"""Unit tests for agentpep/policy/registry_poll.py.

Sprint S-E03 — E03-T08c
Covers:
  - RegistryPoller starts and stops cleanly
  - _sync_poll returns None on 304 (no reload)
  - _sync_poll returns bundle metadata on 200 (reload triggered)
  - Polling updates bundle_version_tracker
  - Polling error does not crash the loop; error is recorded
  - Stats dict contains expected keys
  - Poll interval is configurable
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import tarfile
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.policy.bundle_version import bundle_version_tracker
from app.policy.loader import PolicyLoaderError, TrustedPolicyLoader
from app.policy.registry_poll import RegistryPoller, _DEFAULT_POLL_INTERVAL_S


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_keypair():
    pk = Ed25519PrivateKey.generate()
    return pk, pk.public_key()


def _build_bundle() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        rego = b"package test\ndefault allow = false"
        ti = tarfile.TarInfo(name="main.rego")
        ti.size = len(rego)
        tf.addfile(ti, io.BytesIO(rego))
    return buf.getvalue()


def _sign(pk, bundle_bytes: bytes) -> bytes:
    return pk.sign(hashlib.sha256(bundle_bytes).digest())


LOCAL_URL = "http://localhost:8099/agentpep/policies/global/core/1.0/bundle.tar.gz"


@pytest.fixture(autouse=True)
def reset_tracker():
    bundle_version_tracker.reset()
    yield
    bundle_version_tracker.reset()


# ---------------------------------------------------------------------------
# RegistryPoller initialisation
# ---------------------------------------------------------------------------


class TestRegistryPollerInit:
    def test_default_poll_interval(self):
        p = RegistryPoller()
        assert p._poll_interval_s == _DEFAULT_POLL_INTERVAL_S

    def test_custom_poll_interval(self):
        p = RegistryPoller(poll_interval_s=15.0)
        assert p._poll_interval_s == 15.0

    def test_not_running_initially(self):
        p = RegistryPoller()
        assert p._running is False

    def test_stats_keys(self):
        p = RegistryPoller()
        stats = p.stats
        for key in (
            "running",
            "poll_interval_s",
            "bundle_url",
            "poll_count",
            "reload_count",
            "last_poll_at",
            "last_error",
            "current_etag",
            "current_bundle_version",
        ):
            assert key in stats, f"Missing stats key: {key}"


# ---------------------------------------------------------------------------
# _sync_poll — 304 (no change)
# ---------------------------------------------------------------------------


class TestSyncPollNoChange:
    def test_304_returns_none(self):
        private_key, public_key = _generate_keypair()
        mock_loader = MagicMock(spec=TrustedPolicyLoader)
        mock_loader.fetch_with_etag.return_value = (None, '"etag-v1"')  # 304

        poller = RegistryPoller(
            bundle_url=LOCAL_URL,
            _loader_override=mock_loader,
        )
        poller._current_etag = '"etag-v1"'

        result = poller._sync_poll()
        assert result is None

    def test_poll_count_increments(self):
        mock_loader = MagicMock(spec=TrustedPolicyLoader)
        mock_loader.fetch_with_etag.return_value = (None, '"etag"')

        poller = RegistryPoller(bundle_url=LOCAL_URL, _loader_override=mock_loader)
        assert poller._poll_count == 0
        asyncio.get_event_loop().run_until_complete(poller._poll_once())
        assert poller._poll_count == 1


# ---------------------------------------------------------------------------
# _sync_poll — 200 (new bundle)
# ---------------------------------------------------------------------------


class TestSyncPollNewBundle:
    def test_new_bundle_triggers_reload(self):
        private_key, public_key = _generate_keypair()
        bundle_bytes = _build_bundle()
        sig_bytes = _sign(private_key, bundle_bytes)

        mock_loader = MagicMock(spec=TrustedPolicyLoader)

        # First call (bundle URL) → new body; second call (sig URL) → sig
        mock_loader.fetch_with_etag.side_effect = [
            (bundle_bytes, '"etag-v2"'),  # bundle 200
            (sig_bytes, '"etag-sig"'),    # sig 200
        ]
        from app.policy.bundle_version import BundleVersion
        loaded_bundle = MagicMock()
        loaded_bundle.version = BundleVersion(version="1.0", bundle_name="core", tenant_id="global")
        mock_loader.load_and_track.return_value = loaded_bundle

        poller = RegistryPoller(bundle_url=LOCAL_URL, _loader_override=mock_loader)
        result = poller._sync_poll()

        assert result is not None
        assert result["version"] == "1.0"
        mock_loader.load_and_track.assert_called_once()

    def test_reload_count_increments_on_new_bundle(self):
        private_key, public_key = _generate_keypair()
        bundle_bytes = _build_bundle()
        sig_bytes = _sign(private_key, bundle_bytes)

        mock_loader = MagicMock(spec=TrustedPolicyLoader)
        mock_loader.fetch_with_etag.side_effect = [
            (bundle_bytes, '"etag-v2"'),
            (sig_bytes, '"etag-sig"'),
        ]
        from app.policy.bundle_version import BundleVersion
        loaded_bundle = MagicMock()
        loaded_bundle.version = BundleVersion(version="1.0", bundle_name="core", tenant_id="global")
        mock_loader.load_and_track.return_value = loaded_bundle

        poller = RegistryPoller(bundle_url=LOCAL_URL, _loader_override=mock_loader)
        assert poller._reload_count == 0
        asyncio.get_event_loop().run_until_complete(poller._poll_once())
        assert poller._reload_count == 1


# ---------------------------------------------------------------------------
# Error handling — FAIL_CLOSED
# ---------------------------------------------------------------------------


class TestSyncPollErrorHandling:
    def test_loader_error_recorded_in_last_error(self):
        mock_loader = MagicMock(spec=TrustedPolicyLoader)
        mock_loader.fetch_with_etag.side_effect = [
            (b"corrupt", '"etag-v2"'),
            (b"sig", '"etag-sig"'),
        ]
        mock_loader.load_and_track.side_effect = PolicyLoaderError("signature verification failed")

        poller = RegistryPoller(bundle_url=LOCAL_URL, _loader_override=mock_loader)
        asyncio.get_event_loop().run_until_complete(poller._poll_once())

        assert "signature verification failed" in poller._last_error

    def test_network_error_recorded_and_loop_continues(self):
        """An HTTP error on poll should not kill the poller."""
        import httpx

        mock_loader = MagicMock(spec=TrustedPolicyLoader)
        mock_loader.fetch_with_etag.side_effect = httpx.ConnectError("refused")

        poller = RegistryPoller(bundle_url=LOCAL_URL, _loader_override=mock_loader)
        # Should not raise
        asyncio.get_event_loop().run_until_complete(poller._poll_once())
        assert poller._last_error != ""
        assert poller._reload_count == 0

    def test_sig_304_while_bundle_200_raises_policy_loader_error(self):
        """Inconsistent registry state: bundle 200 but sig 304 → error."""
        bundle_bytes = b"some bundle"

        mock_loader = MagicMock(spec=TrustedPolicyLoader)
        mock_loader.fetch_with_etag.side_effect = [
            (bundle_bytes, '"etag-v2"'),  # bundle 200
            (None, '"etag-sig"'),          # sig 304 (inconsistent)
        ]

        poller = RegistryPoller(bundle_url=LOCAL_URL, _loader_override=mock_loader)
        with pytest.raises(PolicyLoaderError, match="inconsistent"):
            poller._sync_poll()


# ---------------------------------------------------------------------------
# Lifecycle — start / stop
# ---------------------------------------------------------------------------


class TestRegistryPollerLifecycle:
    @pytest.mark.asyncio
    async def test_start_sets_running(self):
        mock_loader = MagicMock(spec=TrustedPolicyLoader)
        # Return 304 forever so the loop just idles
        mock_loader.fetch_with_etag.return_value = (None, '"etag"')

        poller = RegistryPoller(
            bundle_url=LOCAL_URL,
            poll_interval_s=3600.0,  # very long so it doesn't actually poll
            _loader_override=mock_loader,
        )
        await poller.start()
        assert poller._running is True
        await poller.stop()
        assert poller._running is False

    @pytest.mark.asyncio
    async def test_start_is_idempotent(self):
        mock_loader = MagicMock(spec=TrustedPolicyLoader)
        mock_loader.fetch_with_etag.return_value = (None, '"etag"')

        poller = RegistryPoller(
            bundle_url=LOCAL_URL,
            poll_interval_s=3600.0,
            _loader_override=mock_loader,
        )
        await poller.start()
        await poller.start()  # second start should be a no-op
        assert poller._task is not None
        await poller.stop()

    @pytest.mark.asyncio
    async def test_stop_cancels_task(self):
        mock_loader = MagicMock(spec=TrustedPolicyLoader)
        mock_loader.fetch_with_etag.return_value = (None, '"etag"')

        poller = RegistryPoller(
            bundle_url=LOCAL_URL,
            poll_interval_s=3600.0,
            _loader_override=mock_loader,
        )
        await poller.start()
        task = poller._task
        await poller.stop()
        assert task.cancelled() or task.done()


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestRegistryPollerStats:
    def test_stats_reflect_poll_and_reload_counts(self):
        mock_loader = MagicMock(spec=TrustedPolicyLoader)
        mock_loader.fetch_with_etag.return_value = (None, '"etag"')

        poller = RegistryPoller(bundle_url=LOCAL_URL, _loader_override=mock_loader)
        asyncio.get_event_loop().run_until_complete(poller._poll_once())
        asyncio.get_event_loop().run_until_complete(poller._poll_once())

        stats = poller.stats
        assert stats["poll_count"] == 2
        assert stats["reload_count"] == 0

    def test_stats_bundle_version_reflects_tracker(self):
        from app.policy.bundle_version import BundleVersion

        bv = BundleVersion(version="7.0.0", bundle_name="b", tenant_id="t")
        bundle_version_tracker.update(bv)

        poller = RegistryPoller()
        assert poller.stats["current_bundle_version"] == "7.0.0"
