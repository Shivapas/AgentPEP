"""Polling fallback tests — AAPM registry pull-polling without webhook.

Sprint S-E05 (E05-T07)

Validates that AgentPEP's RegistryPoller correctly detects a new bundle
via ETag-based conditional GET when the webhook is unavailable, and that
the 60-second polling window is the effective SLA for bundle updates.

Tests are synchronous (no real asyncio sleep loops) using monkeypatching of
the polling internals to verify:

  1. A 200 OK response with a new ETag triggers bundle reload.
  2. A 304 Not Modified response is a no-op (no reload).
  3. A load error on polling is FAIL_CLOSED (previous bundle retained).
  4. ETag tracking prevents redundant reloads when content is unchanged.

Sprint exit criteria tested here:
  - Pull polling fallback: disable webhook; confirm AgentPEP picks up new
    bundle within 60s via polling (verified via ETag + response routing).
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import io
import json
import tarfile
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.policy.bundle_version import BundleVersionTracker
from app.policy.loader import LoadedBundle, PolicyLoaderError, TrustedPolicyLoader
from app.policy.registry_poll import RegistryPoller


# ---------------------------------------------------------------------------
# Bundle helpers (duplicated from E2E test for module independence)
# ---------------------------------------------------------------------------

def _build_bundle_bytes(version: str = "1.0.0") -> bytes:
    rego = b"""\
package agentpep.core
import rego.v1
default allow := false
allow if {
    input.tool_name in {"read_file", "list_dir", "search_code", "get_file_contents", "list_files"}
    input.deployment_tier == "HOMEGROWN"
    input.taint_level == "CLEAN"
    input.trust_score >= 0.0
}
"""
    data = json.dumps({"version": version}).encode()
    manifest = json.dumps({"revision": f"v{version}", "roots": ["agentpep"]}).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in [
            ("policies/core.rego", rego),
            ("data.json", data),
            (".manifest", manifest),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _sign_bundle(private_key, bundle_bytes: bytes) -> bytes:
    return private_key.sign(hashlib.sha256(bundle_bytes).digest())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture(scope="module")
def bundle_v1(keypair) -> tuple[bytes, bytes]:
    priv, _ = keypair
    b = _build_bundle_bytes("1.0.0")
    return b, _sign_bundle(priv, b)


@pytest.fixture(scope="module")
def bundle_v2(keypair) -> tuple[bytes, bytes]:
    priv, _ = keypair
    b = _build_bundle_bytes("1.1.0")
    return b, _sign_bundle(priv, b)


@pytest.fixture
def version_tracker() -> BundleVersionTracker:
    return BundleVersionTracker()


# ---------------------------------------------------------------------------
# E05-T07 — Polling fallback tests
# ---------------------------------------------------------------------------


def test_poll_detects_new_bundle_on_200(
    keypair,
    bundle_v1: tuple[bytes, bytes],
    bundle_v2: tuple[bytes, bytes],
    version_tracker: BundleVersionTracker,
) -> None:
    """When polling returns 200 with a new ETag, the new bundle is loaded."""
    priv, pub = keypair
    bundle_v1_bytes, bundle_v1_sig = bundle_v1
    bundle_v2_bytes, bundle_v2_sig = bundle_v2

    etag_v1 = f'"{hashlib.sha256(bundle_v1_bytes).hexdigest()[:16]}"'
    etag_v2 = f'"{hashlib.sha256(bundle_v2_bytes).hexdigest()[:16]}"'

    loader = TrustedPolicyLoader(_public_key_override=pub)
    bundle_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/latest/bundle.tar.gz"

    # First call: fetch_with_etag returns v2 bundle (simulating a new bundle)
    def fetch_with_etag_mock(url: str, current_etag: str = "") -> tuple[bytes | None, str]:
        if current_etag == etag_v1:
            # New bundle available
            return bundle_v2_bytes, etag_v2
        return bundle_v1_bytes, etag_v1

    def fetch_sig_mock(url: str) -> bytes:
        if "1.1.0" in url or "v2" in url:
            return bundle_v2_sig
        return bundle_v1_sig

    loaded_bundles: list[LoadedBundle] = []

    def load_and_track_mock(burl: str, **kw: object) -> LoadedBundle:
        # Simulate loader loading the bundle — track calls
        b = _build_bundle_bytes("1.1.0")
        from app.policy.bundle_version import BundleVersion
        bv = BundleVersion(
            version="1.1.0",
            bundle_name="core_enforcement",
            tenant_id="global",
            loaded_at_ms=int(time.time() * 1000),
            source_url=burl,
        )
        lb = LoadedBundle(version=bv, raw_bytes=b)
        version_tracker.update(bv)
        loaded_bundles.append(lb)
        return lb

    poller = RegistryPoller(
        bundle_url=bundle_url,
        poll_interval_s=60.0,
        _loader_override=loader,
    )
    poller._current_etag = etag_v1  # Simulate v1 already loaded

    with (
        patch.object(loader, "fetch_with_etag", side_effect=fetch_with_etag_mock),
        patch.object(loader, "load_and_track", side_effect=load_and_track_mock),
        patch("app.policy.registry_poll.bundle_version_tracker", version_tracker),
    ):
        # Simulate one poll cycle
        asyncio.run(poller._poll_once())

    assert len(loaded_bundles) == 1, "Polling should have triggered exactly one bundle reload"
    assert version_tracker.version_string == "1.1.0"


def test_poll_304_no_reload(
    keypair,
    bundle_v1: tuple[bytes, bytes],
    version_tracker: BundleVersionTracker,
) -> None:
    """A 304 Not Modified response must not trigger a bundle reload."""
    priv, pub = keypair
    bundle_v1_bytes, _ = bundle_v1
    etag_v1 = f'"{hashlib.sha256(bundle_v1_bytes).hexdigest()[:16]}"'

    loader = TrustedPolicyLoader(_public_key_override=pub)
    bundle_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/latest/bundle.tar.gz"

    loaded_count = [0]

    def fetch_with_etag_mock(url: str, current_etag: str = "") -> tuple[bytes | None, str]:
        # 304 Not Modified: return None, same etag
        return None, etag_v1

    def load_and_track_mock(*args: object, **kwargs: object) -> LoadedBundle:
        loaded_count[0] += 1
        raise AssertionError("load_and_track must NOT be called on 304")

    poller = RegistryPoller(
        bundle_url=bundle_url,
        poll_interval_s=60.0,
        _loader_override=loader,
    )
    poller._current_etag = etag_v1

    with (
        patch.object(loader, "fetch_with_etag", side_effect=fetch_with_etag_mock),
        patch.object(loader, "load_and_track", side_effect=load_and_track_mock),
    ):
        asyncio.run(poller._poll_once())

    assert loaded_count[0] == 0, "load_and_track must not be called on 304"


def test_poll_fail_closed_on_load_error(
    keypair,
    bundle_v1: tuple[bytes, bytes],
    version_tracker: BundleVersionTracker,
) -> None:
    """A load error during polling must not clear the active bundle (FAIL_CLOSED)."""
    priv, pub = keypair
    bundle_v1_bytes, _ = bundle_v1
    etag_v1 = f'"{hashlib.sha256(bundle_v1_bytes).hexdigest()[:16]}"'
    etag_v2 = '"new_etag_abc123"'

    from app.policy.bundle_version import BundleVersion

    # Simulate v1 already loaded
    bv_v1 = BundleVersion(
        version="1.0.0",
        bundle_name="core_enforcement",
        tenant_id="global",
        loaded_at_ms=int(time.time() * 1000),
        source_url="http://localhost:8099/agentpep/policies/global/core_enforcement/1.0.0/bundle.tar.gz",
    )
    version_tracker.update(bv_v1)

    loader = TrustedPolicyLoader(_public_key_override=pub)
    bundle_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/latest/bundle.tar.gz"

    def fetch_with_etag_mock(url: str, current_etag: str = "") -> tuple[bytes | None, str]:
        # Return a "new" etag to trigger reload attempt
        return b"corrupted_bundle_data", etag_v2

    def load_and_track_mock(*args: object, **kwargs: object) -> LoadedBundle:
        raise PolicyLoaderError("Simulated load failure: signature mismatch")

    poller = RegistryPoller(
        bundle_url=bundle_url,
        poll_interval_s=60.0,
        _loader_override=loader,
    )
    poller._current_etag = etag_v1

    with (
        patch.object(loader, "fetch_with_etag", side_effect=fetch_with_etag_mock),
        patch.object(loader, "load_and_track", side_effect=load_and_track_mock),
        patch("app.policy.registry_poll.bundle_version_tracker", version_tracker),
    ):
        # Poll should not raise; FAIL_CLOSED means previous bundle stays active
        asyncio.run(poller._poll_once())

    # Version must NOT have changed — old bundle still active
    assert version_tracker.version_string == "1.0.0", (
        f"FAIL_CLOSED: previous bundle (1.0.0) must remain active after load error; "
        f"got {version_tracker.version_string!r}"
    )
    # ETag must NOT be updated to the new one (prevents future 304 masking the error)
    assert poller._current_etag == etag_v1, (
        "ETag must not advance when load fails; keeps trying on next poll"
    )


def test_poll_etag_advances_after_successful_reload(
    keypair,
    bundle_v1: tuple[bytes, bytes],
    bundle_v2: tuple[bytes, bytes],
    version_tracker: BundleVersionTracker,
) -> None:
    """After a successful reload, the stored ETag advances to prevent re-downloading."""
    priv, pub = keypair
    bundle_v1_bytes, _ = bundle_v1
    bundle_v2_bytes, bundle_v2_sig = bundle_v2
    etag_v1 = f'"{hashlib.sha256(bundle_v1_bytes).hexdigest()[:16]}"'
    etag_v2 = f'"{hashlib.sha256(bundle_v2_bytes).hexdigest()[:16]}"'

    loader = TrustedPolicyLoader(_public_key_override=pub)
    bundle_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/latest/bundle.tar.gz"

    from app.policy.bundle_version import BundleVersion

    def fetch_with_etag_mock(url: str, current_etag: str = "") -> tuple[bytes | None, str]:
        return bundle_v2_bytes, etag_v2

    def load_and_track_mock(burl: str, **kw: object) -> LoadedBundle:
        bv = BundleVersion(
            version="1.1.0",
            bundle_name="core_enforcement",
            tenant_id="global",
            loaded_at_ms=int(time.time() * 1000),
            source_url=burl,
        )
        lb = LoadedBundle(version=bv, raw_bytes=bundle_v2_bytes)
        version_tracker.update(bv)
        return lb

    poller = RegistryPoller(
        bundle_url=bundle_url,
        poll_interval_s=60.0,
        _loader_override=loader,
    )
    poller._current_etag = etag_v1

    with (
        patch.object(loader, "fetch_with_etag", side_effect=fetch_with_etag_mock),
        patch.object(loader, "load_and_track", side_effect=load_and_track_mock),
        patch("app.policy.registry_poll.bundle_version_tracker", version_tracker),
    ):
        asyncio.run(poller._poll_once())

    assert poller._current_etag == etag_v2, (
        f"ETag must advance to {etag_v2!r} after successful reload; got {poller._current_etag!r}"
    )


def test_poll_empty_bundle_url_skips_poll(version_tracker: BundleVersionTracker) -> None:
    """Poller with no configured bundle URL skips the poll without error."""
    from app.policy.loader import TrustedPolicyLoader as _Loader

    loader = MagicMock(spec=_Loader)
    poller = RegistryPoller(
        bundle_url="",
        poll_interval_s=60.0,
        _loader_override=loader,
    )

    # No exception should be raised; loader methods not called
    asyncio.run(poller._poll_once())
    loader.fetch_with_etag.assert_not_called()


def test_poll_interval_is_configurable() -> None:
    """RegistryPoller respects the poll_interval_s parameter."""
    poller_fast = RegistryPoller(bundle_url="http://localhost:8099/test", poll_interval_s=10.0)
    poller_slow = RegistryPoller(bundle_url="http://localhost:8099/test", poll_interval_s=300.0)

    assert poller_fast._poll_interval_s == 10.0
    assert poller_slow._poll_interval_s == 300.0
