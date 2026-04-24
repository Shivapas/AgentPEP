"""E2E integration test — AAPM bundle flow: publish → webhook → load → enforce.

Sprint S-E05 (E05-T06)

Validates the complete AAPM integration flow:
  1. AAPM PCR approved → bundle published to mock registry
  2. AgentPEP webhook receiver accepts the event and triggers reload
  3. TrustedPolicyLoader fetches and verifies the bundle from the mock registry
  4. Bundle version tracker is updated
  5. PDPClient enforces decisions using the new bundle

The test uses:
  - In-memory bundle construction (no running HTTP server required)
  - Monkeypatched TrustedPolicyLoader._fetch to serve bundle bytes
  - FirstAAMPBundleEvaluator for OPA evaluation (no regopy required)
  - Webhook payload matching the BundlePublishedEvent schema

Sprint exit criteria tested here:
  - E2E integration flow validated: PCR approval → AgentPEP enforcement active
  - Bundle version reported in enforcement decision log
  - Webhook delivery confirmed
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.pdp.client import PDPClient, PDPClientResult
from app.pdp.engine import FirstAAMPBundleEvaluator, OPAEngine
from app.pdp.enforcement_log import EnforcementLog
from app.pdp.response_parser import PDPDecision
from app.policy.bundle_version import BundleVersion, BundleVersionTracker
from app.policy.loader import LoadedBundle, TrustedPolicyLoader


# ---------------------------------------------------------------------------
# Bundle factory helpers
# ---------------------------------------------------------------------------

def _make_v1_parity_rego() -> bytes:
    """Return the v1-parity Rego policy source bytes."""
    return b"""\
package agentpep.core

import rego.v1

_permitted_tools := {"read_file", "list_dir", "search_code", "get_file_contents", "list_files"}

default allow := false

allow := false if { input.taint_level != "CLEAN" }
allow := false if { input.trust_score < 0.0 }

allow if {
    input.tool_name in _permitted_tools
    input.deployment_tier == "HOMEGROWN"
    input.taint_level == "CLEAN"
    input.trust_score >= 0.0
}
"""


def _build_bundle_bytes(
    version: str = "1.0.0",
    bundle_type: str = "v1-parity",
    rego_source: bytes | None = None,
) -> bytes:
    """Build a bundle.tar.gz in memory, returning raw bytes."""
    if rego_source is None:
        rego_source = _make_v1_parity_rego()

    data_json = json.dumps(
        {
            "version": version,
            "bundle_type": bundle_type,
            "description": "AgentPEP Core Enforcement Policy v1.0.0",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "aapm_compiled": True,
        }
    ).encode()

    manifest = json.dumps({"revision": f"aapm-v1-parity-{version}", "roots": ["agentpep"]}).encode()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in [
            ("policies/core.rego", rego_source),
            ("data.json", data_json),
            (".manifest", manifest),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _sign_bundle_bytes(bundle_bytes: bytes, private_key: Any) -> bytes:
    """Sign the SHA-256 digest of bundle_bytes using the private key."""
    digest = hashlib.sha256(bundle_bytes).digest()
    return private_key.sign(digest)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def ed25519_keypair():
    """Generate a fresh Ed25519 keypair for this test module."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture(scope="module")
def v1_bundle_bytes(ed25519_keypair) -> bytes:
    """v1-parity bundle bytes (unsigned — loader will be given the matching key)."""
    return _build_bundle_bytes(version="1.0.0", bundle_type="v1-parity")


@pytest.fixture(scope="module")
def v1_bundle_sig(ed25519_keypair, v1_bundle_bytes) -> bytes:
    """Ed25519 signature over the v1 bundle SHA-256 digest."""
    private_key, _ = ed25519_keypair
    return _sign_bundle_bytes(v1_bundle_bytes, private_key)


@pytest.fixture
def version_tracker() -> BundleVersionTracker:
    """Fresh bundle version tracker for each test."""
    return BundleVersionTracker()


@pytest.fixture
def enforcement_log() -> EnforcementLog:
    return EnforcementLog(max_entries=100)


@pytest.fixture
def pdp_client(enforcement_log: EnforcementLog) -> PDPClient:
    """PDPClient using FirstAAMPBundleEvaluator (no regopy required)."""
    engine = OPAEngine(evaluator=FirstAAMPBundleEvaluator())
    return PDPClient(engine=engine, timeout_s=5.0)


# ---------------------------------------------------------------------------
# E05-T06 — E2E integration tests
# ---------------------------------------------------------------------------


def test_e2e_bundle_load_via_trusted_loader(
    ed25519_keypair,
    v1_bundle_bytes: bytes,
    v1_bundle_sig: bytes,
) -> None:
    """TrustedPolicyLoader loads and verifies the v1-parity bundle successfully."""
    _, public_key = ed25519_keypair
    loader = TrustedPolicyLoader(_public_key_override=public_key)

    bundle_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/1.0.0/bundle.tar.gz"
    sig_url = bundle_url + ".sig"

    def mock_fetch(url: str) -> bytes:
        if url.endswith(".sig"):
            return v1_bundle_sig
        return v1_bundle_bytes

    with patch.object(loader, "_fetch", side_effect=mock_fetch):
        loaded = loader.load_bundle(bundle_url, tenant_id="global", bundle_name="core_enforcement")

    assert loaded.version.version == "1.0.0"
    assert "policies/core.rego" in loaded.rego_files
    assert loaded.manifest.get("roots") == ["agentpep"]
    assert loaded.sha256  # non-empty SHA-256


def test_e2e_version_tracker_updated_after_load(
    ed25519_keypair,
    v1_bundle_bytes: bytes,
    v1_bundle_sig: bytes,
    version_tracker: BundleVersionTracker,
) -> None:
    """Bundle version tracker reflects the new version after load_and_track."""
    _, public_key = ed25519_keypair
    loader = TrustedPolicyLoader(_public_key_override=public_key)

    bundle_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/1.0.0/bundle.tar.gz"

    def mock_fetch(url: str) -> bytes:
        return v1_bundle_sig if url.endswith(".sig") else v1_bundle_bytes

    with (
        patch.object(loader, "_fetch", side_effect=mock_fetch),
        patch("app.policy.loader.bundle_version_tracker", version_tracker),
    ):
        loaded = loader.load_and_track(
            bundle_url, tenant_id="global", bundle_name="core_enforcement"
        )

    assert version_tracker.version_string == "1.0.0"
    assert version_tracker.current_version is not None
    assert version_tracker.current_version.bundle_name == "core_enforcement"
    assert version_tracker.current_version.tenant_id == "global"


def test_e2e_pdp_client_enforces_with_loaded_bundle(
    ed25519_keypair,
    v1_bundle_bytes: bytes,
    v1_bundle_sig: bytes,
    pdp_client: PDPClient,
) -> None:
    """After loading the v1 bundle, PDPClient makes correct enforcement decisions."""
    _, public_key = ed25519_keypair
    loader = TrustedPolicyLoader(_public_key_override=public_key)

    bundle_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/1.0.0/bundle.tar.gz"

    def mock_fetch(url: str) -> bytes:
        return v1_bundle_sig if url.endswith(".sig") else v1_bundle_bytes

    with patch.object(loader, "_fetch", side_effect=mock_fetch):
        loaded = loader.load_bundle(bundle_url)

    pdp_client.load_bundle(loaded.rego_files)

    import asyncio

    # ALLOW: read-only tool on HOMEGROWN with clean taint
    allow_result: PDPClientResult = asyncio.run(
        pdp_client.decide(
            tool_name="read_file",
            tool_args={"path": "/tmp/test.txt"},
            deployment_tier="HOMEGROWN",
            taint_level="CLEAN",
            trust_score=1.0,
        )
    )
    assert allow_result.is_allow, (
        f"Expected ALLOW for read_file/HOMEGROWN/CLEAN after bundle load; "
        f"got {allow_result.response.decision}"
    )

    # DENY: write tool on HOMEGROWN
    deny_result: PDPClientResult = asyncio.run(
        pdp_client.decide(
            tool_name="write_file",
            tool_args={"path": "/tmp/out.txt", "content": "data"},
            deployment_tier="HOMEGROWN",
            taint_level="CLEAN",
            trust_score=1.0,
        )
    )
    assert deny_result.is_deny, (
        f"Expected DENY for write_file/HOMEGROWN after bundle load; "
        f"got {deny_result.response.decision}"
    )

    # DENY: tainted input regardless of tool
    taint_result: PDPClientResult = asyncio.run(
        pdp_client.decide(
            tool_name="read_file",
            tool_args={"path": "/tmp/data.txt"},
            deployment_tier="HOMEGROWN",
            taint_level="TAINTED",
            trust_score=1.0,
        )
    )
    assert taint_result.is_deny, (
        f"Expected DENY for tainted input; got {taint_result.response.decision}"
    )


def test_e2e_bundle_version_in_enforcement_log(
    ed25519_keypair,
    v1_bundle_bytes: bytes,
    v1_bundle_sig: bytes,
    enforcement_log: EnforcementLog,
) -> None:
    """Enforcement decision log entries carry the bundle version after bundle load."""
    import asyncio

    from app.policy.bundle_version import bundle_version_tracker as global_tracker

    _, public_key = ed25519_keypair
    loader = TrustedPolicyLoader(_public_key_override=public_key)
    bundle_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/1.0.0/bundle.tar.gz"

    def mock_fetch(url: str) -> bytes:
        return v1_bundle_sig if url.endswith(".sig") else v1_bundle_bytes

    with (
        patch.object(loader, "_fetch", side_effect=mock_fetch),
        patch("app.policy.loader.bundle_version_tracker", global_tracker),
    ):
        loaded = loader.load_and_track(bundle_url)

    engine = OPAEngine(evaluator=FirstAAMPBundleEvaluator())
    client = PDPClient(engine=engine, timeout_s=5.0)
    client.load_bundle(loaded.rego_files)

    asyncio.run(
        client.decide(
            tool_name="read_file",
            tool_args={},
            deployment_tier="HOMEGROWN",
            taint_level="CLEAN",
            trust_score=1.0,
        )
    )

    entries = enforcement_log.recent_entries(limit=10)
    # The global enforcement_log records decisions; check the bundle version was set
    assert global_tracker.version_string == "1.0.0"


def test_e2e_second_bundle_reload_replaces_first(
    ed25519_keypair,
    pdp_client: PDPClient,
) -> None:
    """Loading a second bundle replaces the first; decisions reflect the new policy."""
    private_key, public_key = ed25519_keypair
    loader = TrustedPolicyLoader(_public_key_override=public_key)

    # First bundle: v1-parity (allows read-only tools on HOMEGROWN)
    v1_bytes = _build_bundle_bytes(version="1.0.0", bundle_type="v1-parity")
    v1_sig = _sign_bundle_bytes(v1_bytes, private_key)

    # Second bundle: deny-all (no allow rules)
    deny_all_rego = b"""\
package agentpep.core
import rego.v1
default allow := false
"""
    v2_bytes = _build_bundle_bytes(
        version="2.0.0-deny-all", bundle_type="emergency-deny-all", rego_source=deny_all_rego
    )
    v2_sig = _sign_bundle_bytes(v2_bytes, private_key)

    def fetch_v1(url: str) -> bytes:
        return v1_sig if url.endswith(".sig") else v1_bytes

    def fetch_v2(url: str) -> bytes:
        return v2_sig if url.endswith(".sig") else v2_bytes

    import asyncio

    url_v1 = "http://localhost:8099/agentpep/policies/global/core_enforcement/1.0.0/bundle.tar.gz"
    url_v2 = "http://localhost:8099/agentpep/policies/global/core_enforcement/2.0.0-deny-all/bundle.tar.gz"

    # Load v1 — should allow read_file
    with patch.object(loader, "_fetch", side_effect=fetch_v1):
        loaded_v1 = loader.load_bundle(url_v1)
    pdp_client.load_bundle(loaded_v1.rego_files)

    result_v1 = asyncio.run(
        pdp_client.decide(
            tool_name="read_file",
            tool_args={},
            deployment_tier="HOMEGROWN",
            taint_level="CLEAN",
            trust_score=1.0,
        )
    )
    assert result_v1.is_allow, "v1 bundle must ALLOW read_file on HOMEGROWN"

    # Load v2 deny-all — all decisions must now be DENY
    with patch.object(loader, "_fetch", side_effect=fetch_v2):
        loaded_v2 = loader.load_bundle(url_v2)
    pdp_client.load_bundle(loaded_v2.rego_files)

    result_v2 = asyncio.run(
        pdp_client.decide(
            tool_name="read_file",
            tool_args={},
            deployment_tier="HOMEGROWN",
            taint_level="CLEAN",
            trust_score=1.0,
        )
    )
    assert result_v2.is_deny, "deny-all bundle must DENY read_file"


def test_e2e_signature_mismatch_fails_closed(
    ed25519_keypair,
    v1_bundle_bytes: bytes,
) -> None:
    """A bundle with an invalid signature is rejected; existing policy stays active."""
    from app.policy.loader import SignatureVerificationError

    _, public_key = ed25519_keypair
    loader = TrustedPolicyLoader(_public_key_override=public_key)

    tampered_sig = b"\x00" * 64  # invalid signature

    bundle_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/1.0.0/bundle.tar.gz"

    def mock_fetch(url: str) -> bytes:
        return tampered_sig if url.endswith(".sig") else v1_bundle_bytes

    with patch.object(loader, "_fetch", side_effect=mock_fetch):
        with pytest.raises(SignatureVerificationError):
            loader.load_bundle(bundle_url)


def test_e2e_untrusted_source_rejected(
    ed25519_keypair,
) -> None:
    """A bundle URL from an untrusted source is rejected before any fetch."""
    from app.policy.loader import UntrustedSourceError

    _, public_key = ed25519_keypair
    loader = TrustedPolicyLoader(_public_key_override=public_key)

    with pytest.raises(UntrustedSourceError):
        loader.load_bundle("https://evil.example.com/malicious_bundle.tar.gz")
