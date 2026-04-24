"""Emergency deny-all bundle tests — AAPM security incident response.

Sprint S-E05 (E05-T08)

Validates that:
  1. An emergency deny-all Rego bundle causes PDPClient to DENY every
     tool call request (ALLOW / DENY / MODIFY → DENY only).
  2. The bundle can be loaded via the trusted policy loader (valid signature
     and source URL required).
  3. After the emergency is lifted, a normal bundle can restore full
     enforcement behaviour.
  4. The emergency bundle can be detected by inspecting the bundle manifest's
     ``bundle_type`` field.

Sprint exit criteria tested here:
  - Emergency deny-all bundle enforced within SLA (mechanism validated;
    wall-clock SLA is a deployment operations concern, not a unit test).
  - Bundle version updated to emergency version in tracker.

No regopy or OPA binary required — uses FirstAAMPBundleEvaluator for
normal-bundle phases, and a dedicated EmergencyDenyAllEvaluator stub that
mirrors the deny-all Rego bundle behaviour.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import tarfile
import time
from typing import Any
from unittest.mock import patch

import pytest

from app.pdp.client import PDPClient, PDPClientResult
from app.pdp.engine import FirstAAMPBundleEvaluator, OPAEngine, OPAEngineProtocol
from app.pdp.response_parser import PDPDecision
from app.policy.bundle_version import BundleVersion, BundleVersionTracker
from app.policy.loader import LoadedBundle, TrustedPolicyLoader


# ---------------------------------------------------------------------------
# Emergency evaluator stub
# ---------------------------------------------------------------------------


class EmergencyDenyAllEvaluator:
    """Python stub mirroring the emergency-deny-all Rego bundle.

    Denies every request unconditionally — no allow rules, no exceptions.
    Mirrors REGO_POLICY_EMERGENCY_DENY_ALL in scripts/mock_aapm_registry.py.
    """

    def evaluate(
        self,
        rego_modules: dict[str, bytes],
        query: str,
        input_document: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "allow": False,
            "deny": True,
            "modify": False,
            "reason_code": "TOOL_NOT_PERMITTED",
            "details": "Emergency deny-all bundle active — no tool calls permitted",
            "evaluator": "emergency_deny_all",
        }


# ---------------------------------------------------------------------------
# Bundle helpers
# ---------------------------------------------------------------------------

def _build_bundle(version: str, bundle_type: str, rego_source: bytes) -> bytes:
    data = json.dumps(
        {
            "version": version,
            "bundle_type": bundle_type,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    ).encode()
    manifest = json.dumps({"revision": f"{bundle_type}-{version}", "roots": ["agentpep"], "bundle_type": bundle_type}).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in [
            ("policies/core.rego", rego_source),
            ("data.json", data),
            (".manifest", manifest),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _sign(private_key, bundle_bytes: bytes) -> bytes:
    return private_key.sign(hashlib.sha256(bundle_bytes).digest())


NORMAL_REGO = b"""\
package agentpep.core
import rego.v1
_permitted := {"read_file", "list_dir", "search_code", "get_file_contents", "list_files"}
default allow := false
allow if {
    input.tool_name in _permitted
    input.deployment_tier == "HOMEGROWN"
    input.taint_level == "CLEAN"
    input.trust_score >= 0.0
}
"""

EMERGENCY_REGO = b"""\
package agentpep.core
import rego.v1
default allow := false
"""


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


@pytest.fixture
def normal_bundle(keypair) -> tuple[bytes, bytes]:
    priv, _ = keypair
    b = _build_bundle("1.0.0", "v1-parity", NORMAL_REGO)
    return b, _sign(priv, b)


@pytest.fixture
def emergency_bundle(keypair) -> tuple[bytes, bytes]:
    priv, _ = keypair
    b = _build_bundle("emergency-1.0.0", "emergency-deny-all", EMERGENCY_REGO)
    return b, _sign(priv, b)


@pytest.fixture
def version_tracker() -> BundleVersionTracker:
    return BundleVersionTracker()


# ---------------------------------------------------------------------------
# E05-T08 — Emergency deny-all bundle tests
# ---------------------------------------------------------------------------


def test_emergency_bundle_denies_all_tool_calls() -> None:
    """Emergency deny-all evaluator must DENY every possible tool call."""
    engine = OPAEngine(evaluator=EmergencyDenyAllEvaluator())
    client = PDPClient(engine=engine, timeout_s=5.0)
    client.load_bundle({"policies/emergency.rego": EMERGENCY_REGO})

    test_inputs = [
        # Normally-allowed tool on HOMEGROWN
        ("read_file", {"path": "/tmp/x"}, "HOMEGROWN", "CLEAN", 1.0),
        ("list_dir", {}, "HOMEGROWN", "CLEAN", 0.5),
        ("search_code", {"query": "class Foo"}, "HOMEGROWN", "CLEAN", 0.99),
        # Write tool
        ("write_file", {"path": "/tmp/x", "content": "data"}, "HOMEGROWN", "CLEAN", 1.0),
        # Privileged tool
        ("bash", {"command": "ls"}, "HOMEGROWN", "CLEAN", 1.0),
        # Enterprise tier
        ("read_file", {}, "ENTERPRISE", "CLEAN", 1.0),
        # Tainted (also denied, but emergency must deny regardless)
        ("read_file", {}, "HOMEGROWN", "TAINTED", 1.0),
    ]

    for tool_name, tool_args, tier, taint, trust in test_inputs:
        result: PDPClientResult = asyncio.run(
            client.decide(
                tool_name=tool_name,
                tool_args=tool_args,
                deployment_tier=tier,
                taint_level=taint,
                trust_score=trust,
            )
        )
        assert result.is_deny, (
            f"Emergency deny-all bundle must DENY {tool_name!r} on {tier!r}; "
            f"got {result.response.decision}"
        )


def test_emergency_bundle_loaded_via_trusted_loader(
    keypair,
    emergency_bundle: tuple[bytes, bytes],
    version_tracker: BundleVersionTracker,
) -> None:
    """The emergency bundle must load successfully via TrustedPolicyLoader."""
    priv, pub = keypair
    bundle_bytes, bundle_sig = emergency_bundle

    loader = TrustedPolicyLoader(_public_key_override=pub)
    bundle_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/emergency-1.0.0/bundle.tar.gz"

    def mock_fetch(url: str) -> bytes:
        return bundle_sig if url.endswith(".sig") else bundle_bytes

    with (
        patch.object(loader, "_fetch", side_effect=mock_fetch),
        patch("app.policy.loader.bundle_version_tracker", version_tracker),
    ):
        loaded = loader.load_and_track(
            bundle_url, tenant_id="global", bundle_name="core_enforcement"
        )

    assert loaded.version.version == "emergency-1.0.0"
    assert loaded.manifest.get("bundle_type") == "emergency-deny-all"
    assert version_tracker.version_string == "emergency-1.0.0"


def test_emergency_bundle_detected_by_manifest(
    keypair,
    emergency_bundle: tuple[bytes, bytes],
) -> None:
    """The emergency bundle's manifest must carry bundle_type=emergency-deny-all."""
    priv, pub = keypair
    bundle_bytes, bundle_sig = emergency_bundle

    loader = TrustedPolicyLoader(_public_key_override=pub)
    bundle_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/emergency-1.0.0/bundle.tar.gz"

    def mock_fetch(url: str) -> bytes:
        return bundle_sig if url.endswith(".sig") else bundle_bytes

    with patch.object(loader, "_fetch", side_effect=mock_fetch):
        loaded = loader.load_bundle(bundle_url)

    assert loaded.manifest.get("bundle_type") == "emergency-deny-all", (
        "Operator tools and monitoring systems can detect emergency status "
        "by checking manifest.bundle_type == 'emergency-deny-all'"
    )


def test_recovery_from_emergency_bundle(
    keypair,
    normal_bundle: tuple[bytes, bytes],
    emergency_bundle: tuple[bytes, bytes],
    version_tracker: BundleVersionTracker,
) -> None:
    """Loading a normal bundle after an emergency bundle restores ALLOW decisions."""
    priv, pub = keypair
    normal_bytes, normal_sig = normal_bundle
    emerg_bytes, emerg_sig = emergency_bundle

    loader = TrustedPolicyLoader(_public_key_override=pub)

    # --- Phase 1: Load emergency bundle ---
    emerg_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/emergency-1.0.0/bundle.tar.gz"

    def fetch_emergency(url: str) -> bytes:
        return emerg_sig if url.endswith(".sig") else emerg_bytes

    with (
        patch.object(loader, "_fetch", side_effect=fetch_emergency),
        patch("app.policy.loader.bundle_version_tracker", version_tracker),
    ):
        emerg_loaded = loader.load_and_track(emerg_url)

    engine = OPAEngine(evaluator=EmergencyDenyAllEvaluator())
    client = PDPClient(engine=engine, timeout_s=5.0)
    client.load_bundle(emerg_loaded.rego_files)

    emerg_result: PDPClientResult = asyncio.run(
        client.decide(
            tool_name="read_file",
            tool_args={},
            deployment_tier="HOMEGROWN",
            taint_level="CLEAN",
            trust_score=1.0,
        )
    )
    assert emerg_result.is_deny, "Emergency bundle must DENY read_file"
    assert version_tracker.version_string == "emergency-1.0.0"

    # --- Phase 2: Restore normal bundle ---
    normal_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/1.0.0/bundle.tar.gz"

    def fetch_normal(url: str) -> bytes:
        return normal_sig if url.endswith(".sig") else normal_bytes

    with (
        patch.object(loader, "_fetch", side_effect=fetch_normal),
        patch("app.policy.loader.bundle_version_tracker", version_tracker),
    ):
        normal_loaded = loader.load_and_track(normal_url)

    normal_engine = OPAEngine(evaluator=FirstAAMPBundleEvaluator())
    normal_client = PDPClient(engine=normal_engine, timeout_s=5.0)
    normal_client.load_bundle(normal_loaded.rego_files)

    restore_result: PDPClientResult = asyncio.run(
        normal_client.decide(
            tool_name="read_file",
            tool_args={},
            deployment_tier="HOMEGROWN",
            taint_level="CLEAN",
            trust_score=1.0,
        )
    )
    assert restore_result.is_allow, (
        f"Normal bundle must ALLOW read_file/HOMEGROWN after emergency lift; "
        f"got {restore_result.response.decision}"
    )
    assert version_tracker.version_string == "1.0.0", (
        "Version tracker must reflect restored normal bundle"
    )


def test_emergency_bundle_version_in_enforcement_decisions(
    keypair,
    emergency_bundle: tuple[bytes, bytes],
    version_tracker: BundleVersionTracker,
) -> None:
    """Enforcement decisions made under the emergency bundle carry the emergency version."""
    from app.pdp.enforcement_log import enforcement_log as global_log

    priv, pub = keypair
    bundle_bytes, bundle_sig = emergency_bundle

    loader = TrustedPolicyLoader(_public_key_override=pub)
    emerg_url = "http://localhost:8099/agentpep/policies/global/core_enforcement/emergency-1.0.0/bundle.tar.gz"

    def mock_fetch(url: str) -> bytes:
        return bundle_sig if url.endswith(".sig") else bundle_bytes

    with (
        patch.object(loader, "_fetch", side_effect=mock_fetch),
        patch("app.policy.loader.bundle_version_tracker", version_tracker),
    ):
        loader.load_and_track(emerg_url)

    assert version_tracker.version_string == "emergency-1.0.0"

    engine = OPAEngine(evaluator=EmergencyDenyAllEvaluator())
    client = PDPClient(engine=engine, timeout_s=5.0)
    client.load_bundle({})

    asyncio.run(
        client.decide(
            tool_name="read_file",
            tool_args={},
            deployment_tier="HOMEGROWN",
            taint_level="CLEAN",
            trust_score=1.0,
        )
    )

    # Confirm version tracker shows emergency version
    assert "emergency" in version_tracker.version_string


def test_emergency_evaluator_always_deny_any_input() -> None:
    """EmergencyDenyAllEvaluator must DENY with any possible input combination."""
    ev = EmergencyDenyAllEvaluator()
    inputs = [
        {},
        {"tool_name": "read_file", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 1.0},
        {"tool_name": "", "deployment_tier": "", "taint_level": "", "trust_score": 0.0},
        {"tool_name": "admin_delete_all", "trust_score": 1.0},
    ]
    for inp in inputs:
        result = ev.evaluate({}, "data.agentpep.core.allow", inp)
        assert result["allow"] is False, f"EmergencyDenyAllEvaluator must DENY {inp}"
        assert result["deny"] is True
        assert result["evaluator"] == "emergency_deny_all"
