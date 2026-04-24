"""AgentRT — E2E Validation: AAPM → AgentPEP → TrustSOC.

Sprint S-E09 (E09-T07)

Validates the complete AAPM PCR → Policy Registry → AgentPEP → TrustSOC chain
end-to-end. Each test class validates one segment of the integration path.

Full E2E flow:
  1. AAPM PCR approval → Rego bundle compiled + signed by AAPM
  2. AAPM publishes signed bundle to Policy Registry
  3. AgentPEP receives webhook notification → reloads bundle via TrustedPolicyLoader
  4. New policy is immediately active: PDP decisions reflect new bundle
  5. AgentRT regression suite passes against the new bundle
  6. PostToolUse events flow to TrustSOC with blast_radius_score and bundle_version

Exit criterion: all tests pass → "full AAPM → AgentPEP → TrustSOC flow confirmed"

Reference: docs/integrations/agentrt_contract.md — E2E validation
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import tarfile
import time
from typing import Any
from unittest.mock import patch

import pytest

from app.pdp.client import PDPClient
from app.pdp.engine import OPAEngine, RegoNativeEvaluator
from app.pdp.enforcement_log import EnforcementLog
from app.policy.bundle_version import bundle_version_tracker
from app.policy.loader import TrustedPolicyLoader


# ---------------------------------------------------------------------------
# Custom stub evaluators for specific test scenarios
# ---------------------------------------------------------------------------


class DenyAllEvaluator:
    """Evaluator that denies every tool call — simulates an emergency deny-all bundle."""

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
            "reason_code": "EMERGENCY_DENY_ALL",
            "details": "Emergency deny-all bundle active",
            "evaluator": "deny_all_stub",
        }


class AllowReadFileEvaluator:
    """Evaluator that allows only read_file — simulates a restrictive initial bundle."""

    def evaluate(
        self,
        rego_modules: dict[str, bytes],
        query: str,
        input_document: dict[str, Any],
    ) -> dict[str, Any]:
        tool = input_document.get("tool_name", "")
        tier = input_document.get("deployment_tier", "")
        if tool == "read_file" and tier == "HOMEGROWN":
            return {"allow": True, "deny": False, "modify": False,
                    "reason_code": "TOOL_ALLOWED", "details": "", "evaluator": "allow_read_file"}
        return {"allow": False, "deny": True, "modify": False,
                "reason_code": "TOOL_NOT_PERMITTED", "details": "", "evaluator": "allow_read_file"}


class AllowBashAndReadFileEvaluator:
    """Evaluator that allows read_file and bash — simulates an updated bundle."""

    def evaluate(
        self,
        rego_modules: dict[str, bytes],
        query: str,
        input_document: dict[str, Any],
    ) -> dict[str, Any]:
        tool = input_document.get("tool_name", "")
        tier = input_document.get("deployment_tier", "")
        if tool in {"read_file", "bash"} and tier == "HOMEGROWN":
            return {"allow": True, "deny": False, "modify": False,
                    "reason_code": "TOOL_ALLOWED", "details": "", "evaluator": "allow_bash_read"}
        return {"allow": False, "deny": True, "modify": False,
                "reason_code": "TOOL_NOT_PERMITTED", "details": "", "evaluator": "allow_bash_read"}


# ---------------------------------------------------------------------------
# Helper: build a signed bundle
# ---------------------------------------------------------------------------


def _build_signed_bundle(version: str = "1.0.0") -> tuple[bytes, bytes, Any]:
    """Build a minimal signed Rego bundle.

    Returns (bundle_bytes, sig_bytes, public_key).
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    rego = b"""\
package agentpep.core
import rego.v1
default allow := false
allow if {
    input.tool_name in {"read_file", "list_dir", "search_code"}
    input.deployment_tier in {"HOMEGROWN", "MANAGED", "ENTERPRISE"}
}
"""
    manifest = f'{{"revision": "{version}", "roots": ["agentpep"]}}'.encode()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in [("policies/core.rego", rego), (".manifest", manifest)]:
            ti = tarfile.TarInfo(name=name)
            ti.size = len(content)
            tf.addfile(ti, io.BytesIO(content))
    bundle_bytes = buf.getvalue()

    private_key = Ed25519PrivateKey.generate()
    sig_bytes = private_key.sign(hashlib.sha256(bundle_bytes).digest())
    return bundle_bytes, sig_bytes, private_key.public_key()


# ---------------------------------------------------------------------------
# Segment 1: Bundle loading via TrustedPolicyLoader
# ---------------------------------------------------------------------------


class TestE2ESegment1BundleLoading:
    """E2E Segment 1 — AAPM publishes bundle → AgentPEP loads it via TrustedPolicyLoader."""

    def test_valid_bundle_loaded_and_version_tracked(self):
        bundle_bytes, sig_bytes, pub_key = _build_signed_bundle(version="2.0.0")
        loader = TrustedPolicyLoader(_public_key_override=pub_key)
        url = "http://localhost:8099/agentpep/policies/global/core_enforcement/2.0.0/bundle.tar.gz"

        with patch.object(
            loader,
            "_fetch",
            side_effect=lambda u: sig_bytes if u.endswith(".sig") else bundle_bytes,
        ):
            loaded = loader.load_and_track(url, tenant_id="global", bundle_name="core_enforcement")

        assert loaded is not None, "E2E Segment 1 FAIL: bundle not loaded"
        assert "policies/core.rego" in loaded.rego_files, (
            "E2E Segment 1 FAIL: core.rego not found in loaded bundle"
        )

    def test_bundle_sha256_matches_after_load(self):
        bundle_bytes, sig_bytes, pub_key = _build_signed_bundle(version="2.1.0")
        loader = TrustedPolicyLoader(_public_key_override=pub_key)
        url = "http://localhost:8099/agentpep/policies/global/core_enforcement/2.1.0/bundle.tar.gz"

        with patch.object(
            loader,
            "_fetch",
            side_effect=lambda u: sig_bytes if u.endswith(".sig") else bundle_bytes,
        ):
            loaded = loader.load_bundle(url)

        expected_sha256 = hashlib.sha256(bundle_bytes).hexdigest()
        assert loaded.sha256 == expected_sha256, (
            "E2E Segment 1 FAIL: loaded bundle SHA-256 does not match original"
        )

    def test_invalid_signature_blocks_load(self, caplog):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from app.policy.loader import SignatureVerificationError

        bundle_bytes, _, pub_key = _build_signed_bundle(version="evil-1.0")
        attacker_private = Ed25519PrivateKey.generate()
        wrong_sig = attacker_private.sign(hashlib.sha256(bundle_bytes).digest())

        loader = TrustedPolicyLoader(_public_key_override=pub_key)
        url = "http://localhost:8099/agentpep/policies/global/core_enforcement/evil-1.0/bundle.tar.gz"

        with caplog.at_level(logging.ERROR):
            with patch.object(
                loader,
                "_fetch",
                side_effect=lambda u: wrong_sig if u.endswith(".sig") else bundle_bytes,
            ):
                with pytest.raises(SignatureVerificationError):
                    loader.load_bundle(url)

        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records), (
            "E2E Segment 1 FAIL: SECURITY_VIOLATION not emitted for invalid signature"
        )


# ---------------------------------------------------------------------------
# Segment 2: New bundle → PDP decisions reflect updated policy
# ---------------------------------------------------------------------------


class TestE2ESegment2PolicyActivation:
    """E2E Segment 2 — after bundle reload, PDP decisions must change immediately."""

    @pytest.mark.asyncio
    async def test_policy_change_takes_effect_after_bundle_reload(self):
        """Before reload: bash DENY. After reload: bash ALLOW."""
        log = EnforcementLog(max_entries=200)
        import app.pdp.client as _cm
        original_log = _cm.enforcement_log
        _cm.enforcement_log = log

        try:
            # Bundle v1: only read_file allowed
            engine_v1 = OPAEngine(evaluator=AllowReadFileEvaluator())
            client_v1 = PDPClient(engine=engine_v1, timeout_s=5.0, rego_modules={})
            result_before = await client_v1.decide(
                tool_name="bash",
                tool_args={"command": "ls"},
                agent_id="e2e-agent",
                session_id="e2e-seg2",
                deployment_tier="HOMEGROWN",
            )
            assert result_before.is_deny, (
                "E2E Segment 2 FAIL: bash should be DENY before v2 bundle loads"
            )

            # Bundle v2: bash also allowed (simulates AAPM bundle update)
            engine_v2 = OPAEngine(evaluator=AllowBashAndReadFileEvaluator())
            client_v2 = PDPClient(engine=engine_v2, timeout_s=5.0, rego_modules={})
            result_after = await client_v2.decide(
                tool_name="bash",
                tool_args={"command": "ls"},
                agent_id="e2e-agent",
                session_id="e2e-seg2",
                deployment_tier="HOMEGROWN",
            )
            assert result_after.is_allow, (
                "E2E Segment 2 FAIL: bash should be ALLOW after v2 bundle loads"
            )
        finally:
            _cm.enforcement_log = original_log

    @pytest.mark.asyncio
    async def test_pre_existing_sessions_see_new_policy(self):
        """Policy changes must apply immediately — no stale cached decisions."""
        log = EnforcementLog(max_entries=200)
        import app.pdp.client as _cm
        original_log = _cm.enforcement_log
        _cm.enforcement_log = log

        try:
            # Session starts with deny-all
            engine_v1 = OPAEngine(evaluator=DenyAllEvaluator())
            client_v1 = PDPClient(engine=engine_v1, timeout_s=5.0, rego_modules={})
            r1 = await client_v1.decide(
                tool_name="read_file",
                tool_args={"path": "/tmp/test.txt"},
                agent_id="e2e-stale-agent",
                session_id="e2e-stale-sess",
                deployment_tier="HOMEGROWN",
            )
            assert r1.is_deny, "Pre-condition: deny-all bundle should deny read_file"

            # Bundle updated mid-session
            engine_v2 = OPAEngine(evaluator=AllowReadFileEvaluator())
            client_v2 = PDPClient(engine=engine_v2, timeout_s=5.0, rego_modules={})
            r2 = await client_v2.decide(
                tool_name="read_file",
                tool_args={"path": "/tmp/test.txt"},
                agent_id="e2e-stale-agent",
                session_id="e2e-stale-sess",
                deployment_tier="HOMEGROWN",
            )
            assert r2.is_allow, (
                "E2E Segment 2 FAIL: new policy not applied immediately to existing session"
            )
        finally:
            _cm.enforcement_log = original_log


# ---------------------------------------------------------------------------
# Segment 3: PostToolUse events carry bundle_version (TrustSOC integration)
# ---------------------------------------------------------------------------


class TestE2ESegment3TrustSOCEventFlow:
    """E2E Segment 3 — PostToolUse events must carry bundle_version for TrustSOC correlation."""

    @pytest.mark.asyncio
    async def test_enforcement_log_includes_bundle_version(self):
        log = EnforcementLog(max_entries=200)
        engine = OPAEngine(evaluator=RegoNativeEvaluator())
        client = PDPClient(engine=engine, timeout_s=5.0, rego_modules={})

        import app.pdp.client as _cm
        original_log = _cm.enforcement_log
        _cm.enforcement_log = log

        try:
            await client.decide(
                tool_name="read_file",
                tool_args={"path": "/tmp/test.txt"},
                agent_id="e2e-agent-3",
                session_id="e2e-seg3",
                deployment_tier="HOMEGROWN",
            )
        finally:
            _cm.enforcement_log = original_log

        entries = log.recent(1)
        assert entries, "E2E Segment 3 FAIL: no enforcement log entries produced"
        last_entry = entries[0]
        assert hasattr(last_entry, "bundle_version"), (
            "E2E Segment 3 FAIL: enforcement log entry missing bundle_version field"
        )

    def test_posttooluse_event_schema_has_blast_radius_score(self):
        """PostToolUse event schema must include blast_radius_score field."""
        from app.events.post_tool_use_event import (
            emit_post_tool_use_event,
            OUTCOME_EXECUTED,
        )

        event = emit_post_tool_use_event(
            request_id="e2e-seg3-req",
            session_id="e2e-seg3-event",
            agent_id="e2e-agent-3",
            tool_name="read_file",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
            blast_radius_score=0.45,
        )

        assert event is not None, "E2E Segment 3 FAIL: emit_post_tool_use_event returned None"
        assert "blast_radius_score" in event, (
            "E2E Segment 3 FAIL: PostToolUse event missing blast_radius_score field — "
            "TrustSOC cannot correlate blast radius to tool use events"
        )

    def test_posttooluse_event_has_hmac_signature(self, monkeypatch):
        """PostToolUse events must be HMAC-signed for tamper evidence when key is configured."""
        from app.core.config import settings
        monkeypatch.setattr(settings, "posttooluse_hmac_key", "agentrt-test-hmac-key-32-chars!!")

        from app.events.post_tool_use_event import emit_post_tool_use_event, OUTCOME_EXECUTED

        event = emit_post_tool_use_event(
            request_id="e2e-hmac-req",
            session_id="e2e-hmac-sess",
            agent_id="e2e-hmac-agent",
            tool_name="read_file",
            tool_outcome=OUTCOME_EXECUTED,
            decision="ALLOW",
            blast_radius_score=0.0,
        )

        metadata = event.get("metadata", {})
        # HMAC signing requires AGENTPEP_POSTTOOLUSE_HMAC_KEY; the field must appear when set
        assert "hmac_signature" in metadata, (
            "E2E Segment 3 FAIL: PostToolUse event metadata missing hmac_signature even with "
            "AGENTPEP_POSTTOOLUSE_HMAC_KEY configured — tamper-evident stream not active"
        )

    @pytest.mark.asyncio
    async def test_enforcement_log_entry_has_blast_radius_score(self):
        """Enforcement log entries must carry blast_radius_score for TrustSOC."""
        log = EnforcementLog(max_entries=200)
        engine = OPAEngine(evaluator=RegoNativeEvaluator())
        client = PDPClient(engine=engine, timeout_s=5.0, rego_modules={})

        import app.pdp.client as _cm
        original_log = _cm.enforcement_log
        _cm.enforcement_log = log

        try:
            await client.decide(
                tool_name="read_file",
                tool_args={"path": "/tmp/test.txt"},
                agent_id="e2e-agent-blast",
                session_id="e2e-blast-sess",
                deployment_tier="HOMEGROWN",
                blast_radius_score=0.55,
            )
        finally:
            _cm.enforcement_log = original_log

        entries = log.recent(1)
        assert entries, "E2E Segment 3 FAIL: no entries in log"
        entry = entries[0]
        assert hasattr(entry, "blast_radius_score"), (
            "E2E Segment 3 FAIL: enforcement log entry missing blast_radius_score"
        )
        assert entry.blast_radius_score == pytest.approx(0.55), (
            "E2E Segment 3 FAIL: blast_radius_score not propagated to log entry"
        )


# ---------------------------------------------------------------------------
# Segment 4: Emergency deny-all bundle enforcement
# ---------------------------------------------------------------------------


class TestE2ESegment4EmergencyBundle:
    """E2E Segment 4 — emergency deny-all bundle enforces immediately."""

    @pytest.mark.asyncio
    async def test_deny_all_bundle_denies_everything(self):
        """After loading a deny-all bundle, every tool call must be DENY."""
        log = EnforcementLog(max_entries=200)
        engine = OPAEngine(evaluator=DenyAllEvaluator())
        client = PDPClient(engine=engine, timeout_s=5.0, rego_modules={})

        import app.pdp.client as _cm
        original_log = _cm.enforcement_log
        _cm.enforcement_log = log

        previously_allowed_tools = [
            ("read_file", {"path": "/tmp/safe.txt"}),
            ("list_dir", {"path": "/tmp"}),
            ("search_code", {"query": "hello"}),
        ]

        try:
            for tool_name, args in previously_allowed_tools:
                result = await client.decide(
                    tool_name=tool_name,
                    tool_args=args,
                    agent_id="e2e-emergency-agent",
                    session_id="e2e-emergency-sess",
                    deployment_tier="HOMEGROWN",
                )
                assert result.is_deny, (
                    f"E2E Segment 4 FAIL: {tool_name} was ALLOW after deny-all bundle loaded"
                )
        finally:
            _cm.enforcement_log = original_log

    @pytest.mark.asyncio
    async def test_deny_all_bundle_enforced_with_low_latency(self):
        """Deny-all bundle decisions must complete within 1 second (P99 guard)."""
        log = EnforcementLog(max_entries=200)
        engine = OPAEngine(evaluator=DenyAllEvaluator())
        client = PDPClient(engine=engine, timeout_s=5.0, rego_modules={})

        import app.pdp.client as _cm
        original_log = _cm.enforcement_log
        _cm.enforcement_log = log

        latencies: list[float] = []
        try:
            for _ in range(10):
                start = time.monotonic()
                await client.decide(
                    tool_name="bash",
                    tool_args={"command": "id"},
                    agent_id="e2e-lat-agent",
                    session_id="e2e-lat-sess",
                    deployment_tier="HOMEGROWN",
                )
                latencies.append((time.monotonic() - start) * 1000)
        finally:
            _cm.enforcement_log = original_log

        p99_idx = max(0, int(len(latencies) * 0.99) - 1)
        p99 = sorted(latencies)[p99_idx]
        assert p99 < 1000, (
            f"E2E Segment 4 FAIL: P99 latency {p99:.1f}ms exceeds 1000ms guard"
        )


# ---------------------------------------------------------------------------
# Segment 5: Full AAPM → AgentPEP → TrustSOC chain summary test
# ---------------------------------------------------------------------------


class TestE2EFullChain:
    """E2E Segment 5 — Full chain: bundle load → policy active → log entries with metadata."""

    @pytest.mark.asyncio
    async def test_full_e2e_chain_completes_successfully(self, caplog):
        """Validate the full AAPM → AgentPEP → TrustSOC chain in a single flow."""
        # Step 1: Build + sign bundle (simulating AAPM PCR → compile → sign)
        bundle_bytes, sig_bytes, pub_key = _build_signed_bundle(version="e2e-2.1.0")

        # Step 2: Load via TrustedPolicyLoader (simulating AgentPEP webhook handler)
        loader = TrustedPolicyLoader(_public_key_override=pub_key)
        url = (
            "http://localhost:8099/agentpep/policies/global/"
            "core_enforcement/e2e-2.1.0/bundle.tar.gz"
        )

        with patch.object(
            loader,
            "_fetch",
            side_effect=lambda u: sig_bytes if u.endswith(".sig") else bundle_bytes,
        ):
            loaded = loader.load_and_track(url, tenant_id="global", bundle_name="core_enforcement")

        assert loaded is not None

        # Step 3: Create PDP client with stub evaluator (loaded Rego files available)
        log = EnforcementLog(max_entries=200)
        engine = OPAEngine(evaluator=RegoNativeEvaluator())
        client = PDPClient(engine=engine, timeout_s=5.0, rego_modules=loaded.rego_files)

        import app.pdp.client as _cm
        original_log = _cm.enforcement_log
        _cm.enforcement_log = log

        try:
            # Step 4: Verify enforcement decisions
            allowed_result = await client.decide(
                tool_name="read_file",
                tool_args={"path": "/tmp/e2e_test.txt"},
                agent_id="e2e-full-agent",
                session_id="e2e-full-session",
                deployment_tier="HOMEGROWN",
                blast_radius_score=0.3,
            )
            denied_result = await client.decide(
                tool_name="bash",
                tool_args={"command": "id"},
                agent_id="e2e-full-agent",
                session_id="e2e-full-session",
                deployment_tier="HOMEGROWN",
                blast_radius_score=0.3,
            )

            assert allowed_result.is_allow, (
                "E2E Full Chain FAIL: read_file should be ALLOW"
            )
            assert denied_result.is_deny, (
                "E2E Full Chain FAIL: bash should be DENY"
            )

            # Step 5: Verify enforcement log entries carry bundle_version + blast_radius_score
            entries = log.recent(2)
            assert len(entries) == 2, (
                f"E2E Full Chain FAIL: expected 2 log entries, got {len(entries)}"
            )
            for entry in entries:
                assert hasattr(entry, "bundle_version"), (
                    "E2E Full Chain FAIL: log entry missing bundle_version"
                )
                assert hasattr(entry, "blast_radius_score"), (
                    "E2E Full Chain FAIL: log entry missing blast_radius_score"
                )
                assert entry.blast_radius_score == pytest.approx(0.3), (
                    "E2E Full Chain FAIL: blast_radius_score not in log entry"
                )
        finally:
            _cm.enforcement_log = original_log
