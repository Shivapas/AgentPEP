"""Unit tests for agentpep/policy/loader.py.

Sprint S-E03 — E03-T08b
Covers:
  - Source URL validation (allowlist, scheme, path traversal, credentials)
  - Valid bundle loads successfully
  - Invalid signature → FAIL_CLOSED + SignatureVerificationError
  - Untrusted source path → FAIL_CLOSED + UntrustedSourceError
  - Env var override detection and reporting
  - Bundle parsing: rego files, data.json, manifest extraction
  - Version extraction from URL
  - load_and_track() updates bundle_version_tracker
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.policy.bundle_version import bundle_version_tracker
from app.policy.loader import (
    PolicyLoaderError,
    SignatureVerificationError,
    TrustedPolicyLoader,
    UntrustedSourceError,
    _BLOCKED_ENV_VARS,
    check_and_report_env_var_overrides,
    detect_env_var_override_attempt,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _generate_keypair():
    """Return (private_key, public_key) as Ed25519 objects."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def _sign(private_key, bundle_bytes: bytes) -> bytes:
    """Sign the SHA-256 digest of bundle_bytes with private_key."""
    digest = hashlib.sha256(bundle_bytes).digest()
    return private_key.sign(digest)


def _build_bundle(rego: str = 'package test\ndefault allow = false') -> bytes:
    """Build a minimal valid bundle.tar.gz in memory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        # Add a .rego file
        rego_bytes = rego.encode()
        ti = tarfile.TarInfo(name="policies/main.rego")
        ti.size = len(rego_bytes)
        tf.addfile(ti, io.BytesIO(rego_bytes))
        # Add data.json
        data = json.dumps({"version": "1.0"}).encode()
        ti2 = tarfile.TarInfo(name="data.json")
        ti2.size = len(data)
        tf.addfile(ti2, io.BytesIO(data))
        # Add .manifest
        manifest = json.dumps({"revision": "abc123"}).encode()
        ti3 = tarfile.TarInfo(name=".manifest")
        ti3.size = len(manifest)
        tf.addfile(ti3, io.BytesIO(manifest))
    return buf.getvalue()


def _make_loader(public_key) -> TrustedPolicyLoader:
    """Return a loader using the given public key override."""
    return TrustedPolicyLoader(_public_key_override=public_key)


VALID_BUNDLE_URL = (
    "https://registry.trustfabric.internal/agentpep/policies/"
    "global/core_enforcement/1.4.2/bundle.tar.gz"
)
LOCAL_BUNDLE_URL = "http://localhost:8099/agentpep/policies/global/core/1.0/bundle.tar.gz"


@pytest.fixture(autouse=True)
def reset_tracker():
    bundle_version_tracker.reset()
    yield
    bundle_version_tracker.reset()


# ---------------------------------------------------------------------------
# Source URL validation — allowlist (E03-T01)
# ---------------------------------------------------------------------------


class TestSourceUrlValidation:
    def test_valid_registry_url_accepted(self):
        """AAPM registry URLs should not raise."""
        TrustedPolicyLoader._validate_source_url(VALID_BUNDLE_URL)  # no raise

    def test_localhost_http_accepted(self):
        """http://localhost is allowed for dev/test."""
        TrustedPolicyLoader._validate_source_url(LOCAL_BUNDLE_URL)  # no raise

    def test_non_https_non_localhost_rejected(self):
        with pytest.raises(UntrustedSourceError, match="http"):
            TrustedPolicyLoader._validate_source_url(
                "http://evil.example.com/bundle.tar.gz"
            )

    def test_file_scheme_rejected(self):
        with pytest.raises(UntrustedSourceError):
            TrustedPolicyLoader._validate_source_url("file:///etc/passwd")

    def test_wrong_host_rejected(self):
        with pytest.raises(UntrustedSourceError, match="not allowlisted"):
            TrustedPolicyLoader._validate_source_url(
                "https://attacker.example.com/agentpep/policies/global/b/1.0/bundle.tar.gz"
            )

    def test_embedded_credentials_rejected(self):
        with pytest.raises(UntrustedSourceError, match="credentials"):
            TrustedPolicyLoader._validate_source_url(
                "https://user:pass@registry.trustfabric.internal/agentpep/policies/global/b/1.0/bundle.tar.gz"
            )

    def test_path_traversal_dotdot_rejected(self):
        with pytest.raises(UntrustedSourceError, match="traversal"):
            TrustedPolicyLoader._validate_source_url(
                "https://registry.trustfabric.internal/agentpep/policies/../../../etc/passwd"
            )

    def test_path_traversal_encoded_rejected(self):
        with pytest.raises(UntrustedSourceError, match="traversal"):
            TrustedPolicyLoader._validate_source_url(
                "https://registry.trustfabric.internal/agentpep/policies/%2e%2e/etc"
            )

    def test_wrong_path_prefix_rejected(self):
        with pytest.raises(UntrustedSourceError, match="path"):
            TrustedPolicyLoader._validate_source_url(
                "https://registry.trustfabric.internal/other/policies/global/b/1.0/bundle.tar.gz"
            )

    def test_ftp_scheme_rejected(self):
        with pytest.raises(UntrustedSourceError):
            TrustedPolicyLoader._validate_source_url(
                "ftp://registry.trustfabric.internal/bundle.tar.gz"
            )


# ---------------------------------------------------------------------------
# Signature verification — valid bundle (E03-T02)
# ---------------------------------------------------------------------------


class TestSignatureVerification:
    def _mock_fetch(self, bundle_bytes, sig_bytes):
        def side_effect(url):
            if url.endswith(".sig"):
                return sig_bytes
            return bundle_bytes
        return side_effect

    def test_valid_bundle_loads(self):
        private_key, public_key = _generate_keypair()
        bundle_bytes = _build_bundle()
        sig_bytes = _sign(private_key, bundle_bytes)

        loader = _make_loader(public_key)

        with patch.object(loader, "_fetch", side_effect=self._mock_fetch(bundle_bytes, sig_bytes)):
            result = loader.load_bundle(VALID_BUNDLE_URL)

        assert result.version.version == "1.4.2"
        assert len(result.rego_files) == 1
        assert "policies/main.rego" in result.rego_files

    def test_invalid_signature_raises(self):
        _, public_key = _generate_keypair()
        other_private, _ = _generate_keypair()
        bundle_bytes = _build_bundle()
        wrong_sig = _sign(other_private, bundle_bytes)

        loader = _make_loader(public_key)

        with patch.object(loader, "_fetch", side_effect=self._mock_fetch(bundle_bytes, wrong_sig)):
            with pytest.raises(SignatureVerificationError, match="Invalid"):
                loader.load_bundle(VALID_BUNDLE_URL)

    def test_empty_signature_raises(self):
        _, public_key = _generate_keypair()
        bundle_bytes = _build_bundle()

        loader = _make_loader(public_key)

        with patch.object(loader, "_fetch", side_effect=self._mock_fetch(bundle_bytes, b"")):
            with pytest.raises(SignatureVerificationError, match="Empty"):
                loader.load_bundle(VALID_BUNDLE_URL)

    def test_corrupted_bundle_raises(self):
        """Tampered bundle fails signature verification."""
        private_key, public_key = _generate_keypair()
        bundle_bytes = _build_bundle()
        sig_bytes = _sign(private_key, bundle_bytes)
        tampered = bundle_bytes[:-10] + b"\x00" * 10  # corrupt last 10 bytes

        loader = _make_loader(public_key)

        with patch.object(loader, "_fetch", side_effect=self._mock_fetch(tampered, sig_bytes)):
            with pytest.raises(SignatureVerificationError):
                loader.load_bundle(VALID_BUNDLE_URL)

    def test_signature_verification_emits_security_violation_event(self, caplog):
        import logging
        _, public_key = _generate_keypair()
        other_private, _ = _generate_keypair()
        bundle_bytes = _build_bundle()
        wrong_sig = _sign(other_private, bundle_bytes)

        loader = _make_loader(public_key)
        with caplog.at_level(logging.ERROR):
            with patch.object(loader, "_fetch", side_effect=self._mock_fetch(bundle_bytes, wrong_sig)):
                with pytest.raises(SignatureVerificationError):
                    loader.load_bundle(VALID_BUNDLE_URL)

        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Untrusted source — SECURITY_VIOLATION event
# ---------------------------------------------------------------------------


class TestUntrustedSourceEvent:
    def test_untrusted_source_emits_security_violation(self, caplog):
        import logging
        loader = TrustedPolicyLoader()
        with caplog.at_level(logging.ERROR):
            with pytest.raises(UntrustedSourceError):
                loader.load_bundle("file:///etc/malicious_policy.tar.gz")
        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Bundle parsing
# ---------------------------------------------------------------------------


class TestBundleParsing:
    def test_rego_files_extracted(self):
        private_key, public_key = _generate_keypair()
        bundle_bytes = _build_bundle(rego="package mytest\ndefault allow = true")
        sig_bytes = _sign(private_key, bundle_bytes)
        loader = _make_loader(public_key)

        with patch.object(
            loader, "_fetch",
            side_effect=lambda url: sig_bytes if url.endswith(".sig") else bundle_bytes,
        ):
            result = loader.load_bundle(VALID_BUNDLE_URL)

        assert "policies/main.rego" in result.rego_files
        assert b"package mytest" in result.rego_files["policies/main.rego"]

    def test_data_json_extracted(self):
        private_key, public_key = _generate_keypair()
        bundle_bytes = _build_bundle()
        sig_bytes = _sign(private_key, bundle_bytes)
        loader = _make_loader(public_key)

        with patch.object(
            loader, "_fetch",
            side_effect=lambda url: sig_bytes if url.endswith(".sig") else bundle_bytes,
        ):
            result = loader.load_bundle(VALID_BUNDLE_URL)

        assert result.data_json != b""
        data = json.loads(result.data_json)
        assert data["version"] == "1.0"

    def test_manifest_extracted(self):
        private_key, public_key = _generate_keypair()
        bundle_bytes = _build_bundle()
        sig_bytes = _sign(private_key, bundle_bytes)
        loader = _make_loader(public_key)

        with patch.object(
            loader, "_fetch",
            side_effect=lambda url: sig_bytes if url.endswith(".sig") else bundle_bytes,
        ):
            result = loader.load_bundle(VALID_BUNDLE_URL)

        assert result.manifest.get("revision") == "abc123"

    def test_sha256_computed(self):
        private_key, public_key = _generate_keypair()
        bundle_bytes = _build_bundle()
        sig_bytes = _sign(private_key, bundle_bytes)
        loader = _make_loader(public_key)

        with patch.object(
            loader, "_fetch",
            side_effect=lambda url: sig_bytes if url.endswith(".sig") else bundle_bytes,
        ):
            result = loader.load_bundle(VALID_BUNDLE_URL)

        expected = hashlib.sha256(bundle_bytes).hexdigest()
        assert result.sha256 == expected

    def test_invalid_tar_raises_policy_loader_error(self):
        private_key, public_key = _generate_keypair()
        corrupt_bundle = b"this is not a valid tar.gz"
        sig_bytes = _sign(private_key, corrupt_bundle)
        loader = _make_loader(public_key)

        with patch.object(
            loader, "_fetch",
            side_effect=lambda url: sig_bytes if url.endswith(".sig") else corrupt_bundle,
        ):
            with pytest.raises(PolicyLoaderError, match="unpack"):
                loader.load_bundle(VALID_BUNDLE_URL)


# ---------------------------------------------------------------------------
# Version extraction
# ---------------------------------------------------------------------------


class TestVersionExtraction:
    def test_version_extracted_from_standard_path(self):
        url = "https://registry.trustfabric.internal/agentpep/policies/global/core/1.4.2/bundle.tar.gz"
        version, _ = TrustedPolicyLoader._parse_version_from_url(url)
        assert version == "1.4.2"

    def test_version_extracted_for_latest(self):
        url = "https://registry.trustfabric.internal/agentpep/policies/global/core/latest/bundle.tar.gz"
        version, _ = TrustedPolicyLoader._parse_version_from_url(url)
        assert version == "latest"

    def test_version_extracted_semver(self):
        url = "http://localhost:8099/agentpep/policies/global/core/2.0.1-rc1/bundle.tar.gz"
        version, _ = TrustedPolicyLoader._parse_version_from_url(url)
        assert version == "2.0.1-rc1"


# ---------------------------------------------------------------------------
# load_and_track — version tracker integration
# ---------------------------------------------------------------------------


class TestLoadAndTrack:
    def test_load_and_track_updates_tracker(self):
        private_key, public_key = _generate_keypair()
        bundle_bytes = _build_bundle()
        sig_bytes = _sign(private_key, bundle_bytes)
        loader = _make_loader(public_key)

        assert bundle_version_tracker.version_string == "unloaded"

        with patch.object(
            loader, "_fetch",
            side_effect=lambda url: sig_bytes if url.endswith(".sig") else bundle_bytes,
        ):
            loader.load_and_track(VALID_BUNDLE_URL, tenant_id="global", bundle_name="core")

        assert bundle_version_tracker.version_string == "1.4.2"
        assert bundle_version_tracker.is_loaded is True


# ---------------------------------------------------------------------------
# Env var override detection (E03-T04)
# ---------------------------------------------------------------------------


class TestEnvVarOverrideDetection:
    def test_no_blocked_vars_set(self, monkeypatch):
        for var in _BLOCKED_ENV_VARS:
            monkeypatch.delenv(var, raising=False)
        assert detect_env_var_override_attempt() == []

    def test_one_blocked_var_detected(self, monkeypatch):
        monkeypatch.setenv("AGENTPEP_POLICY_URL", "https://evil.example.com/")
        offending = detect_env_var_override_attempt()
        assert "AGENTPEP_POLICY_URL" in offending

    def test_multiple_blocked_vars_detected(self, monkeypatch):
        monkeypatch.setenv("AGENTPEP_POLICY_URL", "https://evil.example.com/")
        monkeypatch.setenv("OPA_BUNDLE_URL", "https://attacker.example.com/")
        offending = detect_env_var_override_attempt()
        assert "AGENTPEP_POLICY_URL" in offending
        assert "OPA_BUNDLE_URL" in offending

    def test_empty_value_not_detected(self, monkeypatch):
        monkeypatch.setenv("AGENTPEP_POLICY_URL", "")
        offending = detect_env_var_override_attempt()
        assert "AGENTPEP_POLICY_URL" not in offending

    def test_check_and_report_emits_security_violation_event(self, monkeypatch, caplog):
        import logging
        monkeypatch.setenv("AGENTPEP_POLICY_URL", "https://evil.example.com/bundle.tar.gz")

        with caplog.at_level(logging.ERROR):
            check_and_report_env_var_overrides()

        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records)

    def test_check_and_report_does_not_raise(self, monkeypatch):
        """Even with blocked vars set, check_and_report_env_var_overrides never raises."""
        monkeypatch.setenv("OPA_POLICY_URL", "https://evil.example.com/")
        check_and_report_env_var_overrides()  # must not raise

    def test_all_blocked_var_names_are_strings(self):
        for var in _BLOCKED_ENV_VARS:
            assert isinstance(var, str)
            assert var.isupper() or "_" in var
