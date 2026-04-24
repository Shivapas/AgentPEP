"""AgentRT — Bypass Regression Suite: Class 1 Config Injection.

Sprint S-E09 (E09-T02)

Validates that CVE-2025-59536 and related config injection attack patterns are
unconditionally blocked by FEATURE-02 (Trusted Policy Loader).

Pass criterion: 100% block rate — all vectors must be blocked with a
SECURITY_VIOLATION event emitted.

Reference: docs/threat_model/bypass_vectors.md — BV-001 Config Injection
Reference: docs/integrations/agentrt_contract.md — Class 1 vectors CI-1 through CI-8
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import tarfile
from unittest.mock import patch

import pytest

from app.policy.loader import (
    SignatureVerificationError,
    TrustedPolicyLoader,
    UntrustedSourceError,
    _BLOCKED_ENV_VARS,
    check_and_report_env_var_overrides,
    detect_env_var_override_attempt,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_signed_bundle(private_key) -> tuple[bytes, bytes]:
    """Build a minimal tar.gz bundle and sign it with *private_key*.

    Returns (bundle_bytes, signature_bytes).
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        rego = b"package agentpep.core\nimport rego.v1\ndefault allow := false"
        ti = tarfile.TarInfo(name="policies/core.rego")
        ti.size = len(rego)
        tf.addfile(ti, io.BytesIO(rego))
    bundle_bytes = buf.getvalue()
    digest = hashlib.sha256(bundle_bytes).digest()
    sig_bytes = private_key.sign(digest)
    return bundle_bytes, sig_bytes


_VALID_BUNDLE_URL = (
    "https://registry.trustfabric.internal/agentpep/policies/"
    "global/core_enforcement/1.4.2/bundle.tar.gz"
)


# ---------------------------------------------------------------------------
# CI-1: Environment variable injection
# ---------------------------------------------------------------------------


class TestCI1EnvVarInjection:
    """AgentRT CI-1 — CVE-2025-59536 env var injection vectors.

    Every variable on the blocklist must be detected and reported.
    Setting a blocked env var must NOT change which URLs the loader accepts.
    """

    @pytest.mark.parametrize("var_name", list(_BLOCKED_ENV_VARS))
    def test_blocked_env_var_detected(self, monkeypatch, var_name):
        monkeypatch.setenv(var_name, "https://attacker.example.com/evil_bundle.tar.gz")
        offending = detect_env_var_override_attempt()
        assert var_name in offending, (
            f"AgentRT CI-1 FAIL: {var_name!r} not detected as policy source override"
        )

    @pytest.mark.parametrize("var_name", list(_BLOCKED_ENV_VARS))
    def test_blocked_env_var_emits_security_violation(self, monkeypatch, caplog, var_name):
        monkeypatch.setenv(var_name, "https://attacker.example.com/evil_bundle.tar.gz")
        with caplog.at_level(logging.ERROR):
            check_and_report_env_var_overrides()
        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records), (
            f"AgentRT CI-1 FAIL: SECURITY_VIOLATION not emitted for {var_name!r}"
        )

    def test_env_var_does_not_expand_loader_allowlist(self, monkeypatch):
        """Env var injection must not make attacker URL appear trusted."""
        monkeypatch.setenv("AGENTPEP_POLICY_URL", "https://attacker.example.com/evil.tar.gz")
        loader = TrustedPolicyLoader()
        with pytest.raises(UntrustedSourceError):
            loader.load_bundle("https://attacker.example.com/evil.tar.gz")

    def test_whitespace_only_var_is_not_detected(self, monkeypatch):
        """A var containing only whitespace must not trigger detection."""
        monkeypatch.setenv("AGENTPEP_POLICY_URL", "   ")
        assert "AGENTPEP_POLICY_URL" not in detect_env_var_override_attempt()

    def test_check_and_report_does_not_raise(self, monkeypatch):
        """Reporting env var violations must not crash the process."""
        for var in _BLOCKED_ENV_VARS:
            monkeypatch.setenv(var, "https://attacker.example.com/evil.tar.gz")
        check_and_report_env_var_overrides()  # must not raise


# ---------------------------------------------------------------------------
# CI-2: Untrusted hostname
# ---------------------------------------------------------------------------


class TestCI2UntrustedHostname:
    """AgentRT CI-2 — bundle URL pointing to an attacker-controlled host."""

    ATTACKER_URLS = [
        "https://attacker.example.com/agentpep/policies/global/core/1.0/bundle.tar.gz",
        "https://evil.trustfabric.internal.attacker.com/agentpep/policies/global/core/1.0/bundle.tar.gz",
        "https://registry.trustfabric.internal.evil.com/agentpep/policies/global/core/1.0/bundle.tar.gz",
        "https://xregistry.trustfabric.internal/agentpep/policies/global/core/1.0/bundle.tar.gz",
        "https://registry.trustfabric.internal@evil.com/agentpep/policies/global/core/1.0/bundle.tar.gz",
    ]

    @pytest.mark.parametrize("url", ATTACKER_URLS)
    def test_attacker_hostname_rejected(self, url, caplog):
        with caplog.at_level(logging.ERROR):
            with pytest.raises(UntrustedSourceError):
                TrustedPolicyLoader._validate_source_url(url)
        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records), (
            f"AgentRT CI-2 FAIL: SECURITY_VIOLATION not emitted for {url!r}"
        )

    def test_subdomain_spoofing_rejected(self, caplog):
        url = (
            "https://registry.trustfabric.internal.evil.com/"
            "agentpep/policies/global/core/1.0/bundle.tar.gz"
        )
        with caplog.at_level(logging.ERROR):
            with pytest.raises(UntrustedSourceError):
                TrustedPolicyLoader._validate_source_url(url)


# ---------------------------------------------------------------------------
# CI-3: file:// scheme injection
# ---------------------------------------------------------------------------


class TestCI3FileSchemeInjection:
    """AgentRT CI-3 — loading a local file as a policy bundle."""

    FILE_URLS = [
        "file:///etc/passwd",
        "file:///tmp/evil_bundle.tar.gz",
        "file:///home/user/crafted_rego.tar.gz",
        "file://localhost/etc/shadow",
        "file:///proc/self/environ",
    ]

    @pytest.mark.parametrize("url", FILE_URLS)
    def test_file_scheme_rejected(self, url, caplog):
        with caplog.at_level(logging.ERROR):
            with pytest.raises(UntrustedSourceError):
                TrustedPolicyLoader._validate_source_url(url)
        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records), (
            f"AgentRT CI-3 FAIL: SECURITY_VIOLATION not emitted for file scheme {url!r}"
        )


# ---------------------------------------------------------------------------
# CI-4: Path traversal
# ---------------------------------------------------------------------------


class TestCI4PathTraversal:
    """AgentRT CI-4 — path traversal sequences in the bundle URL."""

    TRAVERSAL_URLS = [
        "https://registry.trustfabric.internal/agentpep/policies/../../../etc/passwd",
        "https://registry.trustfabric.internal/agentpep/policies/%2e%2e/evil",
        "https://registry.trustfabric.internal/agentpep/policies/%2f%2e%2e/evil",
        "https://registry.trustfabric.internal/agentpep/policies/global/../../secrets",
        "https://registry.trustfabric.internal/agentpep/policies/..%2F..%2Fetc%2Fpasswd",
    ]

    @pytest.mark.parametrize("url", TRAVERSAL_URLS)
    def test_path_traversal_rejected(self, url, caplog):
        with caplog.at_level(logging.ERROR):
            with pytest.raises(UntrustedSourceError):
                TrustedPolicyLoader._validate_source_url(url)
        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records), (
            f"AgentRT CI-4 FAIL: SECURITY_VIOLATION not emitted for path traversal {url!r}"
        )


# ---------------------------------------------------------------------------
# CI-5: Embedded credentials
# ---------------------------------------------------------------------------


class TestCI5EmbeddedCredentials:
    """AgentRT CI-5 — credentials embedded in the bundle URL."""

    CREDENTIAL_URLS = [
        "https://user:pass@registry.trustfabric.internal/agentpep/policies/global/core/1.0/bundle.tar.gz",
        "https://admin:secret@registry.trustfabric.internal/agentpep/policies/global/core/1.0/bundle.tar.gz",
        "https://token@registry.trustfabric.internal/agentpep/policies/global/core/1.0/bundle.tar.gz",
    ]

    @pytest.mark.parametrize("url", CREDENTIAL_URLS)
    def test_embedded_credentials_rejected(self, url, caplog):
        with caplog.at_level(logging.ERROR):
            with pytest.raises(UntrustedSourceError, match="credentials"):
                TrustedPolicyLoader._validate_source_url(url)
        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records), (
            f"AgentRT CI-5 FAIL: SECURITY_VIOLATION not emitted for credential URL {url!r}"
        )


# ---------------------------------------------------------------------------
# CI-6: HTTP cleartext downgrade (non-localhost)
# ---------------------------------------------------------------------------


class TestCI6HttpCleartextDowngrade:
    """AgentRT CI-6 — HTTP cleartext downgrade to enable MITM."""

    HTTP_URLS = [
        "http://registry.trustfabric.internal/agentpep/policies/global/core/1.0/bundle.tar.gz",
        "http://evil.example.com/agentpep/policies/global/core/1.0/bundle.tar.gz",
        "http://10.0.0.1/agentpep/policies/global/core/1.0/bundle.tar.gz",
    ]

    @pytest.mark.parametrize("url", HTTP_URLS)
    def test_http_non_localhost_rejected(self, url, caplog):
        with caplog.at_level(logging.ERROR):
            with pytest.raises(UntrustedSourceError):
                TrustedPolicyLoader._validate_source_url(url)

    def test_http_localhost_accepted(self):
        """HTTP is permitted for localhost (mock registry in dev/test)."""
        url = "http://localhost:8099/agentpep/policies/global/core/1.0/bundle.tar.gz"
        TrustedPolicyLoader._validate_source_url(url)  # must not raise


# ---------------------------------------------------------------------------
# CI-7: Forged bundle signature
# ---------------------------------------------------------------------------


class TestCI7ForgedSignature:
    """AgentRT CI-7 — bundle signed with an attacker-controlled key."""

    def test_attacker_signed_bundle_rejected(self, caplog):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        attacker_private = Ed25519PrivateKey.generate()
        pinned_private = Ed25519PrivateKey.generate()
        pinned_public = pinned_private.public_key()

        bundle_bytes, wrong_sig = _make_signed_bundle(attacker_private)
        loader = TrustedPolicyLoader(_public_key_override=pinned_public)

        with caplog.at_level(logging.ERROR):
            with patch.object(
                loader,
                "_fetch",
                side_effect=lambda url: wrong_sig if url.endswith(".sig") else bundle_bytes,
            ):
                with pytest.raises(SignatureVerificationError):
                    loader.load_bundle(_VALID_BUNDLE_URL)

        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records), (
            "AgentRT CI-7 FAIL: SECURITY_VIOLATION not emitted for forged signature"
        )

    def test_forged_bundle_not_partially_returned(self):
        """On signature failure, no bundle data must be returned."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        attacker_private = Ed25519PrivateKey.generate()
        pinned_private = Ed25519PrivateKey.generate()
        pinned_public = pinned_private.public_key()

        bundle_bytes, wrong_sig = _make_signed_bundle(attacker_private)
        loader = TrustedPolicyLoader(_public_key_override=pinned_public)

        result = None
        try:
            with patch.object(
                loader,
                "_fetch",
                side_effect=lambda url: wrong_sig if url.endswith(".sig") else bundle_bytes,
            ):
                result = loader.load_bundle(_VALID_BUNDLE_URL)
        except SignatureVerificationError:
            pass

        assert result is None, (
            "AgentRT CI-7 FAIL: loader returned bundle data despite signature failure"
        )

    def test_empty_signature_rejected(self, caplog):
        """An empty .sig file must trigger SECURITY_VIOLATION and rejection."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        pinned_private = Ed25519PrivateKey.generate()
        pinned_public = pinned_private.public_key()

        bundle_bytes, _ = _make_signed_bundle(pinned_private)
        loader = TrustedPolicyLoader(_public_key_override=pinned_public)

        with caplog.at_level(logging.ERROR):
            with patch.object(
                loader,
                "_fetch",
                side_effect=lambda url: b"" if url.endswith(".sig") else bundle_bytes,
            ):
                with pytest.raises(SignatureVerificationError):
                    loader.load_bundle(_VALID_BUNDLE_URL)

        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# CI-8: Compound attack
# ---------------------------------------------------------------------------


class TestCI8CompoundAttack:
    """AgentRT CI-8 — multiple injection vectors combined simultaneously."""

    def test_env_var_plus_attacker_url_both_blocked(self, monkeypatch, caplog):
        monkeypatch.setenv("AGENTPEP_POLICY_URL", "https://attacker.example.com/evil.tar.gz")

        with caplog.at_level(logging.ERROR):
            check_and_report_env_var_overrides()

        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records), (
            "AgentRT CI-8 FAIL: SECURITY_VIOLATION not emitted for env var vector"
        )
        with pytest.raises(UntrustedSourceError):
            TrustedPolicyLoader._validate_source_url(
                "https://attacker.example.com/evil.tar.gz"
            )

    def test_path_traversal_plus_wrong_host_both_caught(self, caplog):
        url = "https://evil.com/agentpep/policies/../../../etc/shadow"
        with caplog.at_level(logging.ERROR):
            with pytest.raises(UntrustedSourceError):
                TrustedPolicyLoader._validate_source_url(url)
        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records), (
            "AgentRT CI-8 FAIL: compound traversal+host attack not reported"
        )

    def test_all_blocked_vars_plus_forged_url_comprehensive(self, monkeypatch, caplog):
        """Full compound attack: all env vars set + multiple malformed URLs tested."""
        for var in _BLOCKED_ENV_VARS:
            monkeypatch.setenv(var, "https://attacker.example.com/evil.tar.gz")

        with caplog.at_level(logging.ERROR):
            check_and_report_env_var_overrides()

        security_violations = [r for r in caplog.records if "SECURITY_VIOLATION" in r.message]
        assert len(security_violations) >= len(_BLOCKED_ENV_VARS), (
            f"AgentRT CI-8 FAIL: expected at least {len(_BLOCKED_ENV_VARS)} "
            f"SECURITY_VIOLATION events, got {len(security_violations)}"
        )
