"""Unit tests for Sprint 47 — TLS Interception (APEP-375) & TLS Init (APEP-376).

Tests cover:
  - TLS interception hostname matching
  - Always-passthrough hosts (security-sensitive)
  - Certificate generation (if cryptography available)
  - Certificate caching
  - TLS init CA generation
  - CA verification
"""

import pytest

from app.models.forward_proxy import (
    TLSInitConfig,
    TLSInterceptionConfig,
    TLSInterceptionMode,
)
from app.services.tls_interception import TLSInterceptionEngine, _ALWAYS_PASSTHROUGH
from app.services.tls_init import TLSInitService


class TestTLSInterceptionEngine:
    """Tests for the TLS interception engine (APEP-375)."""

    def setup_method(self):
        self.config = TLSInterceptionConfig(enabled=True)
        self.engine = TLSInterceptionEngine(config=self.config)

    # ------------------------------------------------------------------
    # should_intercept logic
    # ------------------------------------------------------------------

    def test_passthrough_when_not_initialized(self):
        mode = self.engine.should_intercept("example.com")
        assert mode == TLSInterceptionMode.PASSTHROUGH

    def test_passthrough_when_disabled(self):
        config = TLSInterceptionConfig(enabled=False)
        engine = TLSInterceptionEngine(config=config)
        mode = engine.should_intercept("example.com")
        assert mode == TLSInterceptionMode.PASSTHROUGH

    def test_always_passthrough_google(self):
        assert "accounts.google.com" in _ALWAYS_PASSTHROUGH

    def test_always_passthrough_stripe(self):
        assert "api.stripe.com" in _ALWAYS_PASSTHROUGH

    def test_always_passthrough_pypi(self):
        assert "pypi.org" in _ALWAYS_PASSTHROUGH

    # ------------------------------------------------------------------
    # Hostname matching
    # ------------------------------------------------------------------

    def test_hostname_matches_exact(self):
        assert TLSInterceptionEngine._hostname_matches("example.com", "example.com")

    def test_hostname_matches_wildcard(self):
        assert TLSInterceptionEngine._hostname_matches("sub.example.com", "*.example.com")

    def test_hostname_wildcard_no_match(self):
        assert not TLSInterceptionEngine._hostname_matches("other.com", "*.example.com")

    def test_hostname_matches_case_insensitive(self):
        assert TLSInterceptionEngine._hostname_matches("Example.COM", "example.com")

    def test_hostname_wildcard_matches_bare_domain(self):
        assert TLSInterceptionEngine._hostname_matches("example.com", "*.example.com")

    # ------------------------------------------------------------------
    # Exclude list
    # ------------------------------------------------------------------

    def test_exclude_list_passthrough(self):
        config = TLSInterceptionConfig(
            enabled=True,
            exclude_hostnames=["*.internal.corp"],
        )
        engine = TLSInterceptionEngine(config=config)
        # Can't test fully without init, but verify config is set
        assert "*.internal.corp" in engine._config.exclude_hostnames

    # ------------------------------------------------------------------
    # Include list (selective interception)
    # ------------------------------------------------------------------

    def test_include_list_config(self):
        config = TLSInterceptionConfig(
            enabled=True,
            intercept_hostnames=["api.target.com"],
        )
        engine = TLSInterceptionEngine(config=config)
        assert "api.target.com" in engine._config.intercept_hostnames

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def test_initial_cache_size(self):
        assert self.engine.cache_size == 0

    def test_not_initialized_by_default(self):
        assert self.engine.is_initialized is False

    def test_invalidate_cache(self):
        self.engine.invalidate_cache()
        assert self.engine.cache_size == 0

    # ------------------------------------------------------------------
    # Certificate generation without init returns None
    # ------------------------------------------------------------------

    def test_get_cert_without_init(self):
        cert = self.engine.get_or_generate_cert("example.com")
        assert cert is None


class TestTLSInitService:
    """Tests for the ToolTrust tls init equivalent (APEP-376)."""

    def setup_method(self):
        self.service = TLSInitService()

    def test_init_ca_without_crypto(self):
        """If cryptography is not installed, should return gracefully."""
        if not self.service._crypto_available:
            result = self.service.init_ca()
            assert result.created is False
            assert "not installed" in result.message

    @pytest.mark.skipif(
        not TLSInitService()._crypto_available,
        reason="cryptography library not installed",
    )
    def test_init_ca_generates_files(self, tmp_path):
        config = TLSInitConfig(
            output_dir=str(tmp_path),
            organization="Test Org",
            common_name="Test CA",
            validity_days=1,
        )
        result = self.service.init_ca(config)
        assert result.created is True
        assert result.ca_cert_path != ""
        assert result.ca_key_path != ""
        assert result.ca_fingerprint != ""
        assert "generated" in result.message.lower()

        # Verify files exist
        import os
        assert os.path.exists(result.ca_cert_path)
        assert os.path.exists(result.ca_key_path)

    @pytest.mark.skipif(
        not TLSInitService()._crypto_available,
        reason="cryptography library not installed",
    )
    def test_init_ca_idempotent(self, tmp_path):
        config = TLSInitConfig(
            output_dir=str(tmp_path),
            validity_days=1,
        )
        # First call creates
        result1 = self.service.init_ca(config)
        assert result1.created is True

        # Second call returns existing
        result2 = self.service.init_ca(config)
        assert result2.created is False
        assert "already exists" in result2.message

    @pytest.mark.skipif(
        not TLSInitService()._crypto_available,
        reason="cryptography library not installed",
    )
    def test_force_regenerate(self, tmp_path):
        config = TLSInitConfig(
            output_dir=str(tmp_path),
            validity_days=1,
        )
        result1 = self.service.init_ca(config)
        assert result1.created is True

        config.force_regenerate = True
        result2 = self.service.init_ca(config)
        assert result2.created is True

    @pytest.mark.skipif(
        not TLSInitService()._crypto_available,
        reason="cryptography library not installed",
    )
    def test_verify_ca_match(self, tmp_path):
        config = TLSInitConfig(
            output_dir=str(tmp_path),
            validity_days=1,
        )
        result = self.service.init_ca(config)
        assert result.created is True

        is_valid = self.service.verify_ca(result.ca_cert_path, result.ca_key_path)
        assert is_valid is True

    @pytest.mark.skipif(
        not TLSInitService()._crypto_available,
        reason="cryptography library not installed",
    )
    def test_rsa_key_algorithm(self, tmp_path):
        config = TLSInitConfig(
            output_dir=str(tmp_path),
            key_algorithm="RSA_2048",
            validity_days=1,
            force_regenerate=True,
        )
        result = self.service.init_ca(config)
        assert result.created is True
        assert result.ca_fingerprint != ""
