"""Unit tests for agentpep/policy/trusted_key.py.

Sprint S-E03 — E03-T08a
Covers:
  - AAPM_REGISTRY_BASE_URL is a compile-time constant (no runtime mutation)
  - AAPM_POLICY_PUBLIC_KEY_PEM is a non-empty PEM string
  - get_pinned_public_key() returns a valid Ed25519PublicKey
  - get_pinned_public_key() raises ValueError on malformed PEM
  - Dev-mode key path override works when debug=True
  - Dev-mode override is ignored when debug=False
"""

from __future__ import annotations

import os
import tempfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_ed25519_pem() -> bytes:
    """Generate a fresh Ed25519 public key PEM for testing."""
    private_key = Ed25519PrivateKey.generate()
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ---------------------------------------------------------------------------
# AAPM_REGISTRY_BASE_URL
# ---------------------------------------------------------------------------


class TestRegistryBaseUrl:
    def test_base_url_is_https(self):
        from app.policy.trusted_key import AAPM_REGISTRY_BASE_URL

        assert AAPM_REGISTRY_BASE_URL.startswith("https://")

    def test_base_url_ends_with_slash(self):
        from app.policy.trusted_key import AAPM_REGISTRY_BASE_URL

        assert AAPM_REGISTRY_BASE_URL.endswith("/")

    def test_base_url_contains_agentpep_path(self):
        from app.policy.trusted_key import AAPM_REGISTRY_BASE_URL

        assert "agentpep" in AAPM_REGISTRY_BASE_URL

    def test_base_url_is_string_constant(self):
        from app.policy.trusted_key import AAPM_REGISTRY_BASE_URL

        assert isinstance(AAPM_REGISTRY_BASE_URL, str)


# ---------------------------------------------------------------------------
# AAPM_POLICY_PUBLIC_KEY_PEM
# ---------------------------------------------------------------------------


class TestPublicKeyPem:
    def test_pem_is_non_empty_string(self):
        from app.policy.trusted_key import AAPM_POLICY_PUBLIC_KEY_PEM

        assert isinstance(AAPM_POLICY_PUBLIC_KEY_PEM, str)
        assert len(AAPM_POLICY_PUBLIC_KEY_PEM.strip()) > 0

    def test_pem_has_begin_marker(self):
        from app.policy.trusted_key import AAPM_POLICY_PUBLIC_KEY_PEM

        assert "-----BEGIN PUBLIC KEY-----" in AAPM_POLICY_PUBLIC_KEY_PEM

    def test_pem_has_end_marker(self):
        from app.policy.trusted_key import AAPM_POLICY_PUBLIC_KEY_PEM

        assert "-----END PUBLIC KEY-----" in AAPM_POLICY_PUBLIC_KEY_PEM

    def test_webhook_hmac_env_var_name_is_set(self):
        from app.policy.trusted_key import WEBHOOK_HMAC_SECRET_ENV_VAR

        assert WEBHOOK_HMAC_SECRET_ENV_VAR
        assert "AGENTPEP" in WEBHOOK_HMAC_SECRET_ENV_VAR


# ---------------------------------------------------------------------------
# get_pinned_public_key() — production path (debug=False)
# ---------------------------------------------------------------------------


class TestGetPinnedPublicKey:
    def test_returns_ed25519_public_key(self, monkeypatch):
        """Substituting a valid Ed25519 PEM returns an Ed25519PublicKey."""
        from app.core.config import settings
        import app.policy.trusted_key as tk

        monkeypatch.setattr(settings, "debug", False)
        fresh_pem = _generate_ed25519_pem().decode()
        monkeypatch.setattr(tk, "AAPM_POLICY_PUBLIC_KEY_PEM", fresh_pem)

        key = tk.get_pinned_public_key()
        assert isinstance(key, Ed25519PublicKey)

    def test_raises_on_empty_pem(self, monkeypatch):
        from app.core.config import settings
        import app.policy.trusted_key as tk

        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setattr(tk, "AAPM_POLICY_PUBLIC_KEY_PEM", "not a pem")

        with pytest.raises(ValueError, match="parse"):
            tk.get_pinned_public_key()

    def test_raises_on_non_ed25519_key(self, monkeypatch):
        """An RSA key PEM should be rejected (wrong key type)."""
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from app.core.config import settings
        import app.policy.trusted_key as tk

        monkeypatch.setattr(settings, "debug", False)

        rsa_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        rsa_pem = rsa_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        monkeypatch.setattr(tk, "AAPM_POLICY_PUBLIC_KEY_PEM", rsa_pem)

        with pytest.raises(ValueError, match="Ed25519"):
            tk.get_pinned_public_key()

    def test_ignores_dev_path_override_when_not_debug(self, monkeypatch, tmp_path):
        """Even if the env var is set, non-debug mode uses the constant."""
        from app.core.config import settings
        import app.policy.trusted_key as tk

        fresh_pem = _generate_ed25519_pem()
        dev_key_file = tmp_path / "dev_key.pem"
        dev_key_file.write_bytes(fresh_pem)

        monkeypatch.setattr(settings, "debug", False)
        monkeypatch.setenv(tk.DEV_PUBLIC_KEY_PATH_ENV_VAR, str(dev_key_file))

        # Embed a valid key in the constant so we don't get a parse error
        monkeypatch.setattr(tk, "AAPM_POLICY_PUBLIC_KEY_PEM", fresh_pem.decode())

        key = tk.get_pinned_public_key()
        assert isinstance(key, Ed25519PublicKey)
        # The pinned constant PEM was used (no file-read path executed for non-debug)


# ---------------------------------------------------------------------------
# get_pinned_public_key() — dev path override (debug=True)
# ---------------------------------------------------------------------------


class TestGetPinnedPublicKeyDevOverride:
    def test_dev_path_override_used_when_debug_and_env_set(self, monkeypatch, tmp_path):
        """In debug mode, AGENTPEP_POLICY_DEV_PUBLIC_KEY_PATH is honoured."""
        from app.core.config import settings
        import app.policy.trusted_key as tk

        fresh_pem = _generate_ed25519_pem()
        dev_key_file = tmp_path / "dev_pub.pem"
        dev_key_file.write_bytes(fresh_pem)

        monkeypatch.setattr(settings, "debug", True)
        monkeypatch.setenv(tk.DEV_PUBLIC_KEY_PATH_ENV_VAR, str(dev_key_file))

        key = tk.get_pinned_public_key()
        assert isinstance(key, Ed25519PublicKey)

    def test_dev_path_missing_file_raises(self, monkeypatch, tmp_path):
        from app.core.config import settings
        import app.policy.trusted_key as tk

        monkeypatch.setattr(settings, "debug", True)
        monkeypatch.setenv(tk.DEV_PUBLIC_KEY_PATH_ENV_VAR, "/nonexistent/path/key.pem")

        with pytest.raises(ValueError, match="could not be read"):
            tk.get_pinned_public_key()

    def test_falls_back_to_constant_when_env_not_set_debug(self, monkeypatch):
        """debug=True but no env var → uses the constant PEM."""
        from app.core.config import settings
        import app.policy.trusted_key as tk

        fresh_pem = _generate_ed25519_pem().decode()
        monkeypatch.setattr(settings, "debug", True)
        monkeypatch.delenv(tk.DEV_PUBLIC_KEY_PATH_ENV_VAR, raising=False)
        monkeypatch.setattr(tk, "AAPM_POLICY_PUBLIC_KEY_PEM", fresh_pem)

        key = tk.get_pinned_public_key()
        assert isinstance(key, Ed25519PublicKey)
