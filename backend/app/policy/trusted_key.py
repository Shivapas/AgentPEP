"""AAPM policy bundle public key — pinned compile-time constant.

The AAPM Ed25519 public key is embedded here as a compile-time constant.
It cannot be overridden at runtime by operator configuration, environment
variable, or CLI flag.

This key verifies all Rego policy bundles published by the AAPM team.
The corresponding private key is held exclusively by AAPM; AgentPEP never
possesses it.

Key rotation procedure:
  1. Receive the new public key PEM from the AAPM team (see onboarding doc).
  2. Replace AAPM_POLICY_PUBLIC_KEY_PEM below.
  3. Build and release a new AgentPEP binary — there is no runtime update path.
  4. Coordinate with AAPM to rotate on both sides simultaneously.

Sprint S-E03 (E03-T03)
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---------------------------------------------------------------------------
# Pinned AAPM policy public key (Ed25519, PEM-encoded)
#
# DEVELOPMENT KEY — replace with real AAPM key before production deployment.
# This key is used by scripts/mock_aapm_registry.py and test fixtures.
# The production key is provisioned by the AAPM team during AgentPEP
# onboarding (see: docs/integrations/aapm_agentpep_contract_draft.md §9).
#
# To regenerate a development keypair:
#   python scripts/mock_aapm_registry.py --dump-public-key
# ---------------------------------------------------------------------------
AAPM_POLICY_PUBLIC_KEY_PEM: str = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXBjCV0=\n"
    "-----END PUBLIC KEY-----\n"
)

# ---------------------------------------------------------------------------
# Policy Registry base URL — the only allowlisted policy source.
#
# AgentPEP will refuse to load bundles from any URL that does not begin
# with this prefix.  This is a compile-time constant; it cannot be
# overridden by environment variable, config file, or CLI flag.
# ---------------------------------------------------------------------------
AAPM_REGISTRY_BASE_URL: str = (
    "https://registry.trustfabric.internal/agentpep/policies/"
)

# ---------------------------------------------------------------------------
# Webhook HMAC secret — name of the environment variable that holds
# the shared secret provisioned by AAPM during onboarding.
# The secret VALUE is not stored here; it lives in the operator keystore.
# ---------------------------------------------------------------------------
WEBHOOK_HMAC_SECRET_ENV_VAR: str = "AGENTPEP_WEBHOOK_HMAC_SECRET"

# ---------------------------------------------------------------------------
# Development override — test public key path.
#
# When AGENTPEP_POLICY_DEV_PUBLIC_KEY_PATH is set AND the application is
# running in debug mode, the loader will use the key at that path instead
# of AAPM_POLICY_PUBLIC_KEY_PEM.  This allows the mock AAPM registry to be
# used in local development without modifying this file.
#
# This override is categorically disabled in non-debug mode.
# ---------------------------------------------------------------------------
DEV_PUBLIC_KEY_PATH_ENV_VAR: str = "AGENTPEP_POLICY_DEV_PUBLIC_KEY_PATH"


def get_pinned_public_key() -> Ed25519PublicKey:
    """Return the pinned AAPM Ed25519 public key.

    In debug mode, honours AGENTPEP_POLICY_DEV_PUBLIC_KEY_PATH to allow the
    mock registry key to be used locally.  In production (debug=False) this
    override path is unconditionally ignored.

    Raises:
        ValueError: If the PEM cannot be parsed as an Ed25519 public key.
    """
    import os

    from app.core.config import settings

    pem_bytes: bytes

    if settings.debug:
        dev_path = os.environ.get(DEV_PUBLIC_KEY_PATH_ENV_VAR, "").strip()
        if dev_path:
            try:
                with open(dev_path, "rb") as fh:
                    pem_bytes = fh.read()
            except OSError as exc:
                raise ValueError(
                    f"DEV key path {dev_path!r} could not be read: {exc}"
                ) from exc
        else:
            pem_bytes = AAPM_POLICY_PUBLIC_KEY_PEM.encode()
    else:
        pem_bytes = AAPM_POLICY_PUBLIC_KEY_PEM.encode()

    try:
        key = serialization.load_pem_public_key(pem_bytes)
    except Exception as exc:
        raise ValueError(
            f"Failed to parse AAPM public key PEM: {exc}"
        ) from exc

    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(
            f"AAPM public key must be Ed25519; got {type(key).__name__}"
        )

    return key
