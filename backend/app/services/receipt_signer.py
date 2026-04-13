"""ReceiptSigner — cryptographically signed receipts per authorization decision.

Sprint 32 — APEP-256: Ed25519 (PyNaCl) and HMAC-SHA256 (fallback) signed
receipts. Each ALLOW/DENY/ESCALATE decision can produce a receipt that
proves the decision was made by this server and has not been tampered with.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Receipt format version
_RECEIPT_VERSION = "agentpep-receipt-v1"

# Check for optional Ed25519 support
_HAS_NACL = False
try:
    import nacl.signing  # type: ignore[import-untyped]

    _HAS_NACL = True
except ImportError:
    pass


class ReceiptSigner:
    """Generate cryptographically signed receipts for authorization decisions.

    Supports two signing methods:
    - **ed25519** (preferred): Asymmetric — uses PyNaCl ``SigningKey``.
      The verify key can be distributed for offline verification.
    - **hmac-sha256** (fallback): Symmetric — uses stdlib ``hmac``.
      The shared secret must be known to verifiers.

    If Ed25519 is requested but PyNaCl is not installed, the signer
    automatically falls back to HMAC-SHA256 and logs a warning.
    """

    def __init__(
        self,
        signing_method: str = "hmac-sha256",
        private_key: bytes | None = None,
        key_id: str = "default",
    ) -> None:
        self._key_id = key_id
        self._requested_method = signing_method.lower()

        if self._requested_method == "ed25519" and _HAS_NACL:
            self._method = "ed25519"
            if private_key:
                self._signing_key = nacl.signing.SigningKey(private_key)
            else:
                self._signing_key = nacl.signing.SigningKey.generate()
            self._hmac_key: bytes = b""
        else:
            if self._requested_method == "ed25519" and not _HAS_NACL:
                logger.warning(
                    "PyNaCl not installed — falling back to hmac-sha256 for receipts. "
                    "Install pynacl to enable Ed25519 signing."
                )
            self._method = "hmac-sha256"
            self._hmac_key = private_key or os.urandom(32)
            self._signing_key = None  # type: ignore[assignment]

    @property
    def method(self) -> str:
        """The active signing method."""
        return self._method

    @property
    def key_id(self) -> str:
        return self._key_id

    @staticmethod
    def canonicalize(record: dict[str, Any]) -> bytes:
        """Produce a canonical byte representation of a decision record."""
        return json.dumps(record, sort_keys=True, default=str).encode("utf-8")

    def sign(self, decision_record: dict[str, Any]) -> str:
        """Sign a decision record and return a receipt string.

        Receipt format::

            agentpep-receipt-v1|{key_id}|{algorithm}|{b64_content_hash}|{b64_signature}
        """
        canonical = self.canonicalize(decision_record)
        content_hash = hashlib.sha256(canonical).digest()
        b64_hash = base64.urlsafe_b64encode(content_hash).decode()

        if self._method == "ed25519":
            signed = self._signing_key.sign(canonical)
            b64_sig = base64.urlsafe_b64encode(signed.signature).decode()
        else:
            sig = hmac.new(self._hmac_key, canonical, hashlib.sha256).digest()
            b64_sig = base64.urlsafe_b64encode(sig).decode()

        return f"{_RECEIPT_VERSION}|{self._key_id}|{self._method}|{b64_hash}|{b64_sig}"

    def sign_batch(self, records: list[dict[str, Any]]) -> list[str]:
        """Sign multiple decision records."""
        return [self.sign(r) for r in records]

    def get_verify_key_bytes(self) -> bytes:
        """Export the verification key.

        - Ed25519: returns the 32-byte public verify key.
        - HMAC-SHA256: returns the shared secret.
        """
        if self._method == "ed25519":
            return bytes(self._signing_key.verify_key)
        return self._hmac_key

    def reset(self) -> None:
        """Reset internal state (for testing)."""
        pass


# Module-level singleton (initialized from settings when enabled)
receipt_signer: ReceiptSigner | None = None
