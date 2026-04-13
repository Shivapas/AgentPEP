"""ReceiptVerifier — offline verification of signed receipts.

Sprint 32 — APEP-257: Verify Ed25519 and HMAC-SHA256 signed receipts
without server access.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

_RECEIPT_VERSION = "agentpep-receipt-v1"

_HAS_NACL = False
try:
    import nacl.signing  # type: ignore[import-untyped]
    import nacl.exceptions  # type: ignore[import-untyped]

    _HAS_NACL = True
except ImportError:
    pass


def _parse_receipt(receipt: str) -> tuple[str, str, str, bytes, bytes] | None:
    """Parse a receipt string into (version, key_id, algorithm, content_hash, signature).

    Returns None if the format is invalid.
    """
    parts = receipt.split("|")
    if len(parts) != 5:
        return None
    version, key_id, algorithm, b64_hash, b64_sig = parts
    if version != _RECEIPT_VERSION:
        return None
    try:
        content_hash = base64.urlsafe_b64decode(b64_hash)
        signature = base64.urlsafe_b64decode(b64_sig)
    except Exception:
        return None
    return version, key_id, algorithm, content_hash, signature


class ReceiptVerifier:
    """Verify signed receipts offline without server access.

    Verify keys are registered by key_id. Each key stores (algorithm, key_bytes).
    """

    def __init__(
        self,
        verify_keys: dict[str, tuple[str, bytes]] | None = None,
    ) -> None:
        self._keys: dict[str, tuple[str, bytes]] = dict(verify_keys or {})

    def add_key(self, key_id: str, algorithm: str, key_bytes: bytes) -> None:
        """Register a verify key."""
        self._keys[key_id] = (algorithm, key_bytes)

    def load_key_from_file(self, path: str, key_id: str = "default") -> None:
        """Load a verify key from a file.

        The file should contain a single line with the format::

            {algorithm}:{base64_key}
        """
        with open(path) as f:
            line = f.read().strip()
        algorithm, b64_key = line.split(":", 1)
        key_bytes = base64.urlsafe_b64decode(b64_key)
        self.add_key(key_id, algorithm, key_bytes)

    def verify(self, receipt: str, record: dict[str, Any]) -> bool:
        """Verify a receipt against a decision record.

        Returns True if the receipt is valid.
        """
        parsed = _parse_receipt(receipt)
        if parsed is None:
            logger.warning("Invalid receipt format")
            return False

        _, key_id, algorithm, stored_hash, signature = parsed

        if key_id not in self._keys:
            logger.warning("Unknown key_id in receipt: %s", key_id)
            return False

        registered_alg, key_bytes = self._keys[key_id]
        if registered_alg != algorithm:
            logger.warning(
                "Algorithm mismatch: receipt says %s, key registered as %s",
                algorithm,
                registered_alg,
            )
            return False

        # Re-canonicalize the record
        canonical = json.dumps(record, sort_keys=True, default=str).encode("utf-8")

        # Verify content hash
        expected_hash = hashlib.sha256(canonical).digest()
        if stored_hash != expected_hash:
            logger.warning("Content hash mismatch — record may have been tampered with")
            return False

        # Verify signature
        if algorithm == "ed25519":
            if not _HAS_NACL:
                logger.error(
                    "PyNaCl not installed — cannot verify Ed25519 receipts"
                )
                return False
            try:
                verify_key = nacl.signing.VerifyKey(key_bytes)
                verify_key.verify(canonical, signature)
                return True
            except nacl.exceptions.BadSignatureError:
                logger.warning("Ed25519 signature verification failed")
                return False
        elif algorithm == "hmac-sha256":
            expected_sig = hmac.new(key_bytes, canonical, hashlib.sha256).digest()
            if hmac.compare_digest(signature, expected_sig):
                return True
            logger.warning("HMAC-SHA256 signature verification failed")
            return False
        else:
            logger.warning("Unsupported algorithm: %s", algorithm)
            return False

    def verify_batch(
        self, items: list[tuple[str, dict[str, Any]]]
    ) -> list[bool]:
        """Verify multiple (receipt, record) pairs."""
        return [self.verify(receipt, record) for receipt, record in items]
