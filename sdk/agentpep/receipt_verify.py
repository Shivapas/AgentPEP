"""CLI receipt verification — batch-verify signed receipts.

Sprint 34 — APEP-273: ``agentpep receipt verify`` CLI command for batch
verification of signed receipts from audit export files.

Wraps the backend ReceiptVerifier with a file-based CLI interface suitable
for CI/CD pipelines and audit workflows.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import sys
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


# ---------------------------------------------------------------------------
# Standalone receipt verifier (no backend dependency)
# ---------------------------------------------------------------------------


class CLIReceiptVerifier:
    """Verify signed receipts without importing the backend app stack.

    This is a standalone implementation matching the backend ReceiptVerifier
    so the CLI can work without the full app dependencies.
    """

    def __init__(self) -> None:
        self._keys: dict[str, tuple[str, bytes]] = {}

    def add_key(self, key_id: str, algorithm: str, key_bytes: bytes) -> None:
        self._keys[key_id] = (algorithm, key_bytes)

    def load_key_from_file(self, path: str, key_id: str = "default") -> None:
        with open(path) as f:
            line = f.read().strip()
        if ":" not in line:
            raise ValueError(
                f"Invalid key file format — expected 'algorithm:base64_key', got: {line[:40]}..."
            )
        algorithm, b64_key = line.split(":", 1)
        key_bytes = base64.urlsafe_b64decode(b64_key)
        self.add_key(key_id, algorithm, key_bytes)

    def verify(self, receipt: str, record: dict[str, Any]) -> bool:
        parsed = self._parse_receipt(receipt)
        if parsed is None:
            return False

        _, key_id, algorithm, stored_hash, signature = parsed

        if key_id not in self._keys:
            return False

        registered_alg, key_bytes = self._keys[key_id]
        if registered_alg != algorithm:
            return False

        canonical = json.dumps(record, sort_keys=True, default=str).encode("utf-8")
        expected_hash = hashlib.sha256(canonical).digest()
        if stored_hash != expected_hash:
            return False

        if algorithm == "ed25519":
            if not _HAS_NACL:
                logger.error("PyNaCl not installed — cannot verify Ed25519 receipts")
                return False
            try:
                verify_key = nacl.signing.VerifyKey(key_bytes)
                verify_key.verify(canonical, signature)
                return True
            except nacl.exceptions.BadSignatureError:
                return False
        elif algorithm == "hmac-sha256":
            expected_sig = hmac.new(key_bytes, canonical, hashlib.sha256).digest()
            return hmac.compare_digest(signature, expected_sig)

        return False

    @staticmethod
    def _parse_receipt(receipt: str) -> tuple[str, str, str, bytes, bytes] | None:
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


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def batch_verify_receipts(
    *,
    receipts_file: str,
    key_file: str,
    key_id: str = "default",
    verbose: bool = False,
) -> int:
    """Batch-verify receipts from a JSONL file.

    Args:
        receipts_file: Path to JSONL file with receipt+record pairs.
        key_file: Path to verify key file (format: algorithm:base64_key).
        key_id: Key identifier.
        verbose: Print per-receipt details.

    Returns:
        0 if all receipts valid, 1 if any failed.
    """
    verifier = CLIReceiptVerifier()

    try:
        verifier.load_key_from_file(key_file, key_id=key_id)
    except FileNotFoundError:
        print(f"ERROR: Key file not found: {key_file}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"ERROR: Invalid key file format: {exc}", file=sys.stderr)
        return 1

    total = 0
    passed = 0
    failed = 0

    try:
        with open(receipts_file) as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    print(f"  Line {line_num}: FAILED (invalid JSON)")
                    failed += 1
                    continue

                receipt = entry.get("receipt", "")
                record = entry.get("record", {})

                if verifier.verify(receipt, record):
                    passed += 1
                    if verbose:
                        decision_id = record.get("decision_id", "?")
                        print(f"  Line {line_num}: OK (decision_id={decision_id})")
                else:
                    failed += 1
                    decision_id = record.get("decision_id", "?")
                    print(f"  Line {line_num}: FAILED (decision_id={decision_id})")
    except FileNotFoundError:
        print(f"ERROR: Receipts file not found: {receipts_file}", file=sys.stderr)
        return 1

    print(f"\n{passed}/{total} receipts verified successfully")
    if failed > 0:
        print(f"{failed} receipt(s) FAILED verification")
        return 1
    return 0
