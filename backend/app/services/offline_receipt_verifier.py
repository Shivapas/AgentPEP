"""OfflineReceiptVerifier — independent offline receipt chain verifier.

Sprint 39 — APEP-313: Verify Ed25519-signed receipt chains without
server access.  Operates on exported receipt chain JSON files.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

_HAS_NACL = False
try:
    import nacl.signing  # type: ignore[import-untyped]
    import nacl.exceptions  # type: ignore[import-untyped]

    _HAS_NACL = True
except ImportError:
    pass


def _normalize_timestamp(ts: Any) -> str:
    """Normalize timestamp to the isoformat used during signing.

    The signing side calls ``datetime.isoformat()`` which for UTC-aware
    datetimes produces ``…+00:00``.  JSON serialization (``model_dump``)
    may instead emit ``…Z``.  We normalise both to ``+00:00``.
    """
    s = str(ts)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return s


def _canonical_receipt_payload(record: dict[str, Any]) -> bytes:
    """Re-create the canonical byte payload that was signed.

    Must match ``_canonical_receipt_payload`` in ``audit_logger.py``.
    """
    payload: dict[str, Any] = {
        "decision_id": str(record.get("decision_id", "")),
        "session_id": record.get("session_id", ""),
        "agent_id": record.get("agent_id", ""),
        "agent_role": record.get("agent_role", ""),
        "tool_name": record.get("tool_name", ""),
        "tool_args_hash": record.get("tool_args_hash", ""),
        "decision": record.get("decision", ""),
        "risk_score": record.get("risk_score", 0.0),
        "matched_rule_id": (
            str(record["matched_rule_id"]) if record.get("matched_rule_id") else None
        ),
        "taint_flags": record.get("taint_flags", []),
        "delegation_chain": record.get("delegation_chain", []),
        "latency_ms": record.get("latency_ms", 0),
        "timestamp": _normalize_timestamp(record.get("timestamp", "")),
        "sequence_number": record.get("sequence_number", 0),
        "record_hash": record.get("record_hash", ""),
        "plan_id": str(record["plan_id"]) if record.get("plan_id") else None,
        "parent_receipt_id": (
            str(record["parent_receipt_id"]) if record.get("parent_receipt_id") else None
        ),
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


class OfflineReceiptVerifier:
    """Verify per-receipt Ed25519 signatures and chain integrity offline.

    Operates on receipt chain data exported as JSON (from the
    ``GET /v1/plans/{plan_id}/receipts`` endpoint or the CLI
    ``--export`` flag).
    """

    def __init__(self, verify_key: bytes | None = None) -> None:
        self._verify_key_bytes = verify_key

    def load_key(self, key_bytes: bytes) -> None:
        """Load an Ed25519 verify (public) key."""
        self._verify_key_bytes = key_bytes

    def load_key_from_file(self, path: str) -> None:
        """Load a verify key from a file.

        The file should contain a single line::

            ed25519:{base64_key}
        """
        with open(path) as f:
            line = f.read().strip()
        if ":" not in line:
            raise ValueError(
                f"Invalid key file format — expected 'algorithm:base64_key', got: {line[:40]}..."
            )
        algorithm, b64_key = line.split(":", 1)
        if algorithm != "ed25519":
            raise ValueError(f"OfflineReceiptVerifier only supports ed25519, got: {algorithm}")
        self._verify_key_bytes = base64.urlsafe_b64decode(b64_key)

    def verify_receipt(self, record: dict[str, Any]) -> bool:
        """Verify the Ed25519 signature on a single receipt record.

        The record must contain a ``receipt_signature`` field (base64url-encoded).
        Returns True if valid.
        """
        sig_b64 = record.get("receipt_signature", "")
        if not sig_b64:
            return False

        if not self._verify_key_bytes:
            logger.error("No verify key loaded")
            return False

        if not _HAS_NACL:
            logger.error("PyNaCl not installed — cannot verify Ed25519 signatures")
            return False

        try:
            signature = base64.urlsafe_b64decode(sig_b64)
        except Exception:
            logger.warning("Invalid base64 in receipt_signature")
            return False

        canonical = _canonical_receipt_payload(record)

        try:
            vk = nacl.signing.VerifyKey(self._verify_key_bytes)
            vk.verify(canonical, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False
        except Exception:
            logger.exception("Unexpected error during signature verification")
            return False

    def verify_chain(
        self, receipts: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Verify an entire receipt chain: signatures + linkage integrity.

        Args:
            receipts: List of receipt records (as dicts), ordered by
                      sequence_number.

        Returns:
            Verification report dict with keys:
            - total: int — number of receipts processed
            - valid_signatures: int
            - invalid_signatures: int
            - chain_intact: bool — parent_receipt_id linkage is consistent
            - results: list[dict] — per-receipt results
        """
        total = len(receipts)
        valid_sigs = 0
        invalid_sigs = 0
        results: list[dict[str, Any]] = []

        # Build a set of known decision_ids for linkage verification
        known_ids: set[str] = set()
        for r in receipts:
            did = str(r.get("decision_id", ""))
            if did:
                known_ids.add(did)

        chain_intact = True
        for r in receipts:
            did = str(r.get("decision_id", ""))
            parent = r.get("parent_receipt_id")
            parent_str = str(parent) if parent else None

            sig_valid = self.verify_receipt(r)
            if sig_valid:
                valid_sigs += 1
            else:
                invalid_sigs += 1

            # Check parent linkage
            linkage_ok = True
            if parent_str and parent_str not in known_ids:
                linkage_ok = False
                chain_intact = False

            results.append({
                "decision_id": did,
                "sequence_number": r.get("sequence_number", 0),
                "signature_valid": sig_valid,
                "linkage_valid": linkage_ok,
            })

        return {
            "total": total,
            "valid_signatures": valid_sigs,
            "invalid_signatures": invalid_sigs,
            "chain_intact": chain_intact,
            "results": results,
        }
