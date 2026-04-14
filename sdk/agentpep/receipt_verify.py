"""CLI receipt verification — batch-verify signed receipts.

Sprint 34 — APEP-273: ``agentpep receipt verify`` CLI command for batch
verification of signed receipts from audit export files.

Sprint 39 — APEP-314: ``agentpep receipt verify-chain`` CLI command for
verifying per-receipt Ed25519 signatures and chain integrity from an
exported receipt chain JSON file.

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


# ---------------------------------------------------------------------------
# Sprint 39 — APEP-314: Receipt chain verifier (verify-chain)
# ---------------------------------------------------------------------------


class CLIReceiptChainVerifier:
    """Verify per-receipt Ed25519 signatures and chain integrity offline.

    Standalone implementation for the CLI — no backend dependency.
    """

    def __init__(self) -> None:
        self._verify_key_bytes: bytes | None = None

    def load_key_from_file(self, path: str) -> None:
        """Load an Ed25519 verify key from a file.

        Format: ``ed25519:{base64_key}``
        """
        with open(path) as f:
            line = f.read().strip()
        if ":" not in line:
            raise ValueError(
                f"Invalid key file format — expected 'algorithm:base64_key', got: {line[:40]}..."
            )
        algorithm, b64_key = line.split(":", 1)
        if algorithm != "ed25519":
            raise ValueError(
                f"verify-chain only supports ed25519, got: {algorithm}"
            )
        self._verify_key_bytes = base64.urlsafe_b64decode(b64_key)

    def load_key(self, key_bytes: bytes) -> None:
        self._verify_key_bytes = key_bytes

    @staticmethod
    def _normalize_timestamp(ts: Any) -> str:
        """Normalize timestamp: trailing 'Z' -> '+00:00'."""
        s = str(ts)
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return s

    def _canonical_receipt_payload(self, record: dict[str, Any]) -> bytes:
        """Re-create the canonical byte payload that was signed."""
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
            "timestamp": self._normalize_timestamp(record.get("timestamp", "")),
            "sequence_number": record.get("sequence_number", 0),
            "record_hash": record.get("record_hash", ""),
            "plan_id": str(record["plan_id"]) if record.get("plan_id") else None,
            "parent_receipt_id": (
                str(record["parent_receipt_id"])
                if record.get("parent_receipt_id")
                else None
            ),
        }
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    def verify_receipt(self, record: dict[str, Any]) -> bool:
        """Verify a single receipt's Ed25519 signature."""
        sig_b64 = record.get("receipt_signature", "")
        if not sig_b64 or not self._verify_key_bytes or not _HAS_NACL:
            return False

        try:
            signature = base64.urlsafe_b64decode(sig_b64)
        except Exception:
            return False

        canonical = self._canonical_receipt_payload(record)
        try:
            vk = nacl.signing.VerifyKey(self._verify_key_bytes)
            vk.verify(canonical, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False
        except Exception:
            return False

    def verify_chain(
        self, receipts: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Verify signatures and parent linkage for a receipt chain."""
        total = len(receipts)
        valid_sigs = 0
        invalid_sigs = 0
        results: list[dict[str, Any]] = []

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


def verify_chain_cli(
    *,
    plan_id: str,
    receipts_file: str | None = None,
    key_file: str | None = None,
    export_path: str | None = None,
    base_url: str = "http://localhost:8000",
    verbose: bool = False,
) -> int:
    """CLI entry point for ``agentpep receipt verify-chain``.

    If *receipts_file* is provided, verifies the local JSON export.
    Otherwise, fetches the receipt chain from the server via
    ``GET /v1/plans/{plan_id}/receipts``.

    Args:
        plan_id: The MissionPlan UUID.
        receipts_file: Path to a pre-exported JSON receipt chain file.
        key_file: Path to Ed25519 verify key file (ed25519:base64_key).
        export_path: If set, export the fetched receipt chain to this path.
        base_url: AgentPEP server URL (used when fetching).
        verbose: Print per-receipt details.

    Returns:
        0 if chain is valid, 1 otherwise.
    """
    import urllib.request
    import urllib.error

    receipts: list[dict[str, Any]] = []

    # Load receipts from file or fetch from server
    if receipts_file:
        from pathlib import Path

        path = Path(receipts_file)
        if not path.is_file():
            print(f"ERROR: Receipts file not found: {receipts_file}", file=sys.stderr)
            return 1
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict) and "receipts" in data:
                receipts = data["receipts"]
            elif isinstance(data, list):
                receipts = data
            else:
                print("ERROR: Invalid receipt chain format", file=sys.stderr)
                return 1
        except json.JSONDecodeError as exc:
            print(f"ERROR: Invalid JSON: {exc}", file=sys.stderr)
            return 1
    else:
        # Fetch from server
        url = f"{base_url}/v1/plans/{plan_id}/receipts"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
            receipts = data.get("receipts", [])
        except urllib.error.URLError as exc:
            print(f"ERROR: Failed to fetch receipts: {exc}", file=sys.stderr)
            return 1
        except json.JSONDecodeError:
            print("ERROR: Invalid JSON response from server", file=sys.stderr)
            return 1

    if not receipts:
        print(f"No receipts found for plan {plan_id}")
        return 0

    # Export if requested
    if export_path:
        from pathlib import Path

        export_data = {"plan_id": plan_id, "receipts": receipts}
        Path(export_path).write_text(json.dumps(export_data, indent=2, default=str))
        print(f"Exported {len(receipts)} receipts to {export_path}")

    # Verify chain
    verifier = CLIReceiptChainVerifier()

    if key_file:
        try:
            verifier.load_key_from_file(key_file)
        except FileNotFoundError:
            print(f"ERROR: Key file not found: {key_file}", file=sys.stderr)
            return 1
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    report = verifier.verify_chain(receipts)

    # Output
    print(f"\nReceipt Chain Verification — plan {plan_id}")
    print(f"  Total receipts: {report['total']}")
    print(f"  Valid signatures: {report['valid_signatures']}")
    print(f"  Invalid signatures: {report['invalid_signatures']}")
    print(f"  Chain intact: {'YES' if report['chain_intact'] else 'NO'}")

    if verbose:
        for r in report["results"]:
            sig_status = "OK" if r["signature_valid"] else "FAIL"
            link_status = "OK" if r["linkage_valid"] else "BROKEN"
            print(
                f"    seq={r['sequence_number']} "
                f"decision_id={r['decision_id']} "
                f"sig={sig_status} link={link_status}"
            )

    if report["invalid_signatures"] > 0 or not report["chain_intact"]:
        return 1
    return 0
