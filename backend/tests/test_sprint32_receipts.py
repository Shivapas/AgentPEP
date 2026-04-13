"""Tests for Sprint 32 — Cryptographic Receipts.

APEP-256: ReceiptSigner (Ed25519 + HMAC-SHA256)
APEP-257: ReceiptVerifier + CLI tool
"""

import json
import os
import tempfile

import pytest

from app.services.receipt_signer import ReceiptSigner, _HAS_NACL
from app.services.receipt_verifier import ReceiptVerifier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sample_record() -> dict:
    return {
        "decision_id": "d-001",
        "decision": "ALLOW",
        "session_id": "sess-1",
        "agent_id": "agent-1",
        "tool_name": "file.read",
        "risk_score": 0.2,
        "matched_rule_id": "rule-1",
        "taint_flags": ["UNTRUSTED"],
        "latency_ms": 12,
    }


# ---------------------------------------------------------------------------
# APEP-256: ReceiptSigner
# ---------------------------------------------------------------------------


class TestReceiptSignerHMAC:
    """Tests for HMAC-SHA256 receipt signing."""

    def test_sign_returns_receipt_string(self):
        signer = ReceiptSigner(signing_method="hmac-sha256", key_id="k1")
        receipt = signer.sign(_sample_record())
        assert receipt.startswith("agentpep-receipt-v1|k1|hmac-sha256|")
        parts = receipt.split("|")
        assert len(parts) == 5

    def test_sign_is_deterministic(self):
        key = os.urandom(32)
        signer = ReceiptSigner(signing_method="hmac-sha256", private_key=key, key_id="k1")
        r1 = signer.sign(_sample_record())
        r2 = signer.sign(_sample_record())
        assert r1 == r2

    def test_different_records_produce_different_receipts(self):
        signer = ReceiptSigner(signing_method="hmac-sha256", key_id="k1")
        rec1 = _sample_record()
        rec2 = _sample_record()
        rec2["decision"] = "DENY"
        assert signer.sign(rec1) != signer.sign(rec2)

    def test_sign_batch(self):
        signer = ReceiptSigner(signing_method="hmac-sha256", key_id="k1")
        records = [_sample_record(), _sample_record()]
        receipts = signer.sign_batch(records)
        assert len(receipts) == 2
        assert all(r.startswith("agentpep-receipt-v1|") for r in receipts)

    def test_get_verify_key_bytes(self):
        key = os.urandom(32)
        signer = ReceiptSigner(signing_method="hmac-sha256", private_key=key)
        assert signer.get_verify_key_bytes() == key

    def test_receipt_format_version(self):
        signer = ReceiptSigner(signing_method="hmac-sha256")
        receipt = signer.sign(_sample_record())
        assert receipt.startswith("agentpep-receipt-v1|")

    def test_receipt_includes_key_id(self):
        signer = ReceiptSigner(signing_method="hmac-sha256", key_id="my-key-42")
        receipt = signer.sign(_sample_record())
        assert "|my-key-42|" in receipt

    def test_method_property(self):
        signer = ReceiptSigner(signing_method="hmac-sha256")
        assert signer.method == "hmac-sha256"


@pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
class TestReceiptSignerEd25519:
    """Tests for Ed25519 receipt signing (requires PyNaCl)."""

    def test_sign_returns_receipt_string(self):
        signer = ReceiptSigner(signing_method="ed25519", key_id="ed-k1")
        receipt = signer.sign(_sample_record())
        assert receipt.startswith("agentpep-receipt-v1|ed-k1|ed25519|")
        parts = receipt.split("|")
        assert len(parts) == 5

    def test_method_property(self):
        signer = ReceiptSigner(signing_method="ed25519")
        assert signer.method == "ed25519"

    def test_sign_verify_roundtrip(self):
        signer = ReceiptSigner(signing_method="ed25519", key_id="ed-k1")
        record = _sample_record()
        receipt = signer.sign(record)

        verifier = ReceiptVerifier(
            verify_keys={"ed-k1": ("ed25519", signer.get_verify_key_bytes())}
        )
        assert verifier.verify(receipt, record) is True

    def test_get_verify_key_bytes(self):
        signer = ReceiptSigner(signing_method="ed25519")
        key_bytes = signer.get_verify_key_bytes()
        assert len(key_bytes) == 32  # Ed25519 public key is 32 bytes

    def test_sign_batch(self):
        signer = ReceiptSigner(signing_method="ed25519")
        records = [_sample_record(), _sample_record()]
        receipts = signer.sign_batch(records)
        assert len(receipts) == 2

    def test_different_keys_different_signatures(self):
        s1 = ReceiptSigner(signing_method="ed25519", key_id="k1")
        s2 = ReceiptSigner(signing_method="ed25519", key_id="k2")
        record = _sample_record()
        r1 = s1.sign(record)
        r2 = s2.sign(record)
        # Signatures should be different (different keys)
        assert r1.split("|")[-1] != r2.split("|")[-1]


class TestReceiptSignerFallback:
    """Test fallback to HMAC when Ed25519 is requested but nacl is missing."""

    def test_fallback_when_nacl_unavailable(self, monkeypatch):
        import app.services.receipt_signer as mod

        original = mod._HAS_NACL
        monkeypatch.setattr(mod, "_HAS_NACL", False)
        signer = ReceiptSigner(signing_method="ed25519")
        assert signer.method == "hmac-sha256"
        monkeypatch.setattr(mod, "_HAS_NACL", original)


# ---------------------------------------------------------------------------
# APEP-257: ReceiptVerifier
# ---------------------------------------------------------------------------


class TestReceiptVerifier:
    """Tests for receipt verification."""

    def _make_signer_and_verifier(self):
        key = os.urandom(32)
        signer = ReceiptSigner(
            signing_method="hmac-sha256", private_key=key, key_id="v-k1"
        )
        verifier = ReceiptVerifier(
            verify_keys={"v-k1": ("hmac-sha256", signer.get_verify_key_bytes())}
        )
        return signer, verifier

    def test_verify_valid_receipt(self):
        signer, verifier = self._make_signer_and_verifier()
        record = _sample_record()
        receipt = signer.sign(record)
        assert verifier.verify(receipt, record) is True

    def test_verify_tampered_record_fails(self):
        signer, verifier = self._make_signer_and_verifier()
        record = _sample_record()
        receipt = signer.sign(record)
        record["decision"] = "DENY"  # tamper
        assert verifier.verify(receipt, record) is False

    def test_verify_tampered_signature_fails(self):
        signer, verifier = self._make_signer_and_verifier()
        record = _sample_record()
        receipt = signer.sign(record)
        parts = receipt.split("|")
        parts[-1] = "AAAA" + parts[-1][4:]  # corrupt signature
        corrupted = "|".join(parts)
        assert verifier.verify(corrupted, record) is False

    def test_verify_unknown_key_id_fails(self):
        signer = ReceiptSigner(
            signing_method="hmac-sha256", key_id="known"
        )
        verifier = ReceiptVerifier(
            verify_keys={"other": ("hmac-sha256", os.urandom(32))}
        )
        record = _sample_record()
        receipt = signer.sign(record)
        assert verifier.verify(receipt, record) is False

    def test_verify_invalid_format_fails(self):
        verifier = ReceiptVerifier()
        assert verifier.verify("not-a-valid-receipt", {}) is False

    def test_verify_wrong_version_fails(self):
        verifier = ReceiptVerifier()
        assert verifier.verify("bad-version|k|alg|hash|sig", {}) is False

    def test_verify_batch(self):
        signer, verifier = self._make_signer_and_verifier()
        rec1 = _sample_record()
        rec2 = _sample_record()
        rec2["decision_id"] = "d-002"
        r1 = signer.sign(rec1)
        r2 = signer.sign(rec2)

        results = verifier.verify_batch([(r1, rec1), (r2, rec2)])
        assert results == [True, True]

    def test_verify_batch_with_tampered(self):
        signer, verifier = self._make_signer_and_verifier()
        rec1 = _sample_record()
        rec2 = _sample_record()
        r1 = signer.sign(rec1)
        r2 = signer.sign(rec2)
        rec2["decision"] = "DENY"  # tamper rec2

        results = verifier.verify_batch([(r1, rec1), (r2, rec2)])
        assert results == [True, False]

    def test_load_key_from_file(self):
        import base64

        key = os.urandom(32)
        b64_key = base64.urlsafe_b64encode(key).decode()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
            f.write(f"hmac-sha256:{b64_key}")
            key_path = f.name

        try:
            verifier = ReceiptVerifier()
            verifier.load_key_from_file(key_path, key_id="file-key")

            signer = ReceiptSigner(
                signing_method="hmac-sha256", private_key=key, key_id="file-key"
            )
            record = _sample_record()
            receipt = signer.sign(record)
            assert verifier.verify(receipt, record) is True
        finally:
            os.unlink(key_path)

    def test_add_key(self):
        verifier = ReceiptVerifier()
        verifier.add_key("k1", "hmac-sha256", os.urandom(32))
        assert "k1" in verifier._keys

    @pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
    def test_verify_ed25519_receipt(self):
        signer = ReceiptSigner(signing_method="ed25519", key_id="ed-k1")
        verifier = ReceiptVerifier(
            verify_keys={"ed-k1": ("ed25519", signer.get_verify_key_bytes())}
        )
        record = _sample_record()
        receipt = signer.sign(record)
        assert verifier.verify(receipt, record) is True


# ---------------------------------------------------------------------------
# APEP-257: CLI tool
# ---------------------------------------------------------------------------


class TestVerifyReceiptsCLI:
    """Tests for the verify_receipts CLI tool."""

    def _make_test_data(self, records, tamper_index: int | None = None):
        """Create JSONL file and key file for testing.

        Returns (receipts_path, key_path).
        """
        import base64

        key = os.urandom(32)
        signer = ReceiptSigner(
            signing_method="hmac-sha256", private_key=key, key_id="default"
        )

        lines = []
        for i, record in enumerate(records):
            receipt = signer.sign(record)
            rec = dict(record)
            if tamper_index is not None and i == tamper_index:
                rec["decision"] = "TAMPERED"
            lines.append(json.dumps({"receipt": receipt, "record": rec}))

        receipts_fd, receipts_path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(receipts_fd, "w") as f:
            f.write("\n".join(lines) + "\n")

        b64_key = base64.urlsafe_b64encode(key).decode()
        key_fd, key_path = tempfile.mkstemp(suffix=".key")
        with os.fdopen(key_fd, "w") as f:
            f.write(f"hmac-sha256:{b64_key}")

        return receipts_path, key_path

    def test_cli_all_valid(self):
        from app.cli.verify_receipts import main

        records = [_sample_record(), _sample_record()]
        receipts_path, key_path = self._make_test_data(records)
        try:
            exit_code = main([
                "--receipts-file", receipts_path,
                "--key-file", key_path,
            ])
            assert exit_code == 0
        finally:
            os.unlink(receipts_path)
            os.unlink(key_path)

    def test_cli_some_invalid(self):
        from app.cli.verify_receipts import main

        records = [_sample_record(), _sample_record()]
        receipts_path, key_path = self._make_test_data(records, tamper_index=1)
        try:
            exit_code = main([
                "--receipts-file", receipts_path,
                "--key-file", key_path,
            ])
            assert exit_code == 1
        finally:
            os.unlink(receipts_path)
            os.unlink(key_path)

    def test_cli_missing_key_file(self):
        from app.cli.verify_receipts import main

        records = [_sample_record()]
        receipts_path, key_path = self._make_test_data(records)
        os.unlink(key_path)  # Remove key file
        try:
            exit_code = main([
                "--receipts-file", receipts_path,
                "--key-file", key_path,
            ])
            assert exit_code == 1
        finally:
            os.unlink(receipts_path)

    def test_cli_missing_receipts_file(self):
        from app.cli.verify_receipts import main

        _, key_path = self._make_test_data([_sample_record()])
        try:
            exit_code = main([
                "--receipts-file", "/nonexistent/path.jsonl",
                "--key-file", key_path,
            ])
            assert exit_code == 1
        finally:
            os.unlink(key_path)

    def test_cli_verbose_output(self, capsys):
        from app.cli.verify_receipts import main

        records = [_sample_record()]
        receipts_path, key_path = self._make_test_data(records)
        try:
            exit_code = main([
                "--receipts-file", receipts_path,
                "--key-file", key_path,
                "--verbose",
            ])
            assert exit_code == 0
            captured = capsys.readouterr()
            assert "OK" in captured.out
        finally:
            os.unlink(receipts_path)
            os.unlink(key_path)
