"""Tests for Sprint 39 — Receipt Chaining with Plan Root.

APEP-308: AuditDecision extended with plan_id and parent_receipt_id.
APEP-309: Per-receipt Ed25519 signing in AuditLogger.
APEP-310: ReceiptChainManager.
APEP-311: GET /v1/plans/{plan_id}/receipts — full receipt chain.
APEP-312: GET /v1/plans/{plan_id}/receipts/summary — chain summary.
APEP-313: OfflineReceiptVerifier.
APEP-314: CLI receipt verify-chain command.
APEP-315: Adversarial tests.
"""

import base64
import json
import os
import tempfile
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.models.policy import AuditDecision, Decision
from app.services.audit_logger import (
    ReceiptSigningKey,
    _canonical_receipt_payload,
    audit_logger,
    compute_record_hash,
)
from app.services.receipt_chain import (
    ReceiptChainEntry,
    ReceiptChainManager,
    ReceiptChainResponse,
    ReceiptChainSummary,
    receipt_chain_manager,
)

# Check if PyNaCl is available
_HAS_NACL = False
try:
    import nacl.signing  # type: ignore[import-untyped]

    _HAS_NACL = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_audit(**overrides) -> AuditDecision:
    """Create an AuditDecision with sensible defaults for testing."""
    defaults = {
        "session_id": "sess-001",
        "agent_id": "agent-alpha",
        "agent_role": "analyst",
        "tool_name": "file.read",
        "tool_args_hash": "abc123hash",
        "decision": Decision.ALLOW,
        "risk_score": 0.3,
        "latency_ms": 5,
    }
    defaults.update(overrides)
    return AuditDecision(**defaults)


def _make_plan_id() -> UUID:
    return uuid4()


# ---------------------------------------------------------------------------
# APEP-308: AuditDecision model extension tests
# ---------------------------------------------------------------------------


class TestAuditDecisionPlanFields:
    """Unit tests for plan_id, parent_receipt_id, receipt_signature fields."""

    def test_default_plan_fields_are_none(self):
        audit = _make_audit()
        assert audit.plan_id is None
        assert audit.parent_receipt_id is None
        assert audit.receipt_signature == ""

    def test_set_plan_id(self):
        plan_id = uuid4()
        audit = _make_audit(plan_id=plan_id)
        assert audit.plan_id == plan_id

    def test_set_parent_receipt_id(self):
        parent_id = uuid4()
        audit = _make_audit(parent_receipt_id=parent_id)
        assert audit.parent_receipt_id == parent_id

    def test_set_receipt_signature(self):
        audit = _make_audit(receipt_signature="sig_data_here")
        assert audit.receipt_signature == "sig_data_here"

    def test_plan_fields_in_model_dump(self):
        plan_id = uuid4()
        parent_id = uuid4()
        audit = _make_audit(plan_id=plan_id, parent_receipt_id=parent_id)
        data = audit.model_dump(mode="json")
        assert data["plan_id"] == str(plan_id)
        assert data["parent_receipt_id"] == str(parent_id)

    def test_plan_fields_included_in_hash(self):
        """plan_id and parent_receipt_id must affect record_hash."""
        audit1 = _make_audit()
        audit2 = _make_audit(plan_id=uuid4())
        audit1.sequence_number = 1
        audit2.sequence_number = 1
        audit1.timestamp = audit2.timestamp  # Ensure same timestamp

        h1 = compute_record_hash(audit1, "prev")
        h2 = compute_record_hash(audit2, "prev")
        assert h1 != h2

    def test_parent_receipt_id_affects_hash(self):
        ts = datetime.now(UTC)
        audit1 = _make_audit(timestamp=ts)
        audit2 = _make_audit(parent_receipt_id=uuid4(), timestamp=ts)
        audit1.sequence_number = 1
        audit2.sequence_number = 1
        audit1.decision_id = audit2.decision_id  # Same decision_id

        h1 = compute_record_hash(audit1, "prev")
        h2 = compute_record_hash(audit2, "prev")
        assert h1 != h2


# ---------------------------------------------------------------------------
# APEP-309: Per-receipt Ed25519 signing tests
# ---------------------------------------------------------------------------


class TestReceiptSigningKey:
    """Unit tests for ReceiptSigningKey helper."""

    @pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
    def test_generate_key(self):
        key = ReceiptSigningKey()
        assert key.available is True

    @pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
    def test_sign_returns_base64(self):
        key = ReceiptSigningKey()
        sig = key.sign(b"hello world")
        assert sig != ""
        # Should be valid base64
        decoded = base64.urlsafe_b64decode(sig)
        assert len(decoded) == 64  # Ed25519 signatures are 64 bytes

    @pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
    def test_verify_key_bytes(self):
        key = ReceiptSigningKey()
        vk = key.get_verify_key_bytes()
        assert len(vk) == 32  # Ed25519 public keys are 32 bytes

    @pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
    def test_sign_with_explicit_key(self):
        sk = nacl.signing.SigningKey.generate()
        key = ReceiptSigningKey(private_key=bytes(sk))
        sig = key.sign(b"test data")
        assert sig != ""

    def test_no_nacl_key_not_available(self):
        """When constructed without NaCl, sign returns empty."""
        key = ReceiptSigningKey.__new__(ReceiptSigningKey)
        key._signing_key = None
        assert key.available is False
        assert key.sign(b"data") == ""
        assert key.get_verify_key_bytes() == b""


@pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
class TestPerReceiptSigningInAuditLogger:
    """Integration tests for per-receipt Ed25519 signing in AuditLogger."""

    @pytest.mark.asyncio
    async def test_signing_disabled_by_default(self):
        audit_logger.reset()
        assert audit_logger.receipt_signing_enabled is False

    @pytest.mark.asyncio
    async def test_configure_receipt_signing(self):
        audit_logger.reset()
        audit_logger.configure_receipt_signing()
        assert audit_logger.receipt_signing_enabled is True

    @pytest.mark.asyncio
    async def test_append_signs_receipt(self):
        audit_logger.reset()
        audit_logger.configure_receipt_signing()

        audit = _make_audit()
        result = await audit_logger.append(audit)

        assert result.receipt_signature != ""
        # Verify the signature
        vk = audit_logger.get_receipt_verify_key()
        assert len(vk) == 32

        canonical = _canonical_receipt_payload(result)
        verify_key = nacl.signing.VerifyKey(vk)
        sig = base64.urlsafe_b64decode(result.receipt_signature)
        verify_key.verify(canonical, sig)  # Should not raise

    @pytest.mark.asyncio
    async def test_append_without_signing(self):
        audit_logger.reset()
        # No signing configured

        audit = _make_audit()
        result = await audit_logger.append(audit)

        assert result.receipt_signature == ""

    @pytest.mark.asyncio
    async def test_signed_receipt_with_plan_fields(self):
        audit_logger.reset()
        audit_logger.configure_receipt_signing()

        plan_id = uuid4()
        parent_id = uuid4()
        audit = _make_audit(plan_id=plan_id, parent_receipt_id=parent_id)
        result = await audit_logger.append(audit)

        assert result.receipt_signature != ""
        assert result.plan_id == plan_id
        assert result.parent_receipt_id == parent_id

        # Verify
        vk = audit_logger.get_receipt_verify_key()
        canonical = _canonical_receipt_payload(result)
        verify_key = nacl.signing.VerifyKey(vk)
        sig = base64.urlsafe_b64decode(result.receipt_signature)
        verify_key.verify(canonical, sig)


# ---------------------------------------------------------------------------
# APEP-310: ReceiptChainManager tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestReceiptChainManager:
    """Unit tests for ReceiptChainManager."""

    async def test_empty_chain(self):
        plan_id = uuid4()
        chain = await receipt_chain_manager.get_chain(plan_id)
        assert chain.plan_id == plan_id
        assert chain.total_receipts == 0
        assert chain.chain_valid is True
        assert chain.receipts == []

    async def test_get_chain_with_receipts(self):
        plan_id = uuid4()
        audit_logger.reset()

        # Insert some audit records with plan_id
        for i in range(3):
            audit = _make_audit(plan_id=plan_id, tool_name=f"tool.{i}")
            await audit_logger.append(audit)

        chain = await receipt_chain_manager.get_chain(plan_id)
        assert chain.plan_id == plan_id
        assert chain.total_receipts == 3
        assert chain.chain_valid is True
        assert len(chain.receipts) == 3

    async def test_chain_only_includes_plan_receipts(self):
        plan_id = uuid4()
        other_plan_id = uuid4()
        audit_logger.reset()

        # Insert records for different plans
        await audit_logger.append(_make_audit(plan_id=plan_id))
        await audit_logger.append(_make_audit(plan_id=other_plan_id))
        await audit_logger.append(_make_audit(plan_id=plan_id))

        chain = await receipt_chain_manager.get_chain(plan_id)
        assert chain.total_receipts == 2

    async def test_chain_ordered_by_sequence(self):
        plan_id = uuid4()
        audit_logger.reset()

        await audit_logger.append(_make_audit(plan_id=plan_id, tool_name="first"))
        await audit_logger.append(_make_audit(plan_id=plan_id, tool_name="second"))
        await audit_logger.append(_make_audit(plan_id=plan_id, tool_name="third"))

        chain = await receipt_chain_manager.get_chain(plan_id)
        assert chain.receipts[0].tool_name == "first"
        assert chain.receipts[1].tool_name == "second"
        assert chain.receipts[2].tool_name == "third"

    async def test_verify_chain(self):
        plan_id = uuid4()
        audit_logger.reset()

        for _ in range(5):
            await audit_logger.append(_make_audit(plan_id=plan_id))

        report = await receipt_chain_manager.verify_chain(plan_id)
        assert report["chain_valid"] is True
        assert report["total_receipts"] == 5
        assert report["verified"] == 5


# ---------------------------------------------------------------------------
# APEP-312: ReceiptChainSummary tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestReceiptChainSummary:
    """Tests for receipt chain summary computation."""

    async def test_empty_summary(self):
        plan_id = uuid4()
        summary = await receipt_chain_manager.get_summary(plan_id)
        assert summary.plan_id == plan_id
        assert summary.total_receipts == 0
        assert summary.first_timestamp is None
        assert summary.last_timestamp is None

    async def test_summary_with_receipts(self):
        plan_id = uuid4()
        audit_logger.reset()

        await audit_logger.append(
            _make_audit(plan_id=plan_id, agent_id="a1", tool_name="t1", decision=Decision.ALLOW)
        )
        await audit_logger.append(
            _make_audit(plan_id=plan_id, agent_id="a2", tool_name="t2", decision=Decision.DENY)
        )
        await audit_logger.append(
            _make_audit(plan_id=plan_id, agent_id="a1", tool_name="t1", decision=Decision.ALLOW)
        )

        summary = await receipt_chain_manager.get_summary(plan_id)
        assert summary.total_receipts == 3
        assert summary.decision_counts.get("ALLOW") == 2
        assert summary.decision_counts.get("DENY") == 1
        assert sorted(summary.unique_agents) == ["a1", "a2"]
        assert sorted(summary.unique_tools) == ["t1", "t2"]
        assert summary.first_timestamp is not None
        assert summary.last_timestamp is not None
        assert summary.chain_valid is True

    async def test_summary_chain_depth_with_parent_linkage(self):
        plan_id = uuid4()
        audit_logger.reset()

        # Create a chain: root -> child -> grandchild
        root = _make_audit(plan_id=plan_id)
        root = await audit_logger.append(root)

        child = _make_audit(plan_id=plan_id, parent_receipt_id=root.decision_id)
        child = await audit_logger.append(child)

        grandchild = _make_audit(plan_id=plan_id, parent_receipt_id=child.decision_id)
        await audit_logger.append(grandchild)

        summary = await receipt_chain_manager.get_summary(plan_id)
        assert summary.chain_depth == 3  # root(1) + child(2) + grandchild(3)

    async def test_summary_total_risk(self):
        plan_id = uuid4()
        audit_logger.reset()

        await audit_logger.append(_make_audit(plan_id=plan_id, risk_score=0.2))
        await audit_logger.append(_make_audit(plan_id=plan_id, risk_score=0.5))
        await audit_logger.append(_make_audit(plan_id=plan_id, risk_score=0.1))

        summary = await receipt_chain_manager.get_summary(plan_id)
        assert abs(summary.total_risk - 0.8) < 0.001


# ---------------------------------------------------------------------------
# APEP-311/312: API Endpoint Integration Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestReceiptChainAPI:
    """Integration tests for receipt chain API endpoints."""

    def _get_headers(self) -> dict[str, str]:
        from tests.conftest import _get_auth_headers

        return _get_auth_headers()

    async def _create_plan(self, client: AsyncClient) -> str:
        """Helper to create a plan and return its plan_id."""
        import app.services.plan_signer as ps_mod
        from app.services.plan_signer import PlanSigner

        if ps_mod.plan_signer is None:
            ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        resp = await client.post(
            "/v1/plans",
            json={
                "action": "Test receipt chain",
                "issuer": "test@example.com",
                "scope": ["read:public:*"],
            },
            headers=self._get_headers(),
        )
        assert resp.status_code == 201
        return resp.json()["plan_id"]

    async def test_get_receipts_plan_not_found(self):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                f"/v1/plans/{uuid4()}/receipts",
                headers=self._get_headers(),
            )
            assert resp.status_code == 404

    async def test_get_receipts_empty_chain(self):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            plan_id = await self._create_plan(client)
            resp = await client.get(
                f"/v1/plans/{plan_id}/receipts",
                headers=self._get_headers(),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["plan_id"] == plan_id
            assert data["total_receipts"] == 0

    async def test_get_receipts_with_data(self):
        from app.main import app

        audit_logger.reset()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            plan_id = await self._create_plan(client)

            # Insert audit records with matching plan_id
            for i in range(3):
                await audit_logger.append(
                    _make_audit(plan_id=UUID(plan_id), tool_name=f"tool.{i}")
                )

            resp = await client.get(
                f"/v1/plans/{plan_id}/receipts",
                headers=self._get_headers(),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_receipts"] == 3
            assert len(data["receipts"]) == 3

    async def test_get_summary_plan_not_found(self):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                f"/v1/plans/{uuid4()}/receipts/summary",
                headers=self._get_headers(),
            )
            assert resp.status_code == 404

    async def test_get_summary_with_data(self):
        from app.main import app

        audit_logger.reset()

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            plan_id = await self._create_plan(client)

            await audit_logger.append(
                _make_audit(
                    plan_id=UUID(plan_id),
                    agent_id="bot-1",
                    decision=Decision.ALLOW,
                    risk_score=0.25,
                )
            )
            await audit_logger.append(
                _make_audit(
                    plan_id=UUID(plan_id),
                    agent_id="bot-2",
                    decision=Decision.DENY,
                    risk_score=0.75,
                )
            )

            resp = await client.get(
                f"/v1/plans/{plan_id}/receipts/summary",
                headers=self._get_headers(),
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_receipts"] == 2
            assert "ALLOW" in data["decision_counts"]
            assert "DENY" in data["decision_counts"]
            assert set(data["unique_agents"]) == {"bot-1", "bot-2"}


# ---------------------------------------------------------------------------
# APEP-313: OfflineReceiptVerifier tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
class TestOfflineReceiptVerifier:
    """Unit tests for OfflineReceiptVerifier."""

    def _make_signed_record(self, signing_key, **overrides):
        """Create a signed audit record dict.

        Signs using the AuditDecision model (same as AuditLogger) then
        exports as dict for offline verification.
        """
        audit = _make_audit(**overrides)
        audit.sequence_number = overrides.get("sequence_number", 1)
        audit.record_hash = "fakehash123"
        audit.previous_hash = "prevhash"

        # Sign using the model-based canonical function (the source of truth)
        canonical = _canonical_receipt_payload(audit)
        signed = signing_key.sign(canonical)
        sig_b64 = base64.urlsafe_b64encode(signed.signature).decode()

        # Export to dict — timestamps get serialised differently
        record = audit.model_dump(mode="json")
        record["receipt_signature"] = sig_b64
        # Normalize timestamp to match what _canonical_receipt_payload produces
        # (the model uses .isoformat() which gives +00:00, model_dump gives Z)
        record["timestamp"] = audit.timestamp.isoformat()
        return record

    def test_verify_valid_receipt(self):
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)

        verifier = OfflineReceiptVerifier(verify_key=vk)
        record = self._make_signed_record(sk)
        assert verifier.verify_receipt(record) is True

    def test_verify_invalid_signature(self):
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        other_sk = nacl.signing.SigningKey.generate()
        vk = bytes(other_sk.verify_key)  # Wrong key

        verifier = OfflineReceiptVerifier(verify_key=vk)
        record = self._make_signed_record(sk)
        assert verifier.verify_receipt(record) is False

    def test_verify_missing_signature(self):
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)

        verifier = OfflineReceiptVerifier(verify_key=vk)
        record = _make_audit().model_dump(mode="json")
        record["receipt_signature"] = ""
        assert verifier.verify_receipt(record) is False

    def test_verify_chain_all_valid(self):
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)

        verifier = OfflineReceiptVerifier(verify_key=vk)

        records = []
        prev_id = None
        for i in range(3):
            record = self._make_signed_record(
                sk,
                plan_id=uuid4(),
                parent_receipt_id=prev_id,
                sequence_number=i + 1,
            )
            records.append(record)
            prev_id = UUID(record["decision_id"])

        report = verifier.verify_chain(records)
        assert report["total"] == 3
        assert report["valid_signatures"] == 3
        assert report["invalid_signatures"] == 0
        assert report["chain_intact"] is True

    def test_verify_chain_with_tampered_record(self):
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)

        verifier = OfflineReceiptVerifier(verify_key=vk)

        record = self._make_signed_record(sk, sequence_number=1)
        # Tamper with the record after signing
        record["risk_score"] = 0.99

        report = verifier.verify_chain([record])
        assert report["invalid_signatures"] == 1
        assert report["valid_signatures"] == 0

    def test_verify_chain_broken_linkage(self):
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)

        verifier = OfflineReceiptVerifier(verify_key=vk)

        # First record — no parent
        r1 = self._make_signed_record(sk, sequence_number=1)
        # Second record — references unknown parent
        r2 = self._make_signed_record(
            sk,
            sequence_number=2,
            parent_receipt_id=uuid4(),  # Non-existent parent
        )

        report = verifier.verify_chain([r1, r2])
        assert report["chain_intact"] is False

    def test_load_key_from_file(self):
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)
        b64_key = base64.urlsafe_b64encode(vk).decode()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
            f.write(f"ed25519:{b64_key}")
            f.flush()
            key_path = f.name

        try:
            verifier = OfflineReceiptVerifier()
            verifier.load_key_from_file(key_path)
            record = self._make_signed_record(sk)
            assert verifier.verify_receipt(record) is True
        finally:
            os.unlink(key_path)


# ---------------------------------------------------------------------------
# APEP-314: CLI verify-chain tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
class TestCLIVerifyChain:
    """Tests for the agentpep receipt verify-chain CLI command."""

    def _make_signed_records(self, sk, plan_id, count=3):
        records = []
        prev_id = None
        for i in range(count):
            audit = _make_audit(plan_id=plan_id, parent_receipt_id=prev_id)
            audit.sequence_number = i + 1
            audit.record_hash = f"hash_{i}"
            audit.previous_hash = f"hash_{i - 1}" if i > 0 else ""

            canonical = _canonical_receipt_payload(audit)
            signed = sk.sign(canonical)
            sig_b64 = base64.urlsafe_b64encode(signed.signature).decode()

            record = audit.model_dump(mode="json")
            record["receipt_signature"] = sig_b64
            # Normalize timestamp to match the signing canonical format
            record["timestamp"] = audit.timestamp.isoformat()
            records.append(record)
            prev_id = audit.decision_id
        return records

    def test_verify_chain_from_file(self):
        from agentpep.receipt_verify import verify_chain_cli

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)
        plan_id = str(uuid4())

        records = self._make_signed_records(sk, UUID(plan_id))

        # Write receipts file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as rf:
            json.dump({"plan_id": plan_id, "receipts": records}, rf, default=str)
            receipts_path = rf.name

        # Write key file
        b64_key = base64.urlsafe_b64encode(vk).decode()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".key", delete=False
        ) as kf:
            kf.write(f"ed25519:{b64_key}")
            key_path = kf.name

        try:
            rc = verify_chain_cli(
                plan_id=plan_id,
                receipts_file=receipts_path,
                key_file=key_path,
                verbose=True,
            )
            assert rc == 0
        finally:
            os.unlink(receipts_path)
            os.unlink(key_path)

    def test_verify_chain_export(self):
        from agentpep.receipt_verify import verify_chain_cli

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)
        plan_id = str(uuid4())

        records = self._make_signed_records(sk, UUID(plan_id))

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as rf:
            json.dump({"plan_id": plan_id, "receipts": records}, rf, default=str)
            receipts_path = rf.name

        b64_key = base64.urlsafe_b64encode(vk).decode()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".key", delete=False
        ) as kf:
            kf.write(f"ed25519:{b64_key}")
            key_path = kf.name

        export_path = tempfile.mktemp(suffix=".json")

        try:
            rc = verify_chain_cli(
                plan_id=plan_id,
                receipts_file=receipts_path,
                key_file=key_path,
                export_path=export_path,
            )
            assert rc == 0
            # Verify exported file
            with open(export_path) as f:
                exported = json.load(f)
            assert exported["plan_id"] == plan_id
            assert len(exported["receipts"]) == 3
        finally:
            os.unlink(receipts_path)
            os.unlink(key_path)
            if os.path.exists(export_path):
                os.unlink(export_path)

    def test_verify_chain_missing_file(self):
        from agentpep.receipt_verify import verify_chain_cli

        rc = verify_chain_cli(
            plan_id=str(uuid4()),
            receipts_file="/nonexistent/path.json",
        )
        assert rc == 1

    def test_verify_chain_invalid_key_file(self):
        from agentpep.receipt_verify import verify_chain_cli

        sk = nacl.signing.SigningKey.generate()
        plan_id = str(uuid4())

        # Create some receipts so we actually try to load the key
        records = self._make_signed_records(sk, UUID(plan_id), count=1)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as rf:
            json.dump({"receipts": records}, rf, default=str)
            receipts_path = rf.name

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".key", delete=False
        ) as kf:
            kf.write("invalid_format")
            key_path = kf.name

        try:
            rc = verify_chain_cli(
                plan_id=plan_id,
                receipts_file=receipts_path,
                key_file=key_path,
            )
            assert rc == 1
        finally:
            os.unlink(receipts_path)
            os.unlink(key_path)

    def test_cli_parser_verify_chain(self):
        """Test that the CLI parser accepts verify-chain subcommand."""
        from agentpep.cli import build_parser

        parser = build_parser()
        args = parser.parse_args([
            "receipt", "verify-chain",
            "--plan", str(uuid4()),
            "--receipts-file", "chain.json",
            "--key-file", "key.pem",
            "--export", "output.json",
            "--verbose",
        ])
        assert args.receipt_command == "verify-chain"
        assert args.receipts_file == "chain.json"
        assert args.key_file == "key.pem"
        assert args.export == "output.json"
        assert args.verbose is True


# ---------------------------------------------------------------------------
# APEP-315: Adversarial tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
class TestReceiptChainAdversarial:
    """Adversarial tests for receipt chain security."""

    def test_signature_replay_different_record(self):
        """Replaying a valid signature on a different record must fail."""
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)

        # Sign record A
        audit_a = _make_audit(tool_name="original.tool")
        audit_a.sequence_number = 1
        audit_a.record_hash = "hash_a"
        canonical_a = _canonical_receipt_payload(audit_a)
        sig_a = base64.urlsafe_b64encode(sk.sign(canonical_a).signature).decode()

        # Create record B with different data but replay sig from A
        audit_b = _make_audit(tool_name="malicious.tool")
        audit_b.sequence_number = 1
        audit_b.record_hash = "hash_b"
        record_b = audit_b.model_dump(mode="json")
        record_b["receipt_signature"] = sig_a

        verifier = OfflineReceiptVerifier(verify_key=vk)
        assert verifier.verify_receipt(record_b) is False

    def test_tampered_timestamp(self):
        """Modifying the timestamp after signing must invalidate."""
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)

        audit = _make_audit()
        audit.sequence_number = 1
        audit.record_hash = "hash"
        canonical = _canonical_receipt_payload(audit)
        sig = base64.urlsafe_b64encode(sk.sign(canonical).signature).decode()

        record = audit.model_dump(mode="json")
        record["receipt_signature"] = sig
        # Tamper: change timestamp
        record["timestamp"] = "2099-01-01T00:00:00"

        verifier = OfflineReceiptVerifier(verify_key=vk)
        assert verifier.verify_receipt(record) is False

    def test_tampered_decision(self):
        """Changing DENY to ALLOW after signing must fail verification."""
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)

        audit = _make_audit(decision=Decision.DENY)
        audit.sequence_number = 1
        audit.record_hash = "hash"
        canonical = _canonical_receipt_payload(audit)
        sig = base64.urlsafe_b64encode(sk.sign(canonical).signature).decode()

        record = audit.model_dump(mode="json")
        record["receipt_signature"] = sig
        # Tamper: flip decision
        record["decision"] = "ALLOW"

        verifier = OfflineReceiptVerifier(verify_key=vk)
        assert verifier.verify_receipt(record) is False

    def test_tampered_plan_id(self):
        """Changing plan_id after signing must fail."""
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)

        original_plan = uuid4()
        audit = _make_audit(plan_id=original_plan)
        audit.sequence_number = 1
        audit.record_hash = "hash"
        canonical = _canonical_receipt_payload(audit)
        sig = base64.urlsafe_b64encode(sk.sign(canonical).signature).decode()

        record = audit.model_dump(mode="json")
        record["receipt_signature"] = sig
        # Tamper: swap plan_id
        record["plan_id"] = str(uuid4())

        verifier = OfflineReceiptVerifier(verify_key=vk)
        assert verifier.verify_receipt(record) is False

    def test_tampered_parent_receipt_id(self):
        """Changing parent_receipt_id after signing must fail."""
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)

        audit = _make_audit(parent_receipt_id=uuid4())
        audit.sequence_number = 1
        audit.record_hash = "hash"
        canonical = _canonical_receipt_payload(audit)
        sig = base64.urlsafe_b64encode(sk.sign(canonical).signature).decode()

        record = audit.model_dump(mode="json")
        record["receipt_signature"] = sig
        # Tamper: swap parent
        record["parent_receipt_id"] = str(uuid4())

        verifier = OfflineReceiptVerifier(verify_key=vk)
        assert verifier.verify_receipt(record) is False

    def test_forged_signature_bytes(self):
        """Random signature bytes must fail verification."""
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)

        audit = _make_audit()
        audit.sequence_number = 1
        audit.record_hash = "hash"
        record = audit.model_dump(mode="json")
        # Use random bytes as signature
        record["receipt_signature"] = base64.urlsafe_b64encode(os.urandom(64)).decode()

        verifier = OfflineReceiptVerifier(verify_key=vk)
        assert verifier.verify_receipt(record) is False

    def test_wrong_key_verification(self):
        """Verifying with a different key must fail."""
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        wrong_sk = nacl.signing.SigningKey.generate()

        audit = _make_audit()
        audit.sequence_number = 1
        audit.record_hash = "hash"
        canonical = _canonical_receipt_payload(audit)
        sig = base64.urlsafe_b64encode(sk.sign(canonical).signature).decode()

        record = audit.model_dump(mode="json")
        record["receipt_signature"] = sig

        # Use wrong verify key
        verifier = OfflineReceiptVerifier(verify_key=bytes(wrong_sk.verify_key))
        assert verifier.verify_receipt(record) is False

    def test_chain_with_orphaned_parent(self):
        """Receipt referencing a non-existent parent should break chain integrity."""
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        sk = nacl.signing.SigningKey.generate()
        vk = bytes(sk.verify_key)

        # Create a record that claims a parent not in the chain
        audit = _make_audit(parent_receipt_id=uuid4())
        audit.sequence_number = 1
        audit.record_hash = "hash"
        canonical = _canonical_receipt_payload(audit)
        sig = base64.urlsafe_b64encode(sk.sign(canonical).signature).decode()

        record = audit.model_dump(mode="json")
        record["receipt_signature"] = sig

        verifier = OfflineReceiptVerifier(verify_key=vk)
        report = verifier.verify_chain([record])
        assert report["chain_intact"] is False

    @pytest.mark.asyncio
    async def test_per_receipt_sig_roundtrip_with_chain_manager(self):
        """Full integration: sign receipts, retrieve chain, verify offline."""
        audit_logger.reset()
        audit_logger.configure_receipt_signing()

        plan_id = uuid4()
        root = await audit_logger.append(
            _make_audit(plan_id=plan_id, tool_name="step.1")
        )
        child = await audit_logger.append(
            _make_audit(
                plan_id=plan_id,
                parent_receipt_id=root.decision_id,
                tool_name="step.2",
            )
        )
        grandchild = await audit_logger.append(
            _make_audit(
                plan_id=plan_id,
                parent_receipt_id=child.decision_id,
                tool_name="step.3",
            )
        )

        # Retrieve chain via manager
        chain = await receipt_chain_manager.get_chain(plan_id)
        assert chain.total_receipts == 3

        # Convert to dicts for offline verification
        from app.db import mongodb as db_module

        db = db_module.get_database()
        cursor = db[db_module.AUDIT_DECISIONS].find(
            {"plan_id": str(plan_id)}
        ).sort("sequence_number", 1)
        raw_records = []
        async for doc in cursor:
            doc.pop("_id", None)
            raw_records.append(doc)

        # Verify offline
        from app.services.offline_receipt_verifier import OfflineReceiptVerifier

        vk = audit_logger.get_receipt_verify_key()
        verifier = OfflineReceiptVerifier(verify_key=vk)
        report = verifier.verify_chain(raw_records)
        assert report["total"] == 3
        assert report["valid_signatures"] == 3
        assert report["chain_intact"] is True
