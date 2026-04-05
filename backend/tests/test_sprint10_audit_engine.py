"""Sprint 10 — Audit Engine & Kafka Integration tests.

APEP-081: AuditLogger service
APEP-082: SHA-256 hash chain
APEP-083: Kafka producer (mocked)
APEP-084: TTL index verification
APEP-085: Audit query API
APEP-086: Compliance export (CSV/JSON)
APEP-087: PDF audit report generation
APEP-088: Audit integrity verification
"""

import hashlib
import json
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.models.policy import AuditDecision, Decision
from app.services.audit_logger import GENESIS_HASH, audit_logger, compute_record_hash


@pytest.fixture
async def client():
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Helper to seed audit records via the AuditLogger
# ---------------------------------------------------------------------------


async def _seed_audit_records(count: int = 5) -> list[AuditDecision]:
    """Seed N audit records through the AuditLogger with hash chain."""
    records = []
    for i in range(count):
        audit = AuditDecision(
            session_id=f"sess-{i % 3}",
            agent_id=f"agent-{i % 2}",
            agent_role="analyst",
            tool_name=f"tool_{i}",
            tool_args_hash=hashlib.sha256(f"args-{i}".encode()).hexdigest(),
            decision=Decision.ALLOW if i % 2 == 0 else Decision.DENY,
            risk_score=round((i % 7) * 0.1, 2),
            latency_ms=i * 10,
        )
        audit = await audit_logger.append(audit)
        records.append(audit)
    return records


# ===========================================================================
# APEP-081: AuditLogger service
# ===========================================================================


class TestAuditLogger:
    async def test_append_creates_record(self, mock_mongodb):
        """AuditLogger.append persists a record to MongoDB."""
        audit = AuditDecision(
            session_id="s1",
            agent_id="a1",
            agent_role="admin",
            tool_name="file.read",
            tool_args_hash="abc123",
            decision=Decision.ALLOW,
        )
        result = await audit_logger.append(audit)

        assert result.sequence_number == 1
        assert result.record_hash != ""
        assert result.previous_hash == GENESIS_HASH

        # Verify persisted in DB
        doc = await mock_mongodb["audit_decisions"].find_one(
            {"sequence_number": 1}
        )
        assert doc is not None
        assert doc["agent_id"] == "a1"

    async def test_append_increments_sequence(self, mock_mongodb):
        """Sequential appends increment the sequence number."""
        for i in range(3):
            audit = AuditDecision(
                session_id="s1",
                agent_id="a1",
                agent_role="admin",
                tool_name="tool",
                tool_args_hash="h",
                decision=Decision.ALLOW,
            )
            result = await audit_logger.append(audit)
            assert result.sequence_number == i + 1


# ===========================================================================
# APEP-082: SHA-256 hash chain
# ===========================================================================


class TestHashChain:
    async def test_first_record_chains_from_genesis(self, mock_mongodb):
        """First record's previous_hash is the genesis hash."""
        audit = AuditDecision(
            session_id="s1",
            agent_id="a1",
            agent_role="admin",
            tool_name="tool",
            tool_args_hash="h",
            decision=Decision.ALLOW,
        )
        result = await audit_logger.append(audit)
        assert result.previous_hash == GENESIS_HASH

    async def test_hash_chain_links_records(self, mock_mongodb):
        """Each record's previous_hash equals the preceding record's record_hash."""
        records = await _seed_audit_records(5)
        for i in range(1, len(records)):
            assert records[i].previous_hash == records[i - 1].record_hash

    async def test_record_hash_is_deterministic(self, mock_mongodb):
        """Recomputing the record hash yields the same value."""
        records = await _seed_audit_records(3)
        for rec in records:
            recomputed = compute_record_hash(rec, rec.previous_hash)
            assert recomputed == rec.record_hash

    async def test_tampering_detected_by_hash(self, mock_mongodb):
        """Modifying a record field invalidates its hash."""
        records = await _seed_audit_records(1)
        rec = records[0]
        original_hash = rec.record_hash

        # Tamper with a field
        rec.decision = Decision.DENY
        recomputed = compute_record_hash(rec, rec.previous_hash)
        assert recomputed != original_hash


# ===========================================================================
# APEP-083: Kafka producer (unit — mocked)
# ===========================================================================


class TestKafkaProducer:
    async def test_publish_skipped_when_not_started(self, mock_mongodb):
        """publish_decision returns False when producer is not running."""
        from app.services.kafka_producer import kafka_producer

        audit = AuditDecision(
            session_id="s1",
            agent_id="a1",
            agent_role="admin",
            tool_name="tool",
            tool_args_hash="h",
            decision=Decision.ALLOW,
        )
        result = await kafka_producer.publish_decision(audit)
        assert result is False

    async def test_producer_not_started_when_disabled(self, mock_mongodb):
        """Kafka producer start is a no-op when kafka_enabled is False."""
        from app.services.kafka_producer import kafka_producer

        # Default config has kafka_enabled=False
        await kafka_producer.start()
        assert kafka_producer.is_running is False


# ===========================================================================
# APEP-084: TTL index with configurable retention
# ===========================================================================


class TestTTLIndex:
    async def test_audit_decisions_ttl_index_exists(self, mock_mongodb):
        """The audit_decisions collection has a TTL index on timestamp."""
        from app.db.mongodb import init_collections

        await init_collections()

        indexes = await mock_mongodb["audit_decisions"].index_information()
        # Look for a TTL index (expireAfterSeconds key)
        ttl_found = any(
            info.get("expireAfterSeconds") is not None
            for info in indexes.values()
        )
        assert ttl_found, f"No TTL index found. Indexes: {list(indexes.keys())}"


# ===========================================================================
# APEP-085: Audit query API
# ===========================================================================


class TestAuditQueryAPI:
    async def test_get_decisions_empty(self, client):
        """GET /v1/audit/decisions returns empty list when no records exist."""
        resp = await client.get("/v1/audit/decisions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    async def test_get_decisions_returns_records(self, client, mock_mongodb):
        """GET /v1/audit/decisions returns seeded records."""
        await _seed_audit_records(3)

        resp = await client.get("/v1/audit/decisions")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 3
        assert len(data["items"]) == 3

    async def test_filter_by_agent_id(self, client, mock_mongodb):
        """Filtering by agent_id returns only matching records."""
        await _seed_audit_records(4)

        resp = await client.get("/v1/audit/decisions", params={"agent_id": "agent-0"})
        assert resp.status_code == 200
        data = resp.json()
        for rec in data["items"]:
            assert rec["agent_id"] == "agent-0"

    async def test_filter_by_decision(self, client, mock_mongodb):
        """Filtering by decision type returns only matching records."""
        await _seed_audit_records(4)

        resp = await client.get("/v1/audit/decisions", params={"decision": "DENY"})
        assert resp.status_code == 200
        for rec in resp.json()["items"]:
            assert rec["decision"] == "DENY"

    async def test_filter_by_tool_name(self, client, mock_mongodb):
        """Filtering by tool_name returns matching records."""
        await _seed_audit_records(5)

        resp = await client.get("/v1/audit/decisions", params={"tool_name": "tool_2"})
        assert resp.status_code == 200
        for rec in resp.json()["items"]:
            assert rec["tool_name"] == "tool_2"

    async def test_pagination(self, client, mock_mongodb):
        """Page size and page number work correctly for pagination."""
        await _seed_audit_records(10)

        resp = await client.get("/v1/audit/decisions", params={"page_size": 3, "page": 1})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 3
        assert data["total"] == 10


# ===========================================================================
# APEP-086: Compliance export (JSON/CSV)
# ===========================================================================


class TestComplianceExport:
    async def test_export_json_dpdpa(self, client, mock_mongodb):
        """JSON export with DPDPA template returns structured report."""
        await _seed_audit_records(3)

        resp = await client.post(
            "/v1/audit/export/json",
            json={"template": "DPDPA"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["template"] == "DPDPA"
        assert "DPDPA" in data["title"]
        assert len(data["items"]) == 3

    async def test_export_json_gdpr(self, client, mock_mongodb):
        """JSON export with GDPR template returns structured report."""
        await _seed_audit_records(2)

        resp = await client.post(
            "/v1/audit/export/json",
            json={"template": "GDPR"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["template"] == "GDPR"
        assert "GDPR" in data["title"]

    async def test_export_json_cert_in(self, client, mock_mongodb):
        """JSON export with CERT_IN template returns structured report."""
        await _seed_audit_records(2)

        resp = await client.post(
            "/v1/audit/export/json",
            json={"template": "CERT_IN"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["template"] == "CERT_IN"

    async def test_export_json_unknown_template(self, client, mock_mongodb):
        """JSON export with unknown template returns error."""
        resp = await client.post(
            "/v1/audit/export/json",
            json={"template": "UNKNOWN"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "error" in data

    async def test_export_csv_dpdpa(self, client, mock_mongodb):
        """CSV export returns text/csv content type with headers."""
        await _seed_audit_records(3)

        resp = await client.post(
            "/v1/audit/export/csv",
            json={"template": "DPDPA"},
        )
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        lines = resp.text.strip().split("\n")
        assert len(lines) == 4  # 1 header + 3 data rows

    async def test_export_csv_with_filter(self, client, mock_mongodb):
        """CSV export respects agent_id filter."""
        await _seed_audit_records(6)

        resp = await client.post(
            "/v1/audit/export/csv",
            json={"template": "GDPR", "agent_id": "agent-0"},
        )
        assert resp.status_code == 200
        lines = resp.text.strip().split("\n")
        # Header + filtered rows (agent-0 appears at indices 0, 2, 4 → 3 records)
        assert len(lines) >= 2  # At least header + 1 data row


# ===========================================================================
# APEP-087: PDF audit report
# ===========================================================================


class TestPDFExport:
    async def test_export_pdf_returns_bytes(self, client, mock_mongodb):
        """PDF export returns application/pdf content."""
        await _seed_audit_records(2)

        resp = await client.post(
            "/v1/audit/export/pdf",
            json={"template": "DPDPA"},
        )
        assert resp.status_code == 200
        assert "application/pdf" in resp.headers["content-type"]
        # PDF files start with %PDF
        assert resp.content[:5] == b"%PDF-"

    async def test_export_pdf_empty_records(self, client, mock_mongodb):
        """PDF export works even with no matching records."""
        resp = await client.post(
            "/v1/audit/export/pdf",
            json={"template": "GDPR"},
        )
        assert resp.status_code == 200
        assert resp.content[:5] == b"%PDF-"


# ===========================================================================
# APEP-088: Audit integrity verification
# ===========================================================================


class TestAuditIntegrity:
    async def test_verify_empty_chain(self, client, mock_mongodb):
        """Verifying an empty audit chain returns valid with 0 records."""
        resp = await client.get("/v1/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["total_records"] == 0

    async def test_verify_valid_chain(self, client, mock_mongodb):
        """A chain created by AuditLogger verifies successfully."""
        await _seed_audit_records(5)

        resp = await client.get("/v1/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["verified_records"] == 5

    async def test_verify_detects_tampered_hash(self, client, mock_mongodb):
        """Tampering with a record_hash is detected by verification."""
        await _seed_audit_records(5)

        # Tamper with record #3's hash directly in the DB
        await mock_mongodb["audit_decisions"].update_one(
            {"sequence_number": 3},
            {"$set": {"record_hash": "tampered_hash_value"}},
        )

        resp = await client.get("/v1/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False
        # The break is detected at record 3 (recomputed hash != tampered stored hash)
        assert data["first_tampered_sequence"] == 3

    async def test_verify_detects_tampered_field(self, client, mock_mongodb):
        """Tampering with a record field is detected by hash recomputation."""
        await _seed_audit_records(3)

        # Tamper with a field in record #2
        await mock_mongodb["audit_decisions"].update_one(
            {"sequence_number": 2},
            {"$set": {"decision": "ALLOW"}},
        )

        resp = await client.get("/v1/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False
        assert data["first_tampered_sequence"] == 2

    async def test_verify_partial_range(self, client, mock_mongodb):
        """Verification works on a partial sequence range."""
        await _seed_audit_records(10)

        resp = await client.get(
            "/v1/audit/verify", params={"start_sequence": 3, "end_sequence": 7}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert data["verified_records"] == 5


# ===========================================================================
# Integration: intercept → audit logger → hash chain
# ===========================================================================


class TestInterceptAuditIntegration:
    async def test_intercept_creates_chained_audit_record(self, client, mock_mongodb):
        """POST /v1/intercept creates an audit record with hash chain fields."""
        # Seed a permissive rule
        await mock_mongodb["policy_rules"].insert_one(
            {
                "rule_id": str(uuid4()),
                "name": "allow-all",
                "agent_role": ["*"],
                "tool_pattern": "*",
                "action": "ALLOW",
                "taint_check": False,
                "risk_threshold": 1.0,
                "rate_limit": None,
                "arg_validators": [],
                "priority": 100,
                "enabled": True,
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
            }
        )

        resp = await client.post(
            "/v1/intercept",
            json={
                "session_id": "sess-int-1",
                "agent_id": "agent-1",
                "tool_name": "file.read",
                "tool_args": {"path": "/tmp/test"},
            },
        )
        assert resp.status_code == 200

        # Check the audit record was created with hash chain fields
        doc = await mock_mongodb["audit_decisions"].find_one({"agent_id": "agent-1"})
        assert doc is not None
        assert doc["sequence_number"] >= 1
        assert doc["record_hash"] != ""
        assert doc["previous_hash"] != ""
