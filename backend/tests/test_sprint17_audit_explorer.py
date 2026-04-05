"""Sprint 17 — Audit Explorer API tests (APEP-136 to APEP-142).

Tests paginated decision listing, full-text search, decision detail,
session timeline, CSV/JSON export, and hash-chain integrity verification.
"""

import hashlib
import json
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.db import mongodb as db_module
from app.main import app

BASE = "http://test"


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url=BASE) as ac:
        yield ac


@pytest.fixture
async def seed_decisions(mock_mongodb):
    """Seed 30 audit decisions across 2 sessions."""
    col = mock_mongodb[db_module.AUDIT_DECISIONS]
    now = datetime.utcnow()
    docs = []
    for i in range(30):
        session = "sess-A" if i < 20 else "sess-B"
        decision = "ALLOW" if i % 3 == 0 else ("DENY" if i % 3 == 1 else "ESCALATE")
        args_hash = hashlib.sha256(json.dumps({"i": i}, sort_keys=True).encode()).hexdigest()
        docs.append({
            "decision_id": str(uuid4()),
            "session_id": session,
            "agent_id": f"agent-{i % 5}",
            "agent_role": "worker",
            "tool_name": f"tool_{i % 4}",
            "tool_args_hash": args_hash,
            "taint_flags": ["UNTRUSTED"] if i % 5 == 0 else [],
            "risk_score": round(i / 30, 2),
            "delegation_chain": [f"agent-{i % 5}"],
            "matched_rule_id": str(uuid4()),
            "decision": decision,
            "escalation_id": None,
            "latency_ms": 10 + i,
            "timestamp": now - timedelta(minutes=30 - i),
        })
    await col.insert_many(docs)
    return docs


# -----------------------------------------------------------------------
# APEP-136 — Paginated decision table with column filters
# -----------------------------------------------------------------------


class TestDecisionListing:
    async def test_default_pagination(self, client, seed_decisions):
        resp = await client.get("/v1/audit/decisions")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 30
        assert body["page"] == 1
        assert body["page_size"] == 25
        assert len(body["items"]) == 25

    async def test_page_2(self, client, seed_decisions):
        resp = await client.get("/v1/audit/decisions?page=2&page_size=25")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 5  # 30 - 25

    async def test_filter_by_session(self, client, seed_decisions):
        resp = await client.get("/v1/audit/decisions?session_id=sess-B")
        body = resp.json()
        assert body["total"] == 10
        assert all(d["session_id"] == "sess-B" for d in body["items"])

    async def test_filter_by_decision(self, client, seed_decisions):
        resp = await client.get("/v1/audit/decisions?decision=DENY")
        body = resp.json()
        assert body["total"] > 0
        assert all(d["decision"] == "DENY" for d in body["items"])

    async def test_filter_by_risk_range(self, client, seed_decisions):
        resp = await client.get("/v1/audit/decisions?risk_min=0.5&risk_max=0.8")
        body = resp.json()
        for d in body["items"]:
            assert 0.5 <= d["risk_score"] <= 0.8

    async def test_sort_ascending(self, client, seed_decisions):
        resp = await client.get(
            "/v1/audit/decisions?sort_field=risk_score&sort_order=asc&page_size=5"
        )
        body = resp.json()
        scores = [d["risk_score"] for d in body["items"]]
        assert scores == sorted(scores)

    async def test_empty_result(self, client, mock_mongodb):
        resp = await client.get("/v1/audit/decisions?session_id=nonexistent")
        body = resp.json()
        assert body["total"] == 0
        assert body["items"] == []


# -----------------------------------------------------------------------
# APEP-137 — Full-text search
# -----------------------------------------------------------------------


class TestFullTextSearch:
    async def test_search_by_agent(self, client, seed_decisions):
        resp = await client.get("/v1/audit/decisions?search=agent-0")
        body = resp.json()
        assert body["total"] > 0
        for d in body["items"]:
            assert (
                "agent-0" in d["agent_id"]
                or "agent-0" in d["tool_name"]
                or "agent-0" in d["session_id"]
                or "agent-0" in d["decision"]
            )

    async def test_search_by_tool(self, client, seed_decisions):
        resp = await client.get("/v1/audit/decisions?search=tool_2")
        body = resp.json()
        assert body["total"] > 0

    async def test_search_by_decision_value(self, client, seed_decisions):
        resp = await client.get("/v1/audit/decisions?search=ALLOW")
        body = resp.json()
        assert body["total"] > 0

    async def test_search_no_results(self, client, seed_decisions):
        resp = await client.get("/v1/audit/decisions?search=zzz_nonexistent")
        body = resp.json()
        assert body["total"] == 0


# -----------------------------------------------------------------------
# APEP-138 — Decision detail
# -----------------------------------------------------------------------


class TestDecisionDetail:
    async def test_get_detail(self, client, seed_decisions):
        did = seed_decisions[0]["decision_id"]
        resp = await client.get(f"/v1/audit/decisions/{did}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["decision_id"] == did
        assert "tool_args_hash" in body
        assert "taint_flags" in body
        assert "delegation_chain" in body

    async def test_not_found(self, client, mock_mongodb):
        resp = await client.get(f"/v1/audit/decisions/{uuid4()}")
        body = resp.json()
        assert body.get("error") == "Decision not found"


# -----------------------------------------------------------------------
# APEP-139 — Session timeline
# -----------------------------------------------------------------------


class TestSessionTimeline:
    async def test_timeline_chronological(self, client, seed_decisions):
        resp = await client.get("/v1/audit/sessions/sess-A/timeline")
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 20
        timestamps = [d["timestamp"] for d in items]
        assert timestamps == sorted(timestamps)

    async def test_empty_session(self, client, mock_mongodb):
        resp = await client.get("/v1/audit/sessions/no-session/timeline")
        assert resp.status_code == 200
        assert resp.json() == []


# -----------------------------------------------------------------------
# APEP-140 — Audit export (CSV / JSON)
# -----------------------------------------------------------------------


class TestAuditExport:
    async def test_json_export(self, client, seed_decisions):
        resp = await client.get("/v1/audit/export?format=json&limit=5")
        assert resp.status_code == 200
        assert "application/json" in resp.headers["content-type"]
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 5

    async def test_csv_export(self, client, seed_decisions):
        resp = await client.get("/v1/audit/export?format=csv&limit=5")
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        lines = resp.text.strip().split("\n")
        assert len(lines) == 6  # header + 5 rows
        assert "decision_id" in lines[0]

    async def test_csv_export_with_filter(self, client, seed_decisions):
        resp = await client.get(
            "/v1/audit/export?format=csv&session_id=sess-B"
        )
        assert resp.status_code == 200
        lines = resp.text.strip().split("\n")
        # header + 10 sess-B records
        assert len(lines) == 11

    async def test_json_export_empty(self, client, mock_mongodb):
        resp = await client.get("/v1/audit/export?format=json&session_id=none")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_csv_export_empty(self, client, mock_mongodb):
        resp = await client.get("/v1/audit/export?format=csv&session_id=none")
        assert resp.status_code == 200
        assert "No records" in resp.text


# -----------------------------------------------------------------------
# APEP-141 — Hash chain integrity verification
# -----------------------------------------------------------------------


class TestHashChainIntegrity:
    async def test_no_records(self, client, mock_mongodb):
        resp = await client.get("/v1/audit/integrity?session_id=empty")
        body = resp.json()
        assert body["status"] == "NO_RECORDS"
        assert body["total_records"] == 0

    async def test_unlinked_records(self, client, seed_decisions):
        """Records without chain_hash are treated as UNLINKED (verified)."""
        resp = await client.get("/v1/audit/integrity?session_id=sess-A")
        body = resp.json()
        assert body["status"] == "VERIFIED"
        assert body["total_records"] == 20
        assert body["verified"] == 20
        assert body["tampered"] == 0
        for rec in body["records"]:
            assert rec["status"] == "UNLINKED"

    async def test_valid_chain(self, client, mock_mongodb):
        """Records with correct chain_hash pass verification."""
        col = mock_mongodb[db_module.AUDIT_DECISIONS]
        now = datetime.utcnow()
        prev_hash = "0" * 64

        for i in range(3):
            did = str(uuid4())
            args_hash = hashlib.sha256(f"arg{i}".encode()).hexdigest()
            chain_hash = hashlib.sha256(
                f"{prev_hash}{did}{args_hash}".encode()
            ).hexdigest()

            await col.insert_one({
                "decision_id": did,
                "session_id": "chain-session",
                "agent_id": "agent",
                "agent_role": "worker",
                "tool_name": "tool",
                "tool_args_hash": args_hash,
                "taint_flags": [],
                "risk_score": 0.1,
                "delegation_chain": [],
                "decision": "ALLOW",
                "chain_hash": chain_hash,
                "latency_ms": 5,
                "timestamp": now + timedelta(seconds=i),
            })
            prev_hash = chain_hash

        resp = await client.get("/v1/audit/integrity?session_id=chain-session")
        body = resp.json()
        assert body["status"] == "VERIFIED"
        assert body["verified"] == 3
        assert body["tampered"] == 0

    async def test_tampered_record(self, client, mock_mongodb):
        """A record with a wrong chain_hash is flagged as TAMPERED."""
        col = mock_mongodb[db_module.AUDIT_DECISIONS]
        now = datetime.utcnow()

        did = str(uuid4())
        args_hash = hashlib.sha256(b"arg").hexdigest()

        await col.insert_one({
            "decision_id": did,
            "session_id": "tampered-session",
            "agent_id": "agent",
            "agent_role": "worker",
            "tool_name": "tool",
            "tool_args_hash": args_hash,
            "taint_flags": [],
            "risk_score": 0.1,
            "delegation_chain": [],
            "decision": "ALLOW",
            "chain_hash": "bad_hash_value",
            "latency_ms": 5,
            "timestamp": now,
        })

        resp = await client.get(
            "/v1/audit/integrity?session_id=tampered-session"
        )
        body = resp.json()
        assert body["status"] == "TAMPERED"
        assert body["tampered"] == 1
