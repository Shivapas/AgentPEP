"""E2E tests for escalation approval workflow — Sprint 18 (APEP-150).

Tests cover:
- APEP-143: Escalation queue (create, list pending)
- APEP-144: Escalation detail (get by ID)
- APEP-145: Approve / deny / escalate-up actions with comment
- APEP-146: Bulk approve for same-pattern pending escalations
- APEP-147: SLA auto-decision on expired tickets
"""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.policy import EscalationStatus
from app.services.escalation_manager import escalation_manager


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _escalation_payload(**overrides):
    base = {
        "request_id": str(uuid4()),
        "session_id": "sess-001",
        "agent_id": "agent-alpha",
        "agent_role": "analyst",
        "tool_name": "file_read",
        "tool_args": {"path": "/etc/passwd"},
        "risk_score": 0.75,
        "taint_flags": ["UNTRUSTED"],
        "delegation_chain": ["user", "agent-alpha"],
        "reason": "High risk file access",
        "sla_seconds": 300,
        "auto_decision": "DENY",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# APEP-143: Escalation queue — create & list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_escalation(client: AsyncClient):
    """Creating an escalation returns PENDING status with all fields."""
    payload = _escalation_payload()
    res = await client.post("/v1/escalations", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "PENDING"
    assert data["tool_name"] == "file_read"
    assert data["risk_score"] == 0.75
    assert data["taint_flags"] == ["UNTRUSTED"]
    assert data["delegation_chain"] == ["user", "agent-alpha"]
    assert data["sla_deadline"] is not None
    assert data["escalation_id"] is not None


@pytest.mark.asyncio
async def test_list_pending_escalations(client: AsyncClient):
    """List endpoint returns only PENDING tickets."""
    # Create two escalations
    await client.post("/v1/escalations", json=_escalation_payload())
    await client.post("/v1/escalations", json=_escalation_payload(tool_name="shell_exec"))

    res = await client.get("/v1/escalations/pending")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 2
    assert all(t["status"] == "PENDING" for t in data)


@pytest.mark.asyncio
async def test_list_escalations_with_status_filter(client: AsyncClient):
    """List endpoint supports status filter."""
    await client.post("/v1/escalations", json=_escalation_payload())
    res = await client.get("/v1/escalations", params={"status": "PENDING"})
    assert res.status_code == 200
    data = res.json()
    assert all(t["status"] == "PENDING" for t in data)


# ---------------------------------------------------------------------------
# APEP-144: Escalation detail
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_escalation_detail(client: AsyncClient):
    """Get a single escalation by ID returns full detail."""
    create_res = await client.post("/v1/escalations", json=_escalation_payload())
    eid = create_res.json()["escalation_id"]

    res = await client.get(f"/v1/escalations/{eid}")
    assert res.status_code == 200
    data = res.json()
    assert data["escalation_id"] == eid
    assert data["tool_args"] == {"path": "/etc/passwd"}
    assert data["agent_role"] == "analyst"


@pytest.mark.asyncio
async def test_get_nonexistent_escalation(client: AsyncClient):
    """Getting a non-existent escalation returns 404."""
    res = await client.get(f"/v1/escalations/{uuid4()}")
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# APEP-145: Approve / Deny / Escalate-up
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approve_escalation(client: AsyncClient):
    """Approving a PENDING ticket transitions it to APPROVED."""
    create_res = await client.post("/v1/escalations", json=_escalation_payload())
    eid = create_res.json()["escalation_id"]

    res = await client.post(
        f"/v1/escalations/{eid}/approve",
        json={"resolved_by": "admin@corp.com", "comment": "Looks safe"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "APPROVED"
    assert data["resolved_by"] == "admin@corp.com"
    assert data["resolution_comment"] == "Looks safe"
    assert data["resolved_at"] is not None


@pytest.mark.asyncio
async def test_deny_escalation(client: AsyncClient):
    """Denying a PENDING ticket transitions it to DENIED."""
    create_res = await client.post("/v1/escalations", json=_escalation_payload())
    eid = create_res.json()["escalation_id"]

    res = await client.post(
        f"/v1/escalations/{eid}/deny",
        json={"resolved_by": "admin@corp.com", "comment": "Too risky"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "DENIED"
    assert data["resolution_comment"] == "Too risky"


@pytest.mark.asyncio
async def test_escalate_up(client: AsyncClient):
    """Escalating up transitions ticket and records the target reviewer."""
    create_res = await client.post("/v1/escalations", json=_escalation_payload())
    eid = create_res.json()["escalation_id"]

    res = await client.post(
        f"/v1/escalations/{eid}/escalate-up",
        json={
            "resolved_by": "l1-reviewer",
            "escalated_to": "ciso@corp.com",
            "comment": "Needs CISO sign-off",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ESCALATED_UP"
    assert data["escalated_to"] == "ciso@corp.com"


@pytest.mark.asyncio
async def test_approve_already_resolved(client: AsyncClient):
    """Attempting to approve an already-resolved ticket returns 404."""
    create_res = await client.post("/v1/escalations", json=_escalation_payload())
    eid = create_res.json()["escalation_id"]

    # First approve succeeds
    await client.post(
        f"/v1/escalations/{eid}/approve",
        json={"resolved_by": "admin"},
    )

    # Second approve fails
    res = await client.post(
        f"/v1/escalations/{eid}/approve",
        json={"resolved_by": "admin"},
    )
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# APEP-146: Bulk approve
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bulk_approve(client: AsyncClient):
    """Bulk approve resolves all PENDING tickets matching a tool pattern."""
    # Create 3 tickets for same tool
    for _ in range(3):
        await client.post(
            "/v1/escalations",
            json=_escalation_payload(tool_name="db_query"),
        )
    # Create 1 ticket for different tool
    await client.post(
        "/v1/escalations",
        json=_escalation_payload(tool_name="shell_exec"),
    )

    res = await client.post(
        "/v1/escalations/bulk-approve",
        json={
            "tool_pattern": "db_query",
            "resolved_by": "batch-admin",
            "comment": "Approved in bulk",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 3
    assert all(t["status"] == "APPROVED" for t in data)
    assert all(t["tool_name"] == "db_query" for t in data)

    # shell_exec should still be pending
    pending_res = await client.get("/v1/escalations/pending")
    pending = pending_res.json()
    shell_pending = [t for t in pending if t["tool_name"] == "shell_exec"]
    assert len(shell_pending) >= 1


# ---------------------------------------------------------------------------
# APEP-147: SLA auto-decision
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sla_auto_decision(client: AsyncClient, mock_mongodb):
    """Expired SLA tickets are auto-resolved by process-sla endpoint."""
    from app.db.mongodb import ESCALATION_TICKETS

    # Create a ticket with normal SLA
    payload = _escalation_payload(sla_seconds=300)
    create_res = await client.post("/v1/escalations", json=payload)
    assert create_res.status_code == 201
    eid = create_res.json()["escalation_id"]

    # Manually set sla_deadline to the past
    past = (datetime.utcnow() - timedelta(minutes=5)).isoformat()
    await mock_mongodb[ESCALATION_TICKETS].update_one(
        {"escalation_id": eid},
        {"$set": {"sla_deadline": past}},
    )

    # Trigger SLA processing
    res = await client.post("/v1/escalations/process-sla")
    assert res.status_code == 200
    data = res.json()
    assert data["processed"] >= 1
    resolved = [t for t in data["tickets"] if t["escalation_id"] == eid]
    assert len(resolved) == 1
    assert resolved[0]["status"] == "AUTO_DECIDED"
    assert "SLA expired" in resolved[0]["resolution_comment"]


# ---------------------------------------------------------------------------
# APEP-143 + APEP-145: Full workflow E2E
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_escalation_workflow(client: AsyncClient):
    """End-to-end: create -> list pending -> get detail -> approve -> verify resolved."""
    # 1. Create
    create_res = await client.post("/v1/escalations", json=_escalation_payload())
    assert create_res.status_code == 201
    ticket = create_res.json()
    eid = ticket["escalation_id"]

    # 2. List pending — should include our ticket
    list_res = await client.get("/v1/escalations/pending")
    assert any(t["escalation_id"] == eid for t in list_res.json())

    # 3. Get detail
    detail_res = await client.get(f"/v1/escalations/{eid}")
    assert detail_res.status_code == 200
    assert detail_res.json()["status"] == "PENDING"

    # 4. Approve with comment
    approve_res = await client.post(
        f"/v1/escalations/{eid}/approve",
        json={"resolved_by": "security-team", "comment": "Verified safe"},
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "APPROVED"

    # 5. Verify it's no longer in pending list
    list_res2 = await client.get("/v1/escalations/pending")
    assert not any(t["escalation_id"] == eid for t in list_res2.json())

    # 6. Verify it appears in full list with APPROVED status
    all_res = await client.get("/v1/escalations", params={"status": "APPROVED"})
    assert any(t["escalation_id"] == eid for t in all_res.json())
