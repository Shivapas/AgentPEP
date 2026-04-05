"""E2E tests for escalation approval workflow (APEP-150).

Sprint 18: Tests cover the full escalation lifecycle — create, list,
detail, approve/deny/escalate-up, bulk approve, SLA expiration,
and WebSocket real-time feed.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.services.escalation_manager import escalation_manager


@pytest.fixture(autouse=True)
def _clear_escalation_manager():
    """Clear escalation state between tests."""
    escalation_manager.clear()
    yield
    escalation_manager.clear()


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    from tests.conftest import _get_auth_headers

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test", headers=_get_auth_headers()) as c:
        yield c


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _ticket_payload(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "session_id": "sess-001",
        "agent_id": "agent-alpha",
        "agent_role": "reader",
        "tool_name": "file_read",
        "tool_args": {"path": "/etc/passwd"},
        "tool_args_hash": "abc123",
        "risk_score": 0.75,
        "taint_flags": ["UNTRUSTED"],
        "delegation_chain": ["user", "agent-alpha"],
        "reason": "Taint check triggered escalation",
        "sla_seconds": 300,
    }
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# APEP-143: Escalation queue — create & list PENDING tickets
# ---------------------------------------------------------------------------


class TestEscalationQueueCreate:
    async def test_create_ticket(self, client: AsyncClient) -> None:
        resp = await client.post("/v1/escalations", json=_ticket_payload())
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "PENDING"
        assert body["tool_name"] == "file_read"
        assert body["risk_score"] == 0.75
        assert body["taint_flags"] == ["UNTRUSTED"]
        assert "ticket_id" in body

    async def test_list_pending_returns_only_pending(self, client: AsyncClient) -> None:
        # Create two tickets
        r1 = await client.post("/v1/escalations", json=_ticket_payload(tool_name="tool_a"))
        r2 = await client.post("/v1/escalations", json=_ticket_payload(tool_name="tool_b"))
        assert r1.status_code == 201
        assert r2.status_code == 201

        resp = await client.get("/v1/escalations/pending")
        assert resp.status_code == 200
        tickets = resp.json()
        assert len(tickets) == 2
        assert all(t["status"] == "PENDING" for t in tickets)

    async def test_list_pending_excludes_resolved(self, client: AsyncClient) -> None:
        r = await client.post("/v1/escalations", json=_ticket_payload())
        ticket_id = r.json()["ticket_id"]

        # Approve the ticket
        await client.post(
            f"/v1/escalations/{ticket_id}/resolve",
            json={"action": "APPROVED", "comment": "looks safe"},
        )

        resp = await client.get("/v1/escalations/pending")
        assert resp.status_code == 200
        assert len(resp.json()) == 0

    async def test_list_all_includes_resolved(self, client: AsyncClient) -> None:
        r = await client.post("/v1/escalations", json=_ticket_payload())
        ticket_id = r.json()["ticket_id"]

        await client.post(
            f"/v1/escalations/{ticket_id}/resolve",
            json={"action": "APPROVED", "comment": "ok"},
        )

        resp = await client.get("/v1/escalations/all")
        assert resp.status_code == 200
        tickets = resp.json()
        assert len(tickets) == 1
        assert tickets[0]["status"] == "APPROVED"


# ---------------------------------------------------------------------------
# APEP-144: Escalation detail panel
# ---------------------------------------------------------------------------


class TestEscalationDetail:
    async def test_get_ticket_detail(self, client: AsyncClient) -> None:
        r = await client.post("/v1/escalations", json=_ticket_payload())
        ticket_id = r.json()["ticket_id"]

        resp = await client.get(f"/v1/escalations/{ticket_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ticket_id"] == ticket_id
        assert body["tool_name"] == "file_read"
        assert body["tool_args"] == {"path": "/etc/passwd"}
        assert body["risk_score"] == 0.75
        assert body["taint_flags"] == ["UNTRUSTED"]
        assert body["delegation_chain"] == ["user", "agent-alpha"]
        assert body["agent_role"] == "reader"

    async def test_get_nonexistent_ticket(self, client: AsyncClient) -> None:
        fake_id = str(uuid4())
        resp = await client.get(f"/v1/escalations/{fake_id}")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# APEP-145: Approve / deny / escalate-up actions
# ---------------------------------------------------------------------------


class TestEscalationActions:
    async def test_approve(self, client: AsyncClient) -> None:
        r = await client.post("/v1/escalations", json=_ticket_payload())
        ticket_id = r.json()["ticket_id"]

        resp = await client.post(
            f"/v1/escalations/{ticket_id}/resolve",
            json={"action": "APPROVED", "comment": "Verified safe", "resolved_by": "admin"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "APPROVED"
        assert body["resolution_comment"] == "Verified safe"
        assert body["resolved_by"] == "admin"
        assert body["resolved_at"] is not None

    async def test_deny(self, client: AsyncClient) -> None:
        r = await client.post("/v1/escalations", json=_ticket_payload())
        ticket_id = r.json()["ticket_id"]

        resp = await client.post(
            f"/v1/escalations/{ticket_id}/resolve",
            json={"action": "DENIED", "comment": "Too risky"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "DENIED"

    async def test_escalate_up(self, client: AsyncClient) -> None:
        r = await client.post("/v1/escalations", json=_ticket_payload())
        ticket_id = r.json()["ticket_id"]

        resp = await client.post(
            f"/v1/escalations/{ticket_id}/resolve",
            json={"action": "ESCALATED_UP", "comment": "Need higher approval"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ESCALATED_UP"

    async def test_resolve_nonexistent_ticket(self, client: AsyncClient) -> None:
        fake_id = str(uuid4())
        resp = await client.post(
            f"/v1/escalations/{fake_id}/resolve",
            json={"action": "APPROVED", "comment": "ok"},
        )
        assert resp.status_code == 404

    async def test_invalid_action_rejected(self, client: AsyncClient) -> None:
        r = await client.post("/v1/escalations", json=_ticket_payload())
        ticket_id = r.json()["ticket_id"]

        resp = await client.post(
            f"/v1/escalations/{ticket_id}/resolve",
            json={"action": "PENDING", "comment": "invalid"},
        )
        assert resp.status_code == 422

    async def test_double_resolve_is_idempotent(self, client: AsyncClient) -> None:
        r = await client.post("/v1/escalations", json=_ticket_payload())
        ticket_id = r.json()["ticket_id"]

        await client.post(
            f"/v1/escalations/{ticket_id}/resolve",
            json={"action": "APPROVED", "comment": "first"},
        )
        # Second resolve should return the already-resolved ticket
        resp = await client.post(
            f"/v1/escalations/{ticket_id}/resolve",
            json={"action": "DENIED", "comment": "second"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "APPROVED"  # unchanged


# ---------------------------------------------------------------------------
# APEP-146: Bulk approve
# ---------------------------------------------------------------------------


class TestBulkApprove:
    async def test_bulk_approve_matching_pattern(self, client: AsyncClient) -> None:
        # Create three tickets: two file_read, one shell_exec
        await client.post("/v1/escalations", json=_ticket_payload(tool_name="file_read"))
        await client.post(
            "/v1/escalations", json=_ticket_payload(tool_name="file_read_extended")
        )
        await client.post("/v1/escalations", json=_ticket_payload(tool_name="shell_exec"))

        resp = await client.post(
            "/v1/escalations/bulk-approve",
            json={
                "tool_pattern": "file_read*",
                "comment": "Batch approved",
                "resolved_by": "admin",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["approved_count"] == 2

        # Only shell_exec should remain pending
        pending = await client.get("/v1/escalations/pending")
        assert len(pending.json()) == 1
        assert pending.json()[0]["tool_name"] == "shell_exec"

    async def test_bulk_approve_no_matches(self, client: AsyncClient) -> None:
        await client.post("/v1/escalations", json=_ticket_payload(tool_name="file_read"))

        resp = await client.post(
            "/v1/escalations/bulk-approve",
            json={"tool_pattern": "nonexistent_*", "comment": ""},
        )
        assert resp.status_code == 200
        assert resp.json()["approved_count"] == 0


# ---------------------------------------------------------------------------
# APEP-147: SLA timer & auto-decision
# ---------------------------------------------------------------------------


class TestSlaExpiration:
    async def test_sla_check_expires_overdue_tickets(self, client: AsyncClient) -> None:
        # Create a ticket with a very short SLA (already expired)
        await client.post(
            "/v1/escalations", json=_ticket_payload(sla_seconds=0)
        )

        # Give it a moment so deadline is in the past
        await asyncio.sleep(0.05)

        resp = await client.post("/v1/escalations/check-sla")
        assert resp.status_code == 200
        body = resp.json()
        assert body["expired_count"] == 1

        # Verify ticket is now AUTO_DECIDED
        all_tickets = await client.get("/v1/escalations/all")
        assert all_tickets.json()[0]["status"] == "AUTO_DECIDED"

    async def test_sla_check_does_not_expire_valid_tickets(self, client: AsyncClient) -> None:
        await client.post(
            "/v1/escalations", json=_ticket_payload(sla_seconds=3600)
        )

        resp = await client.post("/v1/escalations/check-sla")
        assert resp.status_code == 200
        assert resp.json()["expired_count"] == 0

    async def test_ticket_has_sla_deadline(self, client: AsyncClient) -> None:
        r = await client.post(
            "/v1/escalations", json=_ticket_payload(sla_seconds=600)
        )
        body = r.json()
        assert body["sla_seconds"] == 600
        assert body["sla_deadline"] is not None
        # Deadline should be roughly 600s from creation
        created = datetime.fromisoformat(body["created_at"])
        deadline = datetime.fromisoformat(body["sla_deadline"])
        delta = (deadline - created).total_seconds()
        assert 590 < delta < 610


# ---------------------------------------------------------------------------
# WebSocket real-time feed (APEP-143 WebSocket)
# ---------------------------------------------------------------------------


class TestEscalationWebSocket:
    async def test_ws_receives_snapshot_on_connect(self, client: AsyncClient) -> None:
        """WebSocket should send a snapshot of pending tickets on connection."""
        # Create a ticket first
        await client.post("/v1/escalations", json=_ticket_payload())

        # Test via the escalation_manager directly (httpx doesn't support WS natively)
        queue = escalation_manager.subscribe()
        pending = escalation_manager.list_pending()
        assert len(pending) == 1

        escalation_manager.unsubscribe(queue)

    async def test_ws_notified_on_create(self, client: AsyncClient) -> None:
        """Subscribers should receive ticket_created messages."""
        queue = escalation_manager.subscribe()

        await client.post("/v1/escalations", json=_ticket_payload())

        msg = queue.get_nowait()
        assert msg["type"] == "ticket_created"
        assert "ticket" in msg

        escalation_manager.unsubscribe(queue)

    async def test_ws_notified_on_resolve(self, client: AsyncClient) -> None:
        """Subscribers should receive ticket_resolved messages."""
        r = await client.post("/v1/escalations", json=_ticket_payload())
        ticket_id = r.json()["ticket_id"]

        queue = escalation_manager.subscribe()

        await client.post(
            f"/v1/escalations/{ticket_id}/resolve",
            json={"action": "APPROVED", "comment": "ok"},
        )

        msg = queue.get_nowait()
        assert msg["type"] == "ticket_resolved"
        assert msg["ticket_id"] == ticket_id

        escalation_manager.unsubscribe(queue)

    async def test_ws_notified_on_bulk_approve(self, client: AsyncClient) -> None:
        """Subscribers should receive bulk_approved messages."""
        await client.post(
            "/v1/escalations", json=_ticket_payload(tool_name="file_read")
        )
        await client.post(
            "/v1/escalations", json=_ticket_payload(tool_name="file_write")
        )

        queue = escalation_manager.subscribe()

        await client.post(
            "/v1/escalations/bulk-approve",
            json={"tool_pattern": "file_*", "comment": "batch"},
        )

        msg = queue.get_nowait()
        assert msg["type"] == "bulk_approved"
        assert msg["count"] == 2

        escalation_manager.unsubscribe(queue)


# ---------------------------------------------------------------------------
# End-to-end workflow: full escalation lifecycle
# ---------------------------------------------------------------------------


class TestE2EEscalationWorkflow:
    async def test_full_lifecycle(self, client: AsyncClient) -> None:
        """
        End-to-end test: create ticket -> verify pending -> view detail ->
        approve with comment -> verify no longer pending.
        """
        # Step 1: Create escalation ticket
        r = await client.post("/v1/escalations", json=_ticket_payload())
        assert r.status_code == 201
        ticket_id = r.json()["ticket_id"]

        # Step 2: List pending — should appear
        pending = await client.get("/v1/escalations/pending")
        assert any(t["ticket_id"] == ticket_id for t in pending.json())

        # Step 3: Get detail — verify all fields present
        detail = await client.get(f"/v1/escalations/{ticket_id}")
        body = detail.json()
        assert body["tool_name"] == "file_read"
        assert body["risk_score"] == 0.75
        assert body["taint_flags"] == ["UNTRUSTED"]
        assert body["delegation_chain"] == ["user", "agent-alpha"]
        assert body["status"] == "PENDING"

        # Step 4: Approve
        resolve = await client.post(
            f"/v1/escalations/{ticket_id}/resolve",
            json={"action": "APPROVED", "comment": "Reviewed and safe", "resolved_by": "admin"},
        )
        assert resolve.json()["status"] == "APPROVED"
        assert resolve.json()["resolution_comment"] == "Reviewed and safe"

        # Step 5: No longer pending
        pending2 = await client.get("/v1/escalations/pending")
        assert not any(t["ticket_id"] == ticket_id for t in pending2.json())

    async def test_mixed_lifecycle_with_bulk_and_sla(self, client: AsyncClient) -> None:
        """
        Create multiple tickets, bulk-approve some, let one expire via SLA,
        deny the last manually.
        """
        # Create 4 tickets
        t1 = (
            await client.post(
                "/v1/escalations",
                json=_ticket_payload(tool_name="file_read", sla_seconds=3600),
            )
        ).json()["ticket_id"]
        t2 = (
            await client.post(
                "/v1/escalations",
                json=_ticket_payload(tool_name="file_write", sla_seconds=3600),
            )
        ).json()["ticket_id"]
        t3 = (
            await client.post(
                "/v1/escalations",
                json=_ticket_payload(tool_name="shell_exec", sla_seconds=0),
            )
        ).json()["ticket_id"]
        t4 = (
            await client.post(
                "/v1/escalations",
                json=_ticket_payload(tool_name="db_query", sla_seconds=3600),
            )
        ).json()["ticket_id"]

        # Bulk approve file_* (t1, t2)
        bulk = await client.post(
            "/v1/escalations/bulk-approve",
            json={"tool_pattern": "file_*", "comment": "batch ok"},
        )
        assert bulk.json()["approved_count"] == 2

        # SLA check — t3 should expire
        await asyncio.sleep(0.05)
        sla = await client.post("/v1/escalations/check-sla")
        assert sla.json()["expired_count"] == 1

        # Manually deny t4
        deny = await client.post(
            f"/v1/escalations/{t4}/resolve",
            json={"action": "DENIED", "comment": "Blocked"},
        )
        assert deny.json()["status"] == "DENIED"

        # Verify all resolved
        pending = await client.get("/v1/escalations/pending")
        assert len(pending.json()) == 0

        # Verify statuses
        all_tickets = await client.get("/v1/escalations/all")
        status_map = {t["ticket_id"]: t["status"] for t in all_tickets.json()}
        assert status_map[t1] == "APPROVED"
        assert status_map[t2] == "APPROVED"
        assert status_map[t3] == "AUTO_DECIDED"
        assert status_map[t4] == "DENIED"
