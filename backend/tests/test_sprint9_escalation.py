"""Sprint 9 — Human Escalation Manager integration tests (APEP-080).

Tests cover:
- APEP-072: EscalationTicket model and state machine
- APEP-073: EscalationManager create/resolve lifecycle
- APEP-074: WebSocket push of ESCALATE events
- APEP-075: Configurable timeout (auto-DENY / auto-ALLOW)
- APEP-076: Approver routing (round-robin, specific user, on-call)
- APEP-077: Approval memory (7-day TTL cache, skip re-escalation)
- APEP-078: Email notification webhook
- APEP-079: Slack webhook notification
- APEP-080: End-to-end escalation flow with WebSocket client
"""

import asyncio
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.db import mongodb as db_module
from app.db.mongodb import APPROVAL_MEMORY, APPROVER_GROUPS, ESCALATION_TICKETS
from app.main import app
from app.models.policy import (
    ApproverGroup,
    ApproverRoutingStrategy,
    EscalationResolveRequest,
    EscalationState,
    NotificationConfig,
)
from app.models.policy import (
    EscalationTicketV1 as EscalationTicket,
)
from app.services.escalation_manager import escalation_manager
from app.services.escalation_ws import escalation_ws_manager

# ---------- Fixtures ----------


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def base_ticket_kwargs():
    return {
        "request_id": uuid4(),
        "session_id": "sess-001",
        "agent_id": "agent-alpha",
        "tool_name": "file_write",
        "tool_args": {"path": "/etc/config", "content": "data"},
        "reason": "Untrusted taint on arguments",
        "risk_score": 0.85,
    }


@pytest.fixture
async def http_client():
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# ---------- APEP-072: EscalationTicket Model & State Machine ----------


class TestEscalationTicketModel:
    def test_ticket_defaults(self):
        ticket = EscalationTicket(
            request_id=uuid4(),
            session_id="s1",
            agent_id="a1",
            tool_name="t1",
        )
        assert ticket.state == EscalationState.PENDING
        assert ticket.resolved_at is None
        assert ticket.timeout_seconds == 300
        assert ticket.timeout_action == EscalationState.DENIED

    def test_state_enum_values(self):
        assert EscalationState.PENDING.value == "PENDING"
        assert EscalationState.APPROVED.value == "APPROVED"
        assert EscalationState.DENIED.value == "DENIED"
        assert EscalationState.TIMEOUT.value == "TIMEOUT"

    def test_ticket_serialization(self):
        ticket = EscalationTicket(
            request_id=uuid4(),
            session_id="s1",
            agent_id="a1",
            tool_name="t1",
            risk_score=0.9,
            taint_flags=["UNTRUSTED:web_input"],
        )
        data = ticket.model_dump(mode="json")
        assert data["state"] == "PENDING"
        assert data["risk_score"] == 0.9
        assert "UNTRUSTED:web_input" in data["taint_flags"]

    def test_timeout_action_approved(self):
        ticket = EscalationTicket(
            request_id=uuid4(),
            session_id="s1",
            agent_id="a1",
            tool_name="t1",
            timeout_action=EscalationState.APPROVED,
        )
        assert ticket.timeout_action == EscalationState.APPROVED


# ---------- APEP-073: EscalationManager Create/Resolve ----------


class TestEscalationManagerLifecycle:
    @pytest.mark.asyncio
    async def test_create_ticket(self, mock_mongodb, base_ticket_kwargs):
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)

        assert ticket.state == EscalationState.PENDING
        assert ticket.agent_id == "agent-alpha"
        assert ticket.tool_name == "file_write"
        assert ticket.risk_score == 0.85

        # Verify persisted to MongoDB
        db = db_module.get_database()
        doc = await db[ESCALATION_TICKETS].find_one(
            {"ticket_id": str(ticket.ticket_id)}
        )
        assert doc is not None
        assert doc["state"] == "PENDING"

    @pytest.mark.asyncio
    async def test_resolve_ticket_approve(self, mock_mongodb, base_ticket_kwargs):
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)

        resolve_req = EscalationResolveRequest(
            ticket_id=ticket.ticket_id,
            state=EscalationState.APPROVED,
            decided_by="admin-user",
            decision_reason="Looks safe",
        )
        resolved = await escalation_manager.resolve_ticket(resolve_req)

        assert resolved is not None
        assert resolved.state == EscalationState.APPROVED
        assert resolved.decided_by == "admin-user"
        assert resolved.resolved_at is not None

    @pytest.mark.asyncio
    async def test_resolve_ticket_deny(self, mock_mongodb, base_ticket_kwargs):
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)

        resolve_req = EscalationResolveRequest(
            ticket_id=ticket.ticket_id,
            state=EscalationState.DENIED,
            decided_by="security-lead",
            decision_reason="Too risky",
        )
        resolved = await escalation_manager.resolve_ticket(resolve_req)

        assert resolved is not None
        assert resolved.state == EscalationState.DENIED

    @pytest.mark.asyncio
    async def test_resolve_nonexistent_ticket(self, mock_mongodb):
        resolve_req = EscalationResolveRequest(
            ticket_id=uuid4(),
            state=EscalationState.APPROVED,
            decided_by="admin",
        )
        result = await escalation_manager.resolve_ticket(resolve_req)
        assert result is None

    @pytest.mark.asyncio
    async def test_resolve_already_resolved(self, mock_mongodb, base_ticket_kwargs):
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)

        # Resolve once
        await escalation_manager.resolve_ticket(
            EscalationResolveRequest(
                ticket_id=ticket.ticket_id,
                state=EscalationState.APPROVED,
                decided_by="admin",
            )
        )

        # Try to resolve again — should fail
        result = await escalation_manager.resolve_ticket(
            EscalationResolveRequest(
                ticket_id=ticket.ticket_id,
                state=EscalationState.DENIED,
                decided_by="other-admin",
            )
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_get_ticket(self, mock_mongodb, base_ticket_kwargs):
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)
        fetched = await escalation_manager.get_ticket(ticket.ticket_id)
        assert fetched is not None
        assert fetched.ticket_id == ticket.ticket_id

    @pytest.mark.asyncio
    async def test_list_pending_tickets(self, mock_mongodb, base_ticket_kwargs):
        await escalation_manager.create_ticket(**base_ticket_kwargs)
        kwargs2 = {**base_ticket_kwargs, "request_id": uuid4(), "agent_id": "agent-beta"}
        await escalation_manager.create_ticket(**kwargs2)

        pending = await escalation_manager.list_pending_tickets()
        assert len(pending) == 2


# ---------- APEP-075: Configurable Timeout ----------


class TestEscalationTimeout:
    @pytest.mark.asyncio
    async def test_timeout_auto_deny(self, mock_mongodb, base_ticket_kwargs):
        ticket = await escalation_manager.create_ticket(
            **base_ticket_kwargs,
            timeout_seconds=1,
            timeout_action=EscalationState.DENIED,
        )

        result = await escalation_manager.await_resolution(ticket)
        assert result == EscalationState.DENIED

        # Verify ticket updated in DB
        db = db_module.get_database()
        doc = await db[ESCALATION_TICKETS].find_one(
            {"ticket_id": str(ticket.ticket_id)}
        )
        assert doc["state"] == "TIMEOUT"

    @pytest.mark.asyncio
    async def test_timeout_auto_allow(self, mock_mongodb, base_ticket_kwargs):
        ticket = await escalation_manager.create_ticket(
            **base_ticket_kwargs,
            timeout_seconds=1,
            timeout_action=EscalationState.APPROVED,
        )

        result = await escalation_manager.await_resolution(ticket)
        assert result == EscalationState.APPROVED

    @pytest.mark.asyncio
    async def test_resolution_before_timeout(self, mock_mongodb, base_ticket_kwargs):
        ticket = await escalation_manager.create_ticket(
            **base_ticket_kwargs,
            timeout_seconds=10,
        )

        # Resolve after a short delay
        async def resolve_soon():
            await asyncio.sleep(0.1)
            await escalation_manager.resolve_ticket(
                EscalationResolveRequest(
                    ticket_id=ticket.ticket_id,
                    state=EscalationState.APPROVED,
                    decided_by="admin",
                )
            )

        task = asyncio.create_task(resolve_soon())
        result = await escalation_manager.await_resolution(ticket)
        await task

        assert result == EscalationState.APPROVED

    @pytest.mark.asyncio
    async def test_already_resolved_ticket_no_block(self, mock_mongodb, base_ticket_kwargs):
        """await_resolution on already-resolved ticket returns immediately."""
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)
        await escalation_manager.resolve_ticket(
            EscalationResolveRequest(
                ticket_id=ticket.ticket_id,
                state=EscalationState.DENIED,
                decided_by="admin",
            )
        )
        # Manually set state to simulate already resolved
        ticket.state = EscalationState.DENIED
        result = await escalation_manager.await_resolution(ticket)
        assert result == EscalationState.DENIED


# ---------- APEP-076: Approver Routing ----------


class TestApproverRouting:
    @pytest.mark.asyncio
    async def test_round_robin_routing(self, mock_mongodb):
        db = db_module.get_database()
        group = ApproverGroup(
            group_id="security-team",
            name="Security Team",
            members=["alice", "bob", "carol"],
            strategy=ApproverRoutingStrategy.ROUND_ROBIN,
        )
        await db[APPROVER_GROUPS].insert_one(group.model_dump(mode="json"))

        # First call → alice (index 0)
        approver = await escalation_manager.route_to_approver(group_id="security-team")
        assert approver == "alice"

        # Second call → bob (index 1)
        approver = await escalation_manager.route_to_approver(group_id="security-team")
        assert approver == "bob"

        # Third call → carol (index 2)
        approver = await escalation_manager.route_to_approver(group_id="security-team")
        assert approver == "carol"

        # Fourth call → wraps to alice (index 3 % 3 = 0)
        approver = await escalation_manager.route_to_approver(group_id="security-team")
        assert approver == "alice"

    @pytest.mark.asyncio
    async def test_specific_user_routing(self, mock_mongodb):
        approver = await escalation_manager.route_to_approver(
            specific_user="explicit-reviewer"
        )
        assert approver == "explicit-reviewer"

    @pytest.mark.asyncio
    async def test_on_call_routing(self, mock_mongodb):
        db = db_module.get_database()
        group = ApproverGroup(
            group_id="ops-team",
            name="Ops Team",
            members=["dev1", "dev2"],
            strategy=ApproverRoutingStrategy.ON_CALL,
            on_call_user="dev2",
        )
        await db[APPROVER_GROUPS].insert_one(group.model_dump(mode="json"))

        approver = await escalation_manager.route_to_approver(group_id="ops-team")
        assert approver == "dev2"

    @pytest.mark.asyncio
    async def test_missing_group_returns_none(self, mock_mongodb):
        approver = await escalation_manager.route_to_approver(group_id="nonexistent")
        assert approver is None

    @pytest.mark.asyncio
    async def test_ticket_assigned_to_routed_approver(
        self, mock_mongodb, base_ticket_kwargs
    ):
        db = db_module.get_database()
        group = ApproverGroup(
            group_id="review-team",
            name="Review Team",
            members=["reviewer-1", "reviewer-2"],
            strategy=ApproverRoutingStrategy.ROUND_ROBIN,
        )
        await db[APPROVER_GROUPS].insert_one(group.model_dump(mode="json"))

        ticket = await escalation_manager.create_ticket(
            **base_ticket_kwargs,
            approver_group_id="review-team",
        )
        assert ticket.assigned_to == "reviewer-1"


# ---------- APEP-077: Approval Memory ----------


class TestApprovalMemory:
    @pytest.mark.asyncio
    async def test_approval_memory_skips_re_escalation(
        self, mock_mongodb, base_ticket_kwargs
    ):
        # Create and approve first ticket
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)
        await escalation_manager.resolve_ticket(
            EscalationResolveRequest(
                ticket_id=ticket.ticket_id,
                state=EscalationState.APPROVED,
                decided_by="admin",
            )
        )

        # Second ticket with same args → should be auto-approved via memory
        kwargs2 = {**base_ticket_kwargs, "request_id": uuid4()}
        ticket2 = await escalation_manager.create_ticket(**kwargs2)

        assert ticket2.state == EscalationState.APPROVED
        assert ticket2.decided_by == "approval_memory"

    @pytest.mark.asyncio
    async def test_denial_not_cached(self, mock_mongodb, base_ticket_kwargs):
        # Create and deny first ticket
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)
        await escalation_manager.resolve_ticket(
            EscalationResolveRequest(
                ticket_id=ticket.ticket_id,
                state=EscalationState.DENIED,
                decided_by="admin",
            )
        )

        # Second ticket with same args → should NOT be auto-approved
        kwargs2 = {**base_ticket_kwargs, "request_id": uuid4()}
        ticket2 = await escalation_manager.create_ticket(**kwargs2)

        assert ticket2.state == EscalationState.PENDING

    @pytest.mark.asyncio
    async def test_different_args_not_cached(self, mock_mongodb, base_ticket_kwargs):
        # Create and approve first ticket
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)
        await escalation_manager.resolve_ticket(
            EscalationResolveRequest(
                ticket_id=ticket.ticket_id,
                state=EscalationState.APPROVED,
                decided_by="admin",
            )
        )

        # Different tool args → should NOT be auto-approved
        kwargs2 = {
            **base_ticket_kwargs,
            "request_id": uuid4(),
            "tool_args": {"path": "/etc/shadow", "content": "malicious"},
        }
        ticket2 = await escalation_manager.create_ticket(**kwargs2)
        assert ticket2.state == EscalationState.PENDING

    @pytest.mark.asyncio
    async def test_approval_memory_entry_stored(self, mock_mongodb, base_ticket_kwargs):
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)
        await escalation_manager.resolve_ticket(
            EscalationResolveRequest(
                ticket_id=ticket.ticket_id,
                state=EscalationState.APPROVED,
                decided_by="admin",
            )
        )

        db = db_module.get_database()
        entry = await db[APPROVAL_MEMORY].find_one(
            {"agent_id": "agent-alpha", "tool_name": "file_write"}
        )
        assert entry is not None
        assert entry["approved_by"] == "admin"


# ---------- APEP-078/079: Notification Webhooks ----------


class TestNotificationWebhooks:
    @pytest.mark.asyncio
    async def test_email_notification_sent(self, mock_mongodb, base_ticket_kwargs):
        escalation_manager.set_notification_config(
            NotificationConfig(
                email_webhook_url="https://hooks.example.com/email",
                email_recipients=["admin@example.com"],
            )
        )

        with patch("app.services.escalation_manager.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_response = AsyncMock()
            mock_response.raise_for_status = lambda: None
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_cls.return_value = mock_client

            await escalation_manager.create_ticket(**base_ticket_kwargs)

            mock_client.post.assert_called()
            call_args = mock_client.post.call_args
            assert call_args[0][0] == "https://hooks.example.com/email"
            payload = call_args[1]["json"]
            assert payload["event"] == "ESCALATE"
            assert payload["agent_id"] == "agent-alpha"

    @pytest.mark.asyncio
    async def test_slack_notification_sent(self, mock_mongodb, base_ticket_kwargs):
        escalation_manager.set_notification_config(
            NotificationConfig(
                slack_webhook_url="https://hooks.slack.com/services/test",
                slack_channel="#security-alerts",
            )
        )

        with patch("app.services.escalation_manager.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_response = AsyncMock()
            mock_response.raise_for_status = lambda: None
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_cls.return_value = mock_client

            await escalation_manager.create_ticket(**base_ticket_kwargs)

            mock_client.post.assert_called()
            call_args = mock_client.post.call_args
            assert call_args[0][0] == "https://hooks.slack.com/services/test"
            payload = call_args[1]["json"]
            assert "AgentPEP Escalation" in payload["text"]
            assert payload["channel"] == "#security-alerts"

    @pytest.mark.asyncio
    async def test_no_notifications_when_disabled(self, mock_mongodb, base_ticket_kwargs):
        escalation_manager.set_notification_config(
            NotificationConfig(enabled=False)
        )

        with patch("app.services.escalation_manager.httpx.AsyncClient") as mock_cls:
            await escalation_manager.create_ticket(**base_ticket_kwargs)
            mock_cls.assert_not_called()


# ---------- APEP-074: WebSocket Broadcast ----------


class TestWebSocketBroadcast:
    @pytest.mark.asyncio
    async def test_broadcast_called_on_create(self, mock_mongodb, base_ticket_kwargs):
        mock_callback = AsyncMock()
        escalation_manager.set_websocket_callback(mock_callback)

        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)

        mock_callback.assert_called_once()
        broadcast_ticket = mock_callback.call_args[0][0]
        assert broadcast_ticket.ticket_id == ticket.ticket_id
        assert broadcast_ticket.state == EscalationState.PENDING

    @pytest.mark.asyncio
    async def test_broadcast_called_on_resolve(self, mock_mongodb, base_ticket_kwargs):
        mock_callback = AsyncMock()
        escalation_manager.set_websocket_callback(mock_callback)

        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)

        await escalation_manager.resolve_ticket(
            EscalationResolveRequest(
                ticket_id=ticket.ticket_id,
                state=EscalationState.APPROVED,
                decided_by="admin",
            )
        )

        # Called twice: once for create, once for resolve
        assert mock_callback.call_count == 2

    @pytest.mark.asyncio
    async def test_ws_manager_serialize_ticket(self):
        ticket = EscalationTicket(
            request_id=uuid4(),
            session_id="sess-ws",
            agent_id="agent-ws",
            tool_name="shell_exec",
            risk_score=0.95,
            reason="High risk tool",
        )
        payload = escalation_ws_manager._serialize_ticket(ticket)
        assert payload["event"] == "ESCALATE"
        assert payload["session_id"] == "sess-ws"
        assert payload["risk_score"] == 0.95
        assert payload["state"] == "PENDING"
        assert payload["resolved_at"] is None

    @pytest.mark.asyncio
    async def test_broadcast_failure_does_not_block(
        self, mock_mongodb, base_ticket_kwargs
    ):
        async def failing_callback(ticket):
            raise RuntimeError("WebSocket broadcast failed")

        escalation_manager.set_websocket_callback(failing_callback)

        # Should not raise — ticket creation succeeds despite WS failure
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)
        assert ticket.state == EscalationState.PENDING


# ---------- REST API Integration ----------


class TestEscalationAPI:
    @pytest.mark.asyncio
    async def test_list_pending_tickets_endpoint(
        self, mock_mongodb, http_client, base_ticket_kwargs
    ):
        await escalation_manager.create_ticket(**base_ticket_kwargs)

        resp = await http_client.get("/v1/escalation/tickets/pending")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["state"] == "PENDING"

    @pytest.mark.asyncio
    async def test_get_ticket_endpoint(
        self, mock_mongodb, http_client, base_ticket_kwargs
    ):
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)

        resp = await http_client.get(
            f"/v1/escalation/tickets/{ticket.ticket_id}"
        )
        assert resp.status_code == 200
        assert resp.json()["agent_id"] == "agent-alpha"

    @pytest.mark.asyncio
    async def test_get_ticket_not_found(self, mock_mongodb, http_client):
        resp = await http_client.get(
            f"/v1/escalation/tickets/{uuid4()}"
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_resolve_ticket_endpoint(
        self, mock_mongodb, http_client, base_ticket_kwargs
    ):
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)

        resp = await http_client.post(
            f"/v1/escalation/tickets/{ticket.ticket_id}/resolve",
            json={
                "ticket_id": str(ticket.ticket_id),
                "state": "APPROVED",
                "decided_by": "api-admin",
                "decision_reason": "Approved via API",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["state"] == "APPROVED"
        assert resp.json()["decided_by"] == "api-admin"

    @pytest.mark.asyncio
    async def test_resolve_invalid_state(self, mock_mongodb, http_client, base_ticket_kwargs):
        ticket = await escalation_manager.create_ticket(**base_ticket_kwargs)

        resp = await http_client.post(
            f"/v1/escalation/tickets/{ticket.ticket_id}/resolve",
            json={
                "ticket_id": str(ticket.ticket_id),
                "state": "PENDING",
                "decided_by": "admin",
            },
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_approver_group_crud(self, mock_mongodb, http_client):
        # Create
        resp = await http_client.post(
            "/v1/escalation/approver-groups",
            json={
                "group_id": "test-group",
                "name": "Test Group",
                "members": ["u1", "u2"],
                "strategy": "ROUND_ROBIN",
            },
        )
        assert resp.status_code == 201

        # List
        resp = await http_client.get("/v1/escalation/approver-groups")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

        # Delete
        resp = await http_client.delete("/v1/escalation/approver-groups/test-group")
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_duplicate_approver_group(self, mock_mongodb, http_client):
        group_data = {
            "group_id": "dup-group",
            "name": "Dup",
            "members": ["u1"],
        }
        await http_client.post("/v1/escalation/approver-groups", json=group_data)
        resp = await http_client.post("/v1/escalation/approver-groups", json=group_data)
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_notification_config_update(self, mock_mongodb, http_client):
        resp = await http_client.put(
            "/v1/escalation/notifications/config",
            json={
                "email_webhook_url": "https://example.com/email",
                "slack_webhook_url": "https://hooks.slack.com/test",
                "slack_channel": "#alerts",
                "enabled": True,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["slack_channel"] == "#alerts"


# ---------- End-to-End Flow ----------


class TestEndToEndEscalationFlow:
    @pytest.mark.asyncio
    async def test_full_escalation_lifecycle(self, mock_mongodb, base_ticket_kwargs):
        """End-to-end: create → route → notify → await → resolve → memory."""
        db = db_module.get_database()

        # Setup approver group
        group = ApproverGroup(
            group_id="e2e-team",
            name="E2E Team",
            members=["approver-a", "approver-b"],
            strategy=ApproverRoutingStrategy.ROUND_ROBIN,
        )
        await db[APPROVER_GROUPS].insert_one(group.model_dump(mode="json"))

        # Track WebSocket broadcasts
        broadcasts: list[EscalationTicket] = []

        async def track_broadcast(ticket: EscalationTicket):
            broadcasts.append(ticket)

        escalation_manager.set_websocket_callback(track_broadcast)

        # 1. Create ticket with routing
        ticket = await escalation_manager.create_ticket(
            **base_ticket_kwargs,
            approver_group_id="e2e-team",
            timeout_seconds=10,
        )
        assert ticket.state == EscalationState.PENDING
        assert ticket.assigned_to == "approver-a"
        assert len(broadcasts) == 1

        # 2. Resolve concurrently with await
        async def resolve_after_delay():
            await asyncio.sleep(0.1)
            await escalation_manager.resolve_ticket(
                EscalationResolveRequest(
                    ticket_id=ticket.ticket_id,
                    state=EscalationState.APPROVED,
                    decided_by="approver-a",
                    decision_reason="Verified safe",
                )
            )

        task = asyncio.create_task(resolve_after_delay())
        result = await escalation_manager.await_resolution(ticket)
        await task

        assert result == EscalationState.APPROVED
        assert len(broadcasts) == 2  # Create + resolve

        # 3. Verify approval memory
        args_hash = escalation_manager.compute_args_hash(
            base_ticket_kwargs["tool_args"]
        )
        has_memory = await escalation_manager.check_approval_memory(
            "agent-alpha", "file_write", args_hash
        )
        assert has_memory is True

        # 4. Second identical request → auto-approved via memory
        kwargs2 = {**base_ticket_kwargs, "request_id": uuid4()}
        ticket2 = await escalation_manager.create_ticket(**kwargs2)
        assert ticket2.state == EscalationState.APPROVED
        assert ticket2.decided_by == "approval_memory"

    @pytest.mark.asyncio
    async def test_high_risk_timeout_deny_flow(self, mock_mongodb, base_ticket_kwargs):
        """High-risk escalation times out → auto-DENY."""
        ticket = await escalation_manager.create_ticket(
            **base_ticket_kwargs,
            timeout_seconds=1,
            timeout_action=EscalationState.DENIED,
        )

        result = await escalation_manager.await_resolution(ticket)
        assert result == EscalationState.DENIED

        # Verify DB state
        db = db_module.get_database()
        doc = await db[ESCALATION_TICKETS].find_one(
            {"ticket_id": str(ticket.ticket_id)}
        )
        assert doc["state"] == "TIMEOUT"
        assert "auto-DENIED" in doc["decision_reason"]

    @pytest.mark.asyncio
    async def test_low_risk_timeout_allow_flow(self, mock_mongodb):
        """Low-risk escalation times out → auto-ALLOW."""
        ticket = await escalation_manager.create_ticket(
            request_id=uuid4(),
            session_id="sess-low",
            agent_id="agent-low",
            tool_name="read_file",
            tool_args={"path": "/tmp/data.txt"},
            risk_score=0.2,
            timeout_seconds=1,
            timeout_action=EscalationState.APPROVED,
        )

        result = await escalation_manager.await_resolution(ticket)
        assert result == EscalationState.APPROVED
