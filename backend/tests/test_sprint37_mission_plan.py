"""Tests for Sprint 37 -- MissionPlan: Model, API & Lifecycle.

APEP-292: MissionPlan model tests.
APEP-293: Ed25519 plan signing tests.
APEP-294: POST /v1/plans tests.
APEP-295: GET /v1/plans/{plan_id} tests.
APEP-296: DELETE /v1/plans/{plan_id} tests.
APEP-297: Plan-session binding tests.
APEP-298: Plan TTL expiry background job tests.
APEP-299: Integration tests.
"""

import asyncio
import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.models.mission_plan import (
    BindPlanRequest,
    CreatePlanRequest,
    MissionPlan,
    PlanBudget,
    PlanDenialReason,
    PlanDetailResponse,
    PlanSessionBinding,
    PlanStatus,
)
from app.services.plan_signer import PlanSigner, _HAS_NACL


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plan(**overrides) -> MissionPlan:
    """Create a MissionPlan with sensible defaults for testing."""
    defaults = {
        "action": "Analyze Q3 finance reports",
        "issuer": "admin@example.com",
        "scope": ["read:public:*", "read:internal:reports.*"],
        "requires_checkpoint": ["write:secret:*"],
        "delegates_to": ["agent-alpha", "agent-beta"],
        "budget": PlanBudget(
            max_delegations=10,
            max_risk_total=5.0,
            ttl_seconds=3600,
        ),
    }
    defaults.update(overrides)
    plan = MissionPlan(**defaults)
    return plan


def _make_create_request(**overrides) -> CreatePlanRequest:
    defaults = {
        "action": "Analyze Q3 finance reports",
        "issuer": "admin@example.com",
        "scope": ["read:public:*"],
        "requires_checkpoint": ["write:secret:*"],
        "delegates_to": ["agent-alpha"],
        "budget": PlanBudget(max_delegations=10, ttl_seconds=3600),
    }
    defaults.update(overrides)
    return CreatePlanRequest(**defaults)


# ---------------------------------------------------------------------------
# APEP-292: MissionPlan Model Tests
# ---------------------------------------------------------------------------


class TestMissionPlanModel:
    """Unit tests for MissionPlan Pydantic model."""

    def test_create_with_defaults(self):
        plan = MissionPlan(action="test", issuer="user@test.com")
        assert plan.status == PlanStatus.ACTIVE
        assert plan.delegation_count == 0
        assert plan.accumulated_risk == 0.0
        assert plan.expires_at is None
        assert plan.signature == ""
        assert isinstance(plan.plan_id, UUID)

    def test_create_with_all_fields(self):
        plan = _make_plan()
        assert plan.action == "Analyze Q3 finance reports"
        assert plan.issuer == "admin@example.com"
        assert len(plan.scope) == 2
        assert len(plan.requires_checkpoint) == 1
        assert len(plan.delegates_to) == 2
        assert plan.budget.max_delegations == 10
        assert plan.budget.max_risk_total == 5.0
        assert plan.budget.ttl_seconds == 3600

    def test_is_active_when_active(self):
        plan = _make_plan()
        plan.expires_at = datetime.now(UTC) + timedelta(hours=1)
        assert plan.is_active is True

    def test_is_active_false_when_revoked(self):
        plan = _make_plan(status=PlanStatus.REVOKED)
        assert plan.is_active is False

    def test_is_active_false_when_expired_status(self):
        plan = _make_plan(status=PlanStatus.EXPIRED)
        assert plan.is_active is False

    def test_is_active_false_when_ttl_elapsed(self):
        plan = _make_plan()
        plan.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        assert plan.is_active is False

    def test_budget_exhausted_max_delegations(self):
        plan = _make_plan()
        plan.delegation_count = 10  # equals max_delegations
        assert plan.budget_exhausted is True

    def test_budget_exhausted_max_risk(self):
        plan = _make_plan()
        plan.accumulated_risk = 5.0  # equals max_risk_total
        assert plan.budget_exhausted is True

    def test_budget_not_exhausted(self):
        plan = _make_plan()
        plan.delegation_count = 5
        plan.accumulated_risk = 2.0
        assert plan.budget_exhausted is False

    def test_budget_unlimited(self):
        plan = _make_plan(
            budget=PlanBudget(
                max_delegations=None,
                max_risk_total=None,
                ttl_seconds=None,
            )
        )
        plan.delegation_count = 1000
        plan.accumulated_risk = 100.0
        assert plan.budget_exhausted is False

    def test_plan_status_enum(self):
        assert PlanStatus.ACTIVE == "ACTIVE"
        assert PlanStatus.EXPIRED == "EXPIRED"
        assert PlanStatus.REVOKED == "REVOKED"

    def test_plan_denial_reasons(self):
        assert PlanDenialReason.PLAN_BUDGET_EXHAUSTED == "PLAN_BUDGET_EXHAUSTED"
        assert PlanDenialReason.PLAN_EXPIRED == "PLAN_EXPIRED"
        assert PlanDenialReason.PLAN_REVOKED == "PLAN_REVOKED"
        assert PlanDenialReason.PLAN_AGENT_NOT_AUTHORIZED == "PLAN_AGENT_NOT_AUTHORIZED"
        assert PlanDenialReason.PLAN_NOT_BOUND == "PLAN_NOT_BOUND"

    def test_model_dump_json(self):
        plan = _make_plan()
        data = plan.model_dump(mode="json")
        assert "plan_id" in data
        assert data["status"] == "ACTIVE"
        assert data["budget"]["max_delegations"] == 10

    def test_model_roundtrip(self):
        plan = _make_plan()
        data = plan.model_dump(mode="json")
        restored = MissionPlan(**data)
        assert restored.plan_id == plan.plan_id
        assert restored.action == plan.action
        assert restored.budget.max_delegations == plan.budget.max_delegations


# ---------------------------------------------------------------------------
# APEP-293: PlanSigner Tests
# ---------------------------------------------------------------------------


class TestPlanSignerHMAC:
    """Tests for HMAC-SHA256 plan signing."""

    def test_sign_returns_plan_signature(self):
        signer = PlanSigner(signing_method="hmac-sha256", key_id="k1")
        plan = _make_plan()
        sig = signer.sign_plan(plan)
        assert sig.startswith("agentpep-plan-v1|k1|hmac-sha256|")
        parts = sig.split("|")
        assert len(parts) == 5

    def test_sign_is_deterministic(self):
        key = os.urandom(32)
        signer = PlanSigner(signing_method="hmac-sha256", private_key=key)
        plan = _make_plan()
        s1 = signer.sign_plan(plan)
        s2 = signer.sign_plan(plan)
        assert s1 == s2

    def test_different_plans_produce_different_signatures(self):
        signer = PlanSigner(signing_method="hmac-sha256")
        plan1 = _make_plan(action="Action A")
        plan2 = _make_plan(action="Action B")
        assert signer.sign_plan(plan1) != signer.sign_plan(plan2)

    def test_verify_valid_signature(self):
        key = os.urandom(32)
        signer = PlanSigner(signing_method="hmac-sha256", private_key=key)
        plan = _make_plan()
        plan.signature = signer.sign_plan(plan)
        assert signer.verify_plan(plan) is True

    def test_verify_tampered_plan(self):
        key = os.urandom(32)
        signer = PlanSigner(signing_method="hmac-sha256", private_key=key)
        plan = _make_plan()
        plan.signature = signer.sign_plan(plan)
        plan.action = "TAMPERED"
        assert signer.verify_plan(plan) is False

    def test_verify_empty_signature(self):
        signer = PlanSigner(signing_method="hmac-sha256")
        plan = _make_plan()
        assert signer.verify_plan(plan) is False

    def test_verify_malformed_signature(self):
        signer = PlanSigner(signing_method="hmac-sha256")
        plan = _make_plan()
        plan.signature = "not-a-valid-signature"
        assert signer.verify_plan(plan) is False

    def test_get_verify_key_bytes(self):
        key = os.urandom(32)
        signer = PlanSigner(signing_method="hmac-sha256", private_key=key)
        assert signer.get_verify_key_bytes() == key

    def test_canonicalize_excludes_runtime_fields(self):
        plan = _make_plan()
        plan.delegation_count = 5
        plan.accumulated_risk = 1.0
        plan.status = PlanStatus.REVOKED

        canonical = PlanSigner.canonicalize(plan)
        import json

        data = json.loads(canonical)
        assert "delegation_count" not in data
        assert "accumulated_risk" not in data
        assert "status" not in data

    def test_canonicalize_is_deterministic(self):
        plan = _make_plan()
        c1 = PlanSigner.canonicalize(plan)
        c2 = PlanSigner.canonicalize(plan)
        assert c1 == c2

    def test_method_property(self):
        signer = PlanSigner(signing_method="hmac-sha256")
        assert signer.method == "hmac-sha256"


@pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
class TestPlanSignerEd25519:
    """Tests for Ed25519 plan signing (requires PyNaCl)."""

    def test_sign_returns_ed25519_signature(self):
        signer = PlanSigner(signing_method="ed25519", key_id="ed-k1")
        plan = _make_plan()
        sig = signer.sign_plan(plan)
        assert sig.startswith("agentpep-plan-v1|ed-k1|ed25519|")
        parts = sig.split("|")
        assert len(parts) == 5

    def test_verify_valid_ed25519_signature(self):
        signer = PlanSigner(signing_method="ed25519")
        plan = _make_plan()
        plan.signature = signer.sign_plan(plan)
        assert signer.verify_plan(plan) is True

    def test_verify_tampered_ed25519(self):
        signer = PlanSigner(signing_method="ed25519")
        plan = _make_plan()
        plan.signature = signer.sign_plan(plan)
        plan.action = "TAMPERED"
        assert signer.verify_plan(plan) is False

    def test_ed25519_different_plans(self):
        signer = PlanSigner(signing_method="ed25519")
        plan1 = _make_plan(action="A")
        plan2 = _make_plan(action="B")
        assert signer.sign_plan(plan1) != signer.sign_plan(plan2)

    def test_ed25519_verify_key_bytes(self):
        signer = PlanSigner(signing_method="ed25519")
        vk = signer.get_verify_key_bytes()
        assert len(vk) == 32

    def test_ed25519_with_provided_key(self):
        import nacl.signing

        seed = nacl.signing.SigningKey.generate()
        signer = PlanSigner(
            signing_method="ed25519", private_key=bytes(seed)
        )
        plan = _make_plan()
        plan.signature = signer.sign_plan(plan)
        assert signer.verify_plan(plan) is True

    def test_method_property_ed25519(self):
        signer = PlanSigner(signing_method="ed25519")
        assert signer.method == "ed25519"


# ---------------------------------------------------------------------------
# APEP-294..298: MissionPlanService Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMissionPlanService:
    """Unit tests for MissionPlanService CRUD and lifecycle operations."""

    async def test_create_plan(self, mock_mongodb):
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        req = _make_create_request()
        plan = await mission_plan_service.create_plan(req)

        assert plan.status == PlanStatus.ACTIVE
        assert plan.action == req.action
        assert plan.issuer == req.issuer
        assert plan.signature != ""
        assert plan.expires_at is not None

    async def test_create_plan_without_ttl(self, mock_mongodb):
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        req = _make_create_request(
            budget=PlanBudget(max_delegations=5, ttl_seconds=None)
        )
        plan = await mission_plan_service.create_plan(req)
        assert plan.expires_at is None

    async def test_get_plan(self, mock_mongodb):
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        req = _make_create_request()
        created = await mission_plan_service.create_plan(req)

        fetched = await mission_plan_service.get_plan(created.plan_id)
        assert fetched is not None
        assert fetched.plan_id == created.plan_id
        assert fetched.action == created.action

    async def test_get_plan_not_found(self, mock_mongodb):
        from app.services.mission_plan_service import mission_plan_service

        result = await mission_plan_service.get_plan(uuid4())
        assert result is None

    async def test_get_plan_detail(self, mock_mongodb):
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        req = _make_create_request()
        created = await mission_plan_service.create_plan(req)

        detail = await mission_plan_service.get_plan_detail(created.plan_id)
        assert detail is not None
        assert isinstance(detail, PlanDetailResponse)
        assert detail.is_active is True
        assert detail.budget_exhausted is False

    async def test_revoke_plan(self, mock_mongodb):
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        req = _make_create_request()
        created = await mission_plan_service.create_plan(req)

        result = await mission_plan_service.revoke_plan(created.plan_id)
        assert result is not None
        assert result.status == PlanStatus.REVOKED

        # Verify plan is actually revoked in DB
        fetched = await mission_plan_service.get_plan(created.plan_id)
        assert fetched is not None
        assert fetched.status == PlanStatus.REVOKED
        assert fetched.is_active is False

    async def test_revoke_nonexistent_plan(self, mock_mongodb):
        from app.services.mission_plan_service import mission_plan_service

        result = await mission_plan_service.revoke_plan(uuid4())
        assert result is None

    async def test_bind_session(self, mock_mongodb):
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        req = _make_create_request()
        plan = await mission_plan_service.create_plan(req)

        bind_req = BindPlanRequest(
            session_id="session-123", agent_id="agent-alpha"
        )
        result = await mission_plan_service.bind_session(plan.plan_id, bind_req)
        assert result is not None
        assert result.plan_id == plan.plan_id
        assert result.session_id == "session-123"

    async def test_bind_session_inactive_plan(self, mock_mongodb):
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        req = _make_create_request()
        plan = await mission_plan_service.create_plan(req)
        await mission_plan_service.revoke_plan(plan.plan_id)

        bind_req = BindPlanRequest(
            session_id="session-123", agent_id="agent-alpha"
        )
        result = await mission_plan_service.bind_session(plan.plan_id, bind_req)
        assert result is None

    async def test_get_plan_for_session(self, mock_mongodb):
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        req = _make_create_request()
        plan = await mission_plan_service.create_plan(req)

        bind_req = BindPlanRequest(
            session_id="session-456", agent_id="agent-alpha"
        )
        await mission_plan_service.bind_session(plan.plan_id, bind_req)

        fetched = await mission_plan_service.get_plan_for_session("session-456")
        assert fetched is not None
        assert fetched.plan_id == plan.plan_id

    async def test_get_plan_for_unbound_session(self, mock_mongodb):
        from app.services.mission_plan_service import mission_plan_service

        result = await mission_plan_service.get_plan_for_session("no-such-session")
        assert result is None

    async def test_unbind_session(self, mock_mongodb):
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        req = _make_create_request()
        plan = await mission_plan_service.create_plan(req)

        bind_req = BindPlanRequest(
            session_id="session-789", agent_id="agent-alpha"
        )
        await mission_plan_service.bind_session(plan.plan_id, bind_req)

        unbound = await mission_plan_service.unbind_session("session-789")
        assert unbound is True

        fetched = await mission_plan_service.get_plan_for_session("session-789")
        assert fetched is None

    async def test_record_delegation(self, mock_mongodb):
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        req = _make_create_request()
        plan = await mission_plan_service.create_plan(req)

        await mission_plan_service.record_delegation(plan.plan_id, 0.3)
        await mission_plan_service.record_delegation(plan.plan_id, 0.2)

        updated = await mission_plan_service.get_plan(plan.plan_id)
        assert updated is not None
        assert updated.delegation_count == 2
        assert abs(updated.accumulated_risk - 0.5) < 0.001

    async def test_check_plan_budget_active(self, mock_mongodb):
        from app.services.mission_plan_service import mission_plan_service

        plan = _make_plan()
        plan.expires_at = datetime.now(UTC) + timedelta(hours=1)
        result = await mission_plan_service.check_plan_budget(plan)
        assert result is None

    async def test_check_plan_budget_revoked(self, mock_mongodb):
        from app.services.mission_plan_service import mission_plan_service

        plan = _make_plan(status=PlanStatus.REVOKED)
        result = await mission_plan_service.check_plan_budget(plan)
        assert result == PlanDenialReason.PLAN_REVOKED

    async def test_check_plan_budget_expired(self, mock_mongodb):
        from app.services.mission_plan_service import mission_plan_service

        plan = _make_plan(status=PlanStatus.EXPIRED)
        result = await mission_plan_service.check_plan_budget(plan)
        assert result == PlanDenialReason.PLAN_EXPIRED

    async def test_check_plan_budget_ttl_elapsed(self, mock_mongodb):
        from app.services.mission_plan_service import mission_plan_service

        plan = _make_plan()
        plan.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        result = await mission_plan_service.check_plan_budget(plan)
        assert result == PlanDenialReason.PLAN_EXPIRED

    async def test_check_plan_budget_exhausted(self, mock_mongodb):
        from app.services.mission_plan_service import mission_plan_service

        plan = _make_plan()
        plan.delegation_count = 10  # equals max_delegations
        plan.expires_at = datetime.now(UTC) + timedelta(hours=1)
        result = await mission_plan_service.check_plan_budget(plan)
        assert result == PlanDenialReason.PLAN_BUDGET_EXHAUSTED

    def test_check_agent_authorized(self):
        from app.services.mission_plan_service import mission_plan_service

        plan = _make_plan(delegates_to=["agent-alpha", "agent-beta"])
        assert mission_plan_service.check_agent_authorized(plan, "agent-alpha") is True
        assert mission_plan_service.check_agent_authorized(plan, "agent-gamma") is False

    def test_check_agent_authorized_empty_delegates(self):
        from app.services.mission_plan_service import mission_plan_service

        plan = _make_plan(delegates_to=[])
        # Empty means no restriction
        assert mission_plan_service.check_agent_authorized(plan, "any-agent") is True

    def test_check_requires_checkpoint(self):
        from app.services.mission_plan_service import mission_plan_service

        plan = _make_plan(requires_checkpoint=["write:secret:*", "delete:*:*"])
        assert (
            mission_plan_service.check_requires_checkpoint(plan, "write:secret:passwords")
            is True
        )
        assert (
            mission_plan_service.check_requires_checkpoint(plan, "read:public:reports")
            is False
        )
        assert (
            mission_plan_service.check_requires_checkpoint(plan, "delete:internal:users")
            is True
        )


# ---------------------------------------------------------------------------
# APEP-298: Plan TTL Expiry Job Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestPlanExpiryJob:
    """Unit tests for plan TTL expiry background job."""

    async def test_expire_plans(self, mock_mongodb):
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import (
            PlanExpiryJob,
            mission_plan_service,
        )

        # Create a plan that should be expired
        req = _make_create_request(
            budget=PlanBudget(ttl_seconds=1)  # 1 second TTL
        )
        plan = await mission_plan_service.create_plan(req)

        # Wait for the plan to expire
        await asyncio.sleep(1.1)

        job = PlanExpiryJob()
        count = await job.expire_plans()
        assert count >= 1

        # Verify plan is now expired
        fetched = await mission_plan_service.get_plan(plan.plan_id)
        assert fetched is not None
        assert fetched.status == PlanStatus.EXPIRED

    async def test_expire_plans_no_expired(self, mock_mongodb):
        from app.services.mission_plan_service import PlanExpiryJob

        job = PlanExpiryJob()
        count = await job.expire_plans()
        assert count == 0


# ---------------------------------------------------------------------------
# APEP-294..296: API Endpoint Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestPlanAPIEndpoints:
    """Integration tests for plan REST API endpoints."""

    @pytest.fixture
    async def client(self, mock_mongodb):
        """Create an HTTPX async client for the FastAPI app."""
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from tests.conftest import _get_auth_headers

        from app.main import app

        transport = ASGITransport(app=app)
        async with AsyncClient(
            transport=transport,
            base_url="http://test",
            headers=_get_auth_headers(),
        ) as c:
            yield c

    async def test_create_plan_endpoint(self, client):
        response = await client.post(
            "/v1/plans",
            json={
                "action": "Test action",
                "issuer": "test@example.com",
                "scope": ["read:public:*"],
                "delegates_to": ["agent-1"],
                "budget": {"max_delegations": 5, "ttl_seconds": 600},
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["action"] == "Test action"
        assert data["issuer"] == "test@example.com"
        assert data["status"] == "ACTIVE"
        assert data["signature"] != ""
        assert "plan_id" in data

    async def test_get_plan_endpoint(self, client):
        # Create a plan first
        create_resp = await client.post(
            "/v1/plans",
            json={
                "action": "Get test",
                "issuer": "test@example.com",
                "scope": ["read:public:*"],
                "budget": {"max_delegations": 5},
            },
        )
        plan_id = create_resp.json()["plan_id"]

        # Retrieve it
        response = await client.get(f"/v1/plans/{plan_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["plan_id"] == plan_id
        assert data["action"] == "Get test"
        assert data["is_active"] is True
        assert data["budget_exhausted"] is False

    async def test_get_plan_not_found(self, client):
        response = await client.get(f"/v1/plans/{uuid4()}")
        assert response.status_code == 404

    async def test_revoke_plan_endpoint(self, client):
        # Create a plan
        create_resp = await client.post(
            "/v1/plans",
            json={
                "action": "Revoke test",
                "issuer": "test@example.com",
            },
        )
        plan_id = create_resp.json()["plan_id"]

        # Revoke it
        response = await client.delete(f"/v1/plans/{plan_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "REVOKED"

        # Verify revoked
        get_resp = await client.get(f"/v1/plans/{plan_id}")
        assert get_resp.json()["status"] == "REVOKED"
        assert get_resp.json()["is_active"] is False

    async def test_revoke_plan_not_found(self, client):
        response = await client.delete(f"/v1/plans/{uuid4()}")
        assert response.status_code == 404

    async def test_bind_plan_endpoint(self, client):
        # Create a plan
        create_resp = await client.post(
            "/v1/plans",
            json={
                "action": "Bind test",
                "issuer": "test@example.com",
                "delegates_to": ["agent-1"],
            },
        )
        plan_id = create_resp.json()["plan_id"]

        # Bind a session
        response = await client.post(
            f"/v1/plans/{plan_id}/bind",
            json={"session_id": "sess-001", "agent_id": "agent-1"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["plan_id"] == plan_id
        assert data["session_id"] == "sess-001"
        assert data["agent_id"] == "agent-1"

    async def test_bind_plan_inactive(self, client):
        # Create and revoke a plan
        create_resp = await client.post(
            "/v1/plans",
            json={
                "action": "Bind inactive test",
                "issuer": "test@example.com",
            },
        )
        plan_id = create_resp.json()["plan_id"]
        await client.delete(f"/v1/plans/{plan_id}")

        # Try to bind
        response = await client.post(
            f"/v1/plans/{plan_id}/bind",
            json={"session_id": "sess-002", "agent_id": "agent-1"},
        )
        assert response.status_code == 400

    async def test_create_plan_validation_error(self, client):
        # Missing required field 'action'
        response = await client.post(
            "/v1/plans",
            json={"issuer": "test@example.com"},
        )
        assert response.status_code == 422
