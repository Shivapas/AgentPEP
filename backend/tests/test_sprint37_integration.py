"""Sprint 37 integration and adversarial tests.

APEP-293.g: Adversarial tests for Ed25519 plan signing.
APEP-299: Integration tests for MissionPlan pipeline.
"""

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.models.mission_plan import (
    BindPlanRequest,
    CreatePlanRequest,
    MissionPlan,
    PlanBudget,
    PlanDenialReason,
    PlanStatus,
)
from app.models.policy import Decision
from app.services.plan_signer import PlanSigner, _HAS_NACL


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plan(**overrides) -> MissionPlan:
    defaults = {
        "action": "Integration test plan",
        "issuer": "admin@example.com",
        "scope": ["read:public:*"],
        "requires_checkpoint": ["write:secret:*"],
        "delegates_to": ["agent-alpha", "agent-beta"],
        "budget": PlanBudget(max_delegations=10, max_risk_total=5.0, ttl_seconds=3600),
    }
    defaults.update(overrides)
    return MissionPlan(**defaults)


def _make_create_request(**overrides) -> CreatePlanRequest:
    defaults = {
        "action": "Integration test",
        "issuer": "admin@example.com",
        "scope": ["read:public:*"],
        "delegates_to": ["agent-alpha"],
        "budget": PlanBudget(max_delegations=10, ttl_seconds=3600),
    }
    defaults.update(overrides)
    return CreatePlanRequest(**defaults)


# ---------------------------------------------------------------------------
# APEP-293.g: Adversarial Tests for Ed25519 Plan Signing
# ---------------------------------------------------------------------------


class TestPlanSignerAdversarial:
    """Adversarial tests: tampered data, wrong keys, corrupted signatures."""

    def test_wrong_key_rejects_signature(self):
        signer1 = PlanSigner(signing_method="hmac-sha256", private_key=os.urandom(32))
        signer2 = PlanSigner(signing_method="hmac-sha256", private_key=os.urandom(32))
        plan = _make_plan()
        plan.signature = signer1.sign_plan(plan)
        # signer2 has a different key -- should reject
        assert signer2.verify_plan(plan) is False

    def test_tampered_scope_detected(self):
        key = os.urandom(32)
        signer = PlanSigner(signing_method="hmac-sha256", private_key=key)
        plan = _make_plan()
        plan.signature = signer.sign_plan(plan)
        plan.scope = ["write:secret:*"]  # tamper scope
        assert signer.verify_plan(plan) is False

    def test_tampered_issuer_detected(self):
        key = os.urandom(32)
        signer = PlanSigner(signing_method="hmac-sha256", private_key=key)
        plan = _make_plan()
        plan.signature = signer.sign_plan(plan)
        plan.issuer = "attacker@evil.com"
        assert signer.verify_plan(plan) is False

    def test_tampered_delegates_to_detected(self):
        key = os.urandom(32)
        signer = PlanSigner(signing_method="hmac-sha256", private_key=key)
        plan = _make_plan()
        plan.signature = signer.sign_plan(plan)
        plan.delegates_to = ["agent-attacker"]
        assert signer.verify_plan(plan) is False

    def test_tampered_budget_detected(self):
        key = os.urandom(32)
        signer = PlanSigner(signing_method="hmac-sha256", private_key=key)
        plan = _make_plan()
        plan.signature = signer.sign_plan(plan)
        plan.budget.max_delegations = 99999
        assert signer.verify_plan(plan) is False

    def test_truncated_signature_rejected(self):
        key = os.urandom(32)
        signer = PlanSigner(signing_method="hmac-sha256", private_key=key)
        plan = _make_plan()
        full_sig = signer.sign_plan(plan)
        plan.signature = full_sig[:20]
        assert signer.verify_plan(plan) is False

    def test_extra_pipe_chars_rejected(self):
        key = os.urandom(32)
        signer = PlanSigner(signing_method="hmac-sha256", private_key=key)
        plan = _make_plan()
        sig = signer.sign_plan(plan)
        plan.signature = sig + "|extra"
        assert signer.verify_plan(plan) is False

    def test_empty_string_signature(self):
        signer = PlanSigner(signing_method="hmac-sha256")
        plan = _make_plan()
        plan.signature = ""
        assert signer.verify_plan(plan) is False

    def test_null_byte_injection(self):
        signer = PlanSigner(signing_method="hmac-sha256")
        plan = _make_plan()
        plan.signature = "agentpep-plan-v1|k1|hmac-sha256|\x00\x00|\x00\x00"
        assert signer.verify_plan(plan) is False

    @pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
    def test_ed25519_wrong_key_rejects(self):
        signer1 = PlanSigner(signing_method="ed25519")
        signer2 = PlanSigner(signing_method="ed25519")
        plan = _make_plan()
        plan.signature = signer1.sign_plan(plan)
        assert signer2.verify_plan(plan) is False

    @pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
    def test_ed25519_tampered_plan_rejected(self):
        signer = PlanSigner(signing_method="ed25519")
        plan = _make_plan()
        plan.signature = signer.sign_plan(plan)
        plan.action = "EVIL ACTION"
        assert signer.verify_plan(plan) is False

    @pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")
    def test_ed25519_tampered_requires_checkpoint(self):
        signer = PlanSigner(signing_method="ed25519")
        plan = _make_plan()
        plan.signature = signer.sign_plan(plan)
        plan.requires_checkpoint = []  # remove safety checkpoints
        assert signer.verify_plan(plan) is False

    def test_replay_signature_on_different_plan(self):
        key = os.urandom(32)
        signer = PlanSigner(signing_method="hmac-sha256", private_key=key)
        plan_a = _make_plan(action="Plan A")
        plan_b = _make_plan(action="Plan B")
        sig_a = signer.sign_plan(plan_a)
        plan_b.signature = sig_a  # Replay plan A's sig on plan B
        assert signer.verify_plan(plan_b) is False


# ---------------------------------------------------------------------------
# APEP-299: Integration Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestMissionPlanIntegration:
    """End-to-end integration tests for the MissionPlan lifecycle."""

    @pytest.fixture
    async def client(self, mock_mongodb):
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

    async def test_full_plan_lifecycle(self, client):
        """Test create -> get -> bind -> revoke lifecycle."""
        # 1. Create
        create_resp = await client.post(
            "/v1/plans",
            json={
                "action": "Full lifecycle test",
                "issuer": "admin@example.com",
                "scope": ["read:public:*"],
                "delegates_to": ["agent-1"],
                "budget": {"max_delegations": 5, "ttl_seconds": 600},
            },
        )
        assert create_resp.status_code == 201
        plan_id = create_resp.json()["plan_id"]

        # 2. Get
        get_resp = await client.get(f"/v1/plans/{plan_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["is_active"] is True

        # 3. Bind
        bind_resp = await client.post(
            f"/v1/plans/{plan_id}/bind",
            json={"session_id": "sess-lifecycle", "agent_id": "agent-1"},
        )
        assert bind_resp.status_code == 201

        # 4. Revoke
        revoke_resp = await client.delete(f"/v1/plans/{plan_id}")
        assert revoke_resp.status_code == 200
        assert revoke_resp.json()["status"] == "REVOKED"

        # 5. Verify revoked
        get_resp2 = await client.get(f"/v1/plans/{plan_id}")
        assert get_resp2.json()["is_active"] is False

    async def test_plan_budget_delegation_tracking(self, client, mock_mongodb):
        """Test that delegations are tracked and budget exhaustion works."""
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        req = _make_create_request(
            budget=PlanBudget(max_delegations=3)
        )
        plan = await mission_plan_service.create_plan(req)

        # Record 3 delegations
        for _ in range(3):
            await mission_plan_service.record_delegation(plan.plan_id, 0.1)

        updated = await mission_plan_service.get_plan(plan.plan_id)
        assert updated is not None
        assert updated.delegation_count == 3
        assert updated.budget_exhausted is True

        # Budget check should now return exhausted
        denial = await mission_plan_service.check_plan_budget(updated)
        assert denial == PlanDenialReason.PLAN_BUDGET_EXHAUSTED

    async def test_plan_risk_budget_exhaustion(self, client, mock_mongodb):
        """Test that risk accumulation exhausts the plan budget."""
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        req = _make_create_request(
            budget=PlanBudget(max_risk_total=1.0)
        )
        plan = await mission_plan_service.create_plan(req)

        # Accumulate risk beyond max
        await mission_plan_service.record_delegation(plan.plan_id, 0.6)
        await mission_plan_service.record_delegation(plan.plan_id, 0.5)

        updated = await mission_plan_service.get_plan(plan.plan_id)
        assert updated is not None
        assert updated.accumulated_risk >= 1.0
        assert updated.budget_exhausted is True

    async def test_plan_session_rebinding(self, client, mock_mongodb):
        """Test that binding a session to a new plan unbinds the old one."""
        import app.services.plan_signer as ps_mod

        ps_mod.plan_signer = PlanSigner(signing_method="hmac-sha256")

        from app.services.mission_plan_service import mission_plan_service

        # Create two plans
        plan_a = await mission_plan_service.create_plan(
            _make_create_request(action="Plan A")
        )
        plan_b = await mission_plan_service.create_plan(
            _make_create_request(action="Plan B")
        )

        # Bind session to plan A
        await mission_plan_service.bind_session(
            plan_a.plan_id,
            BindPlanRequest(session_id="sess-rebind", agent_id="agent-1"),
        )
        found = await mission_plan_service.get_plan_for_session("sess-rebind")
        assert found is not None
        assert found.plan_id == plan_a.plan_id

        # Unbind and bind to plan B
        await mission_plan_service.unbind_session("sess-rebind")
        await mission_plan_service.bind_session(
            plan_b.plan_id,
            BindPlanRequest(session_id="sess-rebind", agent_id="agent-1"),
        )
        found = await mission_plan_service.get_plan_for_session("sess-rebind")
        assert found is not None
        assert found.plan_id == plan_b.plan_id

    async def test_plan_pipeline_checkpoint_filter(self, mock_mongodb):
        """Test that checkpoint patterns trigger ESCALATE in the pipeline."""
        from app.services.mission_plan_service import mission_plan_service

        plan = _make_plan(requires_checkpoint=["file.write", "admin.*"])

        assert mission_plan_service.check_requires_checkpoint(plan, "file.write") is True
        assert mission_plan_service.check_requires_checkpoint(plan, "admin.delete") is True
        assert mission_plan_service.check_requires_checkpoint(plan, "file.read") is False

    async def test_plan_pipeline_delegates_filter(self, mock_mongodb):
        """Test that unauthorized agents are denied by delegates_to filter."""
        from app.services.mission_plan_service import mission_plan_service

        plan = _make_plan(delegates_to=["agent-alpha", "agent-beta"])

        assert mission_plan_service.check_agent_authorized(plan, "agent-alpha") is True
        assert mission_plan_service.check_agent_authorized(plan, "agent-beta") is True
        assert mission_plan_service.check_agent_authorized(plan, "agent-gamma") is False

    async def test_create_multiple_plans_different_issuers(self, client):
        """Test that different issuers can create independent plans."""
        for i in range(3):
            resp = await client.post(
                "/v1/plans",
                json={
                    "action": f"Plan {i}",
                    "issuer": f"user{i}@example.com",
                    "scope": ["read:public:*"],
                },
            )
            assert resp.status_code == 201
            assert resp.json()["issuer"] == f"user{i}@example.com"

    async def test_signature_integrity_persists_across_retrieval(self, client):
        """Test that a plan's signature is preserved after creation and retrieval."""
        create_resp = await client.post(
            "/v1/plans",
            json={
                "action": "Sig integrity test",
                "issuer": "admin@example.com",
                "scope": ["read:public:*"],
                "budget": {"max_delegations": 5},
            },
        )
        plan_id = create_resp.json()["plan_id"]
        original_sig = create_resp.json()["signature"]

        get_resp = await client.get(f"/v1/plans/{plan_id}")
        assert get_resp.json()["signature"] == original_sig

    async def test_revoke_already_revoked_plan(self, client):
        """Test that revoking an already revoked plan returns its status."""
        create_resp = await client.post(
            "/v1/plans",
            json={
                "action": "Double revoke test",
                "issuer": "admin@example.com",
            },
        )
        plan_id = create_resp.json()["plan_id"]

        # Revoke once
        resp1 = await client.delete(f"/v1/plans/{plan_id}")
        assert resp1.status_code == 200

        # Revoke again -- should still return OK with REVOKED status
        resp2 = await client.delete(f"/v1/plans/{plan_id}")
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "REVOKED"
