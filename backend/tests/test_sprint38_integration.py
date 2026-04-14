"""Integration tests for Sprint 38 -- Scope Pattern Language & DSL Compiler.

APEP-302.g: Integration tests for ScopePatternCompiler.
APEP-307.b: Integration and adversarial tests verifying the scope pattern
             pipeline end-to-end, including PolicyEvaluator integration.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient
from tests.conftest import _get_auth_headers

from app.models.mission_plan import (
    CreatePlanRequest,
    MissionPlan,
    PlanBudget,
    PlanSessionBinding,
    PlanStatus,
)
from app.models.policy import Decision, PolicyRule, ToolCallRequest
from app.services.rule_cache import rule_cache
from app.services.scope_pattern import (
    PlanCheckpointFilter,
    PlanScopeFilter,
    ScopePatternCompiler,
    ScopePatternParser,
    plan_checkpoint_filter,
    plan_scope_filter,
    scope_pattern_compiler,
    scope_pattern_parser,
)

import app.db.mongodb as db_module


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plan(**overrides) -> MissionPlan:
    """Create a MissionPlan with sensible defaults for testing."""
    defaults = {
        "action": "Analyze Q3 reports",
        "issuer": "admin@example.com",
        "scope": ["read:public:*", "read:internal:reports.*"],
        "requires_checkpoint": ["write:secret:*"],
        "delegates_to": ["agent-alpha"],
        "budget": PlanBudget(max_delegations=10, ttl_seconds=3600),
    }
    defaults.update(overrides)
    return MissionPlan(**defaults)


async def _seed_plan_and_binding(db, plan: MissionPlan, session_id: str, agent_id: str):
    """Insert a plan and binding into the mock database."""
    # Compute expires_at if ttl_seconds is set
    if plan.budget.ttl_seconds and plan.expires_at is None:
        plan.expires_at = plan.issued_at + timedelta(seconds=plan.budget.ttl_seconds)

    await db[db_module.MISSION_PLANS].insert_one(plan.model_dump(mode="json"))
    binding = PlanSessionBinding(
        plan_id=plan.plan_id,
        session_id=session_id,
        agent_id=agent_id,
    )
    await db[db_module.PLAN_SESSION_BINDINGS].insert_one(binding.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# APEP-302.g: ScopePatternCompiler Integration Tests
# ---------------------------------------------------------------------------


class TestScopePatternCompilerIntegration:
    """Integration tests for the ScopePatternCompiler pipeline."""

    def test_compile_and_match_read_public_wildcard(self):
        """read:public:* should compile and match any tool name via direct glob fallback."""
        result = scope_pattern_compiler.compile("read:public:*")
        assert result.tool_glob == "public.read.*"

        # Verify it works with fnmatch
        import fnmatch
        assert fnmatch.fnmatch("public.read.docs", result.tool_glob)
        assert fnmatch.fnmatch("public.read.anything", result.tool_glob)
        assert not fnmatch.fnmatch("internal.write.docs", result.tool_glob)

    def test_compile_and_match_resource_hierarchy(self):
        """write:internal:reports.* should match reports sub-resources."""
        result = scope_pattern_compiler.compile("write:internal:reports.*")
        import fnmatch
        assert fnmatch.fnmatch("internal.write.reports.q3", result.tool_glob)
        assert fnmatch.fnmatch("internal.write.reports.q4", result.tool_glob)
        assert not fnmatch.fnmatch("internal.write.users.q3", result.tool_glob)

    def test_compile_many_and_match(self):
        """Batch compile and match against multiple patterns."""
        patterns = [
            "read:public:*",
            "write:internal:reports.*",
            "*:*:system.health",
        ]
        result = scope_pattern_compiler.compile_many(patterns)
        assert result.valid
        assert len(result.compiled) == 3

        import fnmatch
        # Test each compiled glob
        assert fnmatch.fnmatch("public.read.docs", result.compiled[0].tool_glob)
        assert fnmatch.fnmatch("internal.write.reports.q3", result.compiled[1].tool_glob)
        assert fnmatch.fnmatch("system.health", result.compiled[2].tool_glob)

    def test_plan_scope_filter_with_mission_plan_patterns(self):
        """Scope filter works with patterns typical in MissionPlan.scope."""
        plan = _make_plan(scope=[
            "read:public:*",
            "read:internal:reports.*",
            "execute:*:tools.code_exec",
        ])

        # Should be allowed by "read:public:*" via direct glob fallback
        # ("*" matches everything in direct fnmatch)
        r1 = plan_scope_filter.check("public.read.anything", plan.scope)
        assert r1.allowed is True

        # tools.code_exec via execute:*:tools.code_exec → glob "execute.tools.code_exec"
        r2 = plan_scope_filter.check("execute.tools.code_exec", plan.scope)
        assert r2.allowed is True

        # Something completely out of scope
        r3 = plan_scope_filter.check("secret.delete.all", plan.scope)
        assert r3.allowed is False

    def test_checkpoint_filter_with_mission_plan_patterns(self):
        """Checkpoint filter works with patterns typical in MissionPlan.requires_checkpoint."""
        plan = _make_plan(requires_checkpoint=[
            "write:secret:*",
            "delete:pii:users.*",
        ])

        # Should match write:secret:* checkpoint
        r1 = plan_checkpoint_filter.matches("secret.write.db", plan.requires_checkpoint)
        assert r1.matches is True

        # Should match delete:pii:users.* checkpoint
        r2 = plan_checkpoint_filter.matches("pii.delete.users.123", plan.requires_checkpoint)
        assert r2.matches is True

        # Should NOT match any checkpoint
        r3 = plan_checkpoint_filter.matches("public.read.docs", plan.requires_checkpoint)
        assert r3.matches is False

    def test_scope_and_checkpoint_combined(self):
        """A tool may be in scope but still require a checkpoint."""
        scope = ["*:*:*"]
        checkpoints = ["write:secret:*"]

        tool = "secret.write.db"

        scope_result = plan_scope_filter.check(tool, scope)
        checkpoint_result = plan_checkpoint_filter.matches(tool, checkpoints)

        assert scope_result.allowed is True  # Allowed by scope
        assert checkpoint_result.matches is True  # But requires checkpoint


# ---------------------------------------------------------------------------
# APEP-307.b: PolicyEvaluator Pipeline Integration Tests
# ---------------------------------------------------------------------------


class TestPolicyEvaluatorScopeIntegration:
    """Integration tests for scope pattern filters in the PolicyEvaluator pipeline."""

    @pytest.mark.asyncio
    async def test_scope_deny_in_pipeline(self, mock_mongodb):
        """A tool call outside plan scope is denied by the pipeline."""
        from app.core.config import settings
        from app.services.policy_evaluator import PolicyEvaluator

        # Enable mission plan feature
        original = settings.mission_plan_enabled
        settings.mission_plan_enabled = True

        try:
            db = mock_mongodb

            # Create a plan with limited scope
            plan = _make_plan(scope=["read:public:docs"])
            await _seed_plan_and_binding(
                db, plan, session_id="sess-1", agent_id="agent-alpha"
            )

            # Seed a permissive RBAC rule so the pipeline proceeds past plan filters
            await db[db_module.POLICY_RULES].insert_one(
                PolicyRule(
                    name="allow-all",
                    tool_pattern="*",
                    action=Decision.ALLOW,
                    agent_role=["*"],
                    priority=1,
                    taint_check=False,
                ).model_dump(mode="json")
            )

            request = ToolCallRequest(
                agent_id="agent-alpha",
                session_id="sess-1",
                tool_name="secret.delete.db",
                tool_args={},
            )

            evaluator = PolicyEvaluator()
            response = await evaluator.evaluate(request)

            # The scope filter should have denied the call
            assert response.decision == Decision.DENY
            assert "scope" in response.reason.lower() or "Plan scope denied" in response.reason

        finally:
            settings.mission_plan_enabled = original

    @pytest.mark.asyncio
    async def test_checkpoint_escalate_in_pipeline(self, mock_mongodb):
        """A tool call matching checkpoint pattern triggers ESCALATE."""
        from app.core.config import settings
        from app.services.policy_evaluator import PolicyEvaluator

        original = settings.mission_plan_enabled
        settings.mission_plan_enabled = True

        try:
            db = mock_mongodb

            # Create plan with broad scope but specific checkpoint
            plan = _make_plan(
                scope=["*:*:*"],
                requires_checkpoint=["write:secret:*"],
            )
            await _seed_plan_and_binding(
                db, plan, session_id="sess-2", agent_id="agent-alpha"
            )

            await db[db_module.POLICY_RULES].insert_one(
                PolicyRule(
                    name="allow-all-2",
                    tool_pattern="*",
                    action=Decision.ALLOW,
                    agent_role=["*"],
                    priority=1,
                    taint_check=False,
                ).model_dump(mode="json")
            )

            request = ToolCallRequest(
                agent_id="agent-alpha",
                session_id="sess-2",
                tool_name="secret.write.db",
                tool_args={},
            )

            evaluator = PolicyEvaluator()
            response = await evaluator.evaluate(request)

            # The checkpoint filter should have triggered ESCALATE
            assert response.decision == Decision.ESCALATE
            assert "checkpoint" in response.reason.lower()

        finally:
            settings.mission_plan_enabled = original

    @pytest.mark.asyncio
    async def test_scope_allow_proceeds_to_rbac(self, mock_mongodb):
        """A tool call within scope should pass scope filter and reach RBAC."""
        from app.core.config import settings
        from app.services.policy_evaluator import PolicyEvaluator

        original = settings.mission_plan_enabled
        settings.mission_plan_enabled = True

        try:
            db = mock_mongodb

            plan = _make_plan(
                scope=["*:*:*"],
                requires_checkpoint=[],
            )
            await _seed_plan_and_binding(
                db, plan, session_id="sess-3", agent_id="agent-alpha"
            )

            await db[db_module.POLICY_RULES].insert_one(
                PolicyRule(
                    name="allow-all-3",
                    tool_pattern="*",
                    action=Decision.ALLOW,
                    agent_role=["*"],
                    priority=1,
                    taint_check=False,
                ).model_dump(mode="json")
            )

            request = ToolCallRequest(
                agent_id="agent-alpha",
                session_id="sess-3",
                tool_name="file.read",
                tool_args={},
            )

            evaluator = PolicyEvaluator()
            response = await evaluator.evaluate(request)

            # Should ALLOW (scope is wide open, no checkpoint, RBAC allows)
            assert response.decision == Decision.ALLOW

        finally:
            settings.mission_plan_enabled = original

    @pytest.mark.asyncio
    async def test_no_plan_bound_proceeds_normally(self, mock_mongodb):
        """Without a plan binding, scope filters are skipped."""
        from app.core.config import settings
        from app.services.policy_evaluator import PolicyEvaluator

        original = settings.mission_plan_enabled
        settings.mission_plan_enabled = True

        try:
            db = mock_mongodb

            await db[db_module.POLICY_RULES].insert_one(
                PolicyRule(
                    name="allow-all-4",
                    tool_pattern="*",
                    action=Decision.ALLOW,
                    agent_role=["*"],
                    priority=1,
                    taint_check=False,
                ).model_dump(mode="json")
            )

            request = ToolCallRequest(
                agent_id="agent-x",
                session_id="no-plan-session",
                tool_name="any.tool",
                tool_args={},
            )

            evaluator = PolicyEvaluator()
            response = await evaluator.evaluate(request)

            # No plan → scope filter skipped → RBAC decides
            assert response.decision == Decision.ALLOW

        finally:
            settings.mission_plan_enabled = original


# ---------------------------------------------------------------------------
# APEP-307.b: API-level Integration Tests
# ---------------------------------------------------------------------------


class TestScopeAPIIntegration:
    """API-level integration tests for scope endpoints."""

    @pytest.mark.asyncio
    async def test_parse_then_compile_roundtrip(self):
        """Parse patterns, then compile the same patterns — both should succeed."""
        from app.main import app

        patterns = ["read:public:*", "write:internal:reports.*", "*:secret:db"]

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers=_get_auth_headers(),
        ) as client:
            # Parse
            parse_resp = await client.post(
                "/v1/scopes/parse", json={"patterns": patterns}
            )
            assert parse_resp.status_code == 200
            parse_data = parse_resp.json()
            assert parse_data["valid"] is True
            assert len(parse_data["tokens"]) == 3

            # Compile same patterns
            compile_resp = await client.post(
                "/v1/scopes/compile", json={"patterns": patterns}
            )
            assert compile_resp.status_code == 200
            compile_data = compile_resp.json()
            assert compile_data["valid"] is True
            assert len(compile_data["compiled"]) == 3

    @pytest.mark.asyncio
    async def test_compile_then_check(self):
        """Compile patterns, then use check endpoint to verify matching."""
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers=_get_auth_headers(),
        ) as client:
            # Compile
            compile_resp = await client.post(
                "/v1/scopes/compile",
                json={"patterns": ["read:public:*"]},
            )
            assert compile_resp.status_code == 200
            compiled = compile_resp.json()["compiled"][0]
            glob = compiled["tool_glob"]

            # Check: tool matching the glob
            check_resp = await client.post(
                "/v1/scopes/check",
                json={"tool_name": "public.read.docs", "scope": ["read:public:*"]},
            )
            assert check_resp.status_code == 200
            assert check_resp.json()["allowed"] is True

    @pytest.mark.asyncio
    async def test_all_endpoints_reject_empty_patterns(self):
        """All scope endpoints should reject requests with empty pattern lists."""
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers=_get_auth_headers(),
        ) as client:
            # parse
            resp = await client.post("/v1/scopes/parse", json={"patterns": []})
            assert resp.status_code == 422  # Validation error: min_length=1

            # compile
            resp = await client.post("/v1/scopes/compile", json={"patterns": []})
            assert resp.status_code == 422

            # checkpoint requires at least 1 pattern
            resp = await client.post(
                "/v1/scopes/checkpoint",
                json={"tool_name": "tool", "requires_checkpoint": []},
            )
            assert resp.status_code == 422

            # check requires at least 1 scope
            resp = await client.post(
                "/v1/scopes/check",
                json={"tool_name": "tool", "scope": []},
            )
            assert resp.status_code == 422
