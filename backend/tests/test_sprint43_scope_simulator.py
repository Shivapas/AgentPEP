"""Tests for Sprint 43 -- Scope Simulator, Pattern Library & SDK Plan API.

APEP-340: Scope simulator UI component tests.
APEP-341: agentpep scope simulate CLI tests.
APEP-342: Enterprise scope pattern library unit and integration tests.
APEP-344: ToolTrustSession SDK class unit tests.
APEP-345: SDK delegate() method tests.
APEP-347: Integration tests for Sprint 43.
"""

import json

import pytest

from app.models.mission_plan import MissionPlan, PlanBudget, PlanStatus
from app.models.scope_pattern_library import (
    CreatePatternTemplateRequest,
    PatternCategory,
    PatternRiskLevel,
    PatternTemplateListResponse,
    PatternTemplateResponse,
    ScopePatternTemplate,
    ScopeSimulateRequest,
    ScopeSimulateResult,
    UpdatePatternTemplateRequest,
)
from app.services.scope_pattern_library import (
    ScopePatternLibraryService,
    scope_pattern_library,
)
from app.services.scope_simulator import ScopeSimulator, scope_simulator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plan(**overrides) -> MissionPlan:
    defaults = {
        "action": "Test scope simulation",
        "issuer": "admin@example.com",
        "scope": ["read:public:*", "write:internal:reports.*"],
        "requires_checkpoint": ["delete:*:*"],
        "delegates_to": [],
        "budget": PlanBudget(),
        "status": PlanStatus.ACTIVE,
    }
    defaults.update(overrides)
    return MissionPlan(**defaults)


# ===========================================================================
# APEP-341: Scope Simulator Core Logic Tests
# ===========================================================================


class TestScopeSimulator:
    """Unit tests for the ScopeSimulator service."""

    def test_allow_in_scope(self):
        """Tool within scope and no checkpoint match should be ALLOW."""
        result = scope_simulator.simulate_sync(
            scope=["read:public:*"],
            requires_checkpoint=[],
            tool_name="file.read.public.report",
        )
        assert result.effective_decision == "ALLOW"
        assert result.scope_allowed is True
        assert result.checkpoint_triggered is False

    def test_deny_out_of_scope(self):
        """Tool outside scope should be DENY."""
        result = scope_simulator.simulate_sync(
            scope=["read:public:*"],
            requires_checkpoint=[],
            tool_name="file.write.secret.credentials",
        )
        assert result.effective_decision == "DENY"
        assert result.scope_allowed is False

    def test_escalate_checkpoint_match(self):
        """Tool within scope but matching checkpoint should be ESCALATE."""
        result = scope_simulator.simulate_sync(
            scope=["*:*:*"],
            requires_checkpoint=["delete:*:*"],
            tool_name="file.delete.public.temp",
        )
        assert result.effective_decision == "ESCALATE"
        assert result.scope_allowed is True
        assert result.checkpoint_triggered is True

    def test_deny_takes_precedence_over_escalate(self):
        """Out of scope DENY should take precedence even if checkpoint matches."""
        result = scope_simulator.simulate_sync(
            scope=["read:public:*"],
            requires_checkpoint=["delete:*:*"],
            tool_name="file.delete.secret.key",
        )
        assert result.effective_decision == "DENY"

    def test_no_scope_means_unrestricted(self):
        """Empty scope patterns means all tools are allowed."""
        result = scope_simulator.simulate_sync(
            scope=[],
            requires_checkpoint=[],
            tool_name="anything.at.all",
        )
        assert result.effective_decision == "ALLOW"
        assert result.scope_allowed is True

    def test_checkpoint_with_specific_patterns(self):
        """Checkpoint with specific pattern only matches relevant tools."""
        result = scope_simulator.simulate_sync(
            scope=["*:*:*"],
            requires_checkpoint=["write:secret:credentials.*"],
            tool_name="file.read.public.report",
        )
        assert result.effective_decision == "ALLOW"
        assert result.checkpoint_triggered is False

    def test_simulate_returns_compiled_patterns(self):
        """Simulation result includes compiled RBAC patterns."""
        result = scope_simulator.simulate_sync(
            scope=["read:public:*"],
            requires_checkpoint=[],
            tool_name="file.read.public.report",
        )
        assert len(result.compiled_rbac_patterns) > 0
        assert any("file.read" in p for p in result.compiled_rbac_patterns)

    def test_simulate_batch(self):
        """Batch simulation evaluates multiple tools."""
        results = scope_simulator.simulate_batch_sync(
            scope=["read:public:*"],
            requires_checkpoint=["delete:*:*"],
            tool_names=[
                "file.read.public.report",
                "file.delete.public.temp",
                "file.write.secret.key",
            ],
        )
        assert len(results) == 3
        assert results[0].effective_decision == "ALLOW"
        assert results[1].effective_decision == "DENY"  # delete not in read-only scope
        assert results[2].effective_decision == "DENY"  # write not in read-only scope

    @pytest.mark.asyncio
    async def test_simulate_async_with_inline(self):
        """Async simulation with inline scope patterns."""
        request = ScopeSimulateRequest(
            scope=["read:public:*"],
            requires_checkpoint=[],
            tool_name="file.read.public.data",
        )
        result = await scope_simulator.simulate(request)
        assert result.effective_decision == "ALLOW"

    @pytest.mark.asyncio
    async def test_simulate_async_with_missing_plan(self):
        """Async simulation with non-existent plan_id raises ValueError."""
        from uuid import uuid4

        request = ScopeSimulateRequest(
            plan_id=uuid4(),
            tool_name="file.read.public.data",
        )
        with pytest.raises(ValueError, match="not found"):
            await scope_simulator.simulate(request)


# ===========================================================================
# APEP-342: Enterprise Scope Pattern Library Tests
# ===========================================================================


class TestPatternLibrary:
    """Unit tests for the ScopePatternLibraryService."""

    @pytest.mark.asyncio
    async def test_list_builtin_templates(self):
        """Built-in templates are loaded and listable."""
        service = ScopePatternLibraryService()
        response = await service.list_templates()
        assert response.total >= 30
        assert len(response.templates) > 0

    @pytest.mark.asyncio
    async def test_filter_by_category(self):
        """Filter templates by category."""
        service = ScopePatternLibraryService()
        response = await service.list_templates(category=PatternCategory.SECRETS)
        assert response.total > 0
        for t in response.templates:
            assert t.category == PatternCategory.SECRETS

    @pytest.mark.asyncio
    async def test_filter_by_risk_level(self):
        """Filter templates by risk level."""
        service = ScopePatternLibraryService()
        response = await service.list_templates(risk_level=PatternRiskLevel.CRITICAL)
        assert response.total > 0
        for t in response.templates:
            assert t.risk_level == PatternRiskLevel.CRITICAL

    @pytest.mark.asyncio
    async def test_filter_by_tag(self):
        """Filter templates by tag."""
        service = ScopePatternLibraryService()
        response = await service.list_templates(tag="read-only")
        assert response.total > 0
        for t in response.templates:
            assert "read-only" in [tg.lower() for tg in t.tags]

    @pytest.mark.asyncio
    async def test_search(self):
        """Free-text search on name/description/tags."""
        service = ScopePatternLibraryService()
        response = await service.list_templates(search="credential")
        assert response.total > 0

    @pytest.mark.asyncio
    async def test_create_template(self):
        """Create a custom pattern template."""
        service = ScopePatternLibraryService()
        request = CreatePatternTemplateRequest(
            name="Test Custom Pattern",
            description="A test pattern for unit testing.",
            category=PatternCategory.CUSTOM,
            risk_level=PatternRiskLevel.LOW,
            scope_patterns=["read:public:test.*"],
            tags=["test", "unit-test"],
        )
        result = await service.create_template(request)
        assert result.name == "Test Custom Pattern"
        assert result.category == PatternCategory.CUSTOM

        # Verify it appears in listing
        fetched = await service.get_template(result.template_id)
        assert fetched is not None
        assert fetched.name == "Test Custom Pattern"

    @pytest.mark.asyncio
    async def test_create_template_invalid_pattern(self):
        """Creating template with invalid scope patterns raises ValueError."""
        service = ScopePatternLibraryService()
        request = CreatePatternTemplateRequest(
            name="Invalid Pattern",
            category=PatternCategory.CUSTOM,
            scope_patterns=["invalid_pattern"],
        )
        with pytest.raises(ValueError, match="Invalid scope patterns"):
            await service.create_template(request)

    @pytest.mark.asyncio
    async def test_update_template(self):
        """Update an existing template."""
        service = ScopePatternLibraryService()
        create_req = CreatePatternTemplateRequest(
            name="Updatable Pattern",
            category=PatternCategory.CUSTOM,
            scope_patterns=["read:public:*"],
        )
        created = await service.create_template(create_req)

        update_req = UpdatePatternTemplateRequest(
            name="Updated Pattern Name",
            tags=["updated"],
        )
        updated = await service.update_template(created.template_id, update_req)
        assert updated is not None
        assert updated.name == "Updated Pattern Name"
        assert "updated" in updated.tags

    @pytest.mark.asyncio
    async def test_delete_template(self):
        """Delete a template."""
        service = ScopePatternLibraryService()
        create_req = CreatePatternTemplateRequest(
            name="Deletable Pattern",
            category=PatternCategory.CUSTOM,
            scope_patterns=["read:public:*"],
        )
        created = await service.create_template(create_req)
        assert await service.delete_template(created.template_id) is True
        assert await service.get_template(created.template_id) is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self):
        """Deleting non-existent template returns False."""
        from uuid import uuid4

        service = ScopePatternLibraryService()
        service._ensure_initialized()
        assert await service.delete_template(uuid4()) is False

    @pytest.mark.asyncio
    async def test_get_categories(self):
        """Get category counts for faceted browsing."""
        service = ScopePatternLibraryService()
        categories = await service.get_categories()
        assert len(categories) > 0
        for cat in categories:
            assert "category" in cat
            assert "count" in cat
            assert cat["count"] > 0

    @pytest.mark.asyncio
    async def test_pagination(self):
        """Pagination works correctly."""
        service = ScopePatternLibraryService()
        page1 = await service.list_templates(offset=0, limit=5)
        page2 = await service.list_templates(offset=5, limit=5)
        assert len(page1.templates) == 5
        assert page1.total == page2.total
        # Pages shouldn't overlap
        ids1 = {t.template_id for t in page1.templates}
        ids2 = {t.template_id for t in page2.templates}
        assert ids1.isdisjoint(ids2)


# ===========================================================================
# APEP-342: Pattern Library Pydantic Model Tests
# ===========================================================================


class TestPatternLibraryModels:
    """Tests for Pydantic models used by the pattern library."""

    def test_scope_pattern_template_defaults(self):
        """ScopePatternTemplate has sensible defaults."""
        tmpl = ScopePatternTemplate(
            name="Test",
            category=PatternCategory.DATA_ACCESS,
            scope_patterns=["read:public:*"],
        )
        assert tmpl.risk_level == PatternRiskLevel.MEDIUM
        assert tmpl.enabled is True
        assert tmpl.author == "agentpep"
        assert tmpl.version == "1.0"

    def test_scope_simulate_request_requires_tool(self):
        """ScopeSimulateRequest requires tool_name."""
        with pytest.raises(Exception):
            ScopeSimulateRequest()  # type: ignore[call-arg]

    def test_scope_simulate_result_fields(self):
        """ScopeSimulateResult contains all required fields."""
        result = ScopeSimulateResult(
            tool_name="test.tool",
            scope_allowed=True,
            checkpoint_triggered=False,
            effective_decision="ALLOW",
        )
        assert result.tool_name == "test.tool"
        assert result.effective_decision == "ALLOW"

    def test_pattern_category_values(self):
        """All pattern categories are valid."""
        assert PatternCategory.DATA_ACCESS == "data_access"
        assert PatternCategory.SECRETS == "secrets"
        assert PatternCategory.COMPLIANCE == "compliance"

    def test_pattern_risk_level_values(self):
        """All risk levels are valid."""
        assert PatternRiskLevel.LOW == "low"
        assert PatternRiskLevel.CRITICAL == "critical"


# ===========================================================================
# APEP-341: CLI scope simulate Tests
# ===========================================================================


class TestScopeSimulateCLI:
    """Tests for the agentpep scope simulate CLI command."""

    def test_basic_simulation(self):
        """Run a basic scope simulation from CLI."""
        from agentpep.cli import main

        result = main([
            "scope", "simulate",
            "--scope", "read:public:*",
            "--tool-name", "file.read.public.report",
            "--json",
        ])
        assert result == 0

    def test_deny_simulation(self):
        """CLI returns 1 when tool is denied."""
        from agentpep.cli import main

        result = main([
            "scope", "simulate",
            "--scope", "read:public:*",
            "--tool-name", "file.write.secret.key",
            "--json",
        ])
        assert result == 1

    def test_checkpoint_simulation(self):
        """CLI returns 1 when tool triggers checkpoint (ESCALATE)."""
        from agentpep.cli import main

        result = main([
            "scope", "simulate",
            "--scope", "*:*:*",
            "--checkpoint", "delete:*:*",
            "--tool-name", "file.delete.public.temp",
            "--json",
        ])
        assert result == 1

    def test_multiple_tools(self):
        """CLI handles multiple tool names."""
        from agentpep.cli import main

        result = main([
            "scope", "simulate",
            "--scope", "read:public:*",
            "--tool-name", "file.read.public.a", "file.read.public.b",
            "--json",
        ])
        assert result == 0

    def test_plan_file(self, tmp_path):
        """CLI loads scope from plan YAML file."""
        plan_file = tmp_path / "plan.yaml"
        plan_file.write_text(
            "scope:\n"
            "  - read:public:*\n"
            "requires_checkpoint:\n"
            "  - delete:*:*\n"
        )
        from agentpep.cli import main

        result = main([
            "scope", "simulate",
            "--plan", str(plan_file),
            "--tool-name", "file.read.public.report",
            "--json",
        ])
        assert result == 0

    def test_no_scope_error(self):
        """CLI errors when no scope patterns are provided."""
        from agentpep.cli import main

        result = main([
            "scope", "simulate",
            "--tool-name", "file.read.public.report",
        ])
        assert result == 1

    def test_invalid_scope_error(self):
        """CLI errors on invalid scope patterns."""
        from agentpep.cli import main

        result = main([
            "scope", "simulate",
            "--scope", "invalid_pattern",
            "--tool-name", "file.read.public.report",
        ])
        assert result == 1

    def test_text_output(self, capsys):
        """CLI produces readable text output."""
        from agentpep.cli import main

        main([
            "scope", "simulate",
            "--scope", "read:public:*",
            "--tool-name", "file.read.public.report",
        ])
        captured = capsys.readouterr()
        assert "ALLOW" in captured.out
        assert "file.read.public.report" in captured.out


# ===========================================================================
# APEP-344: ToolTrustSession Model Tests
# ===========================================================================


class TestToolTrustSessionModels:
    """Unit tests for ToolTrustSession helper classes."""

    def test_plan_info_from_dict(self):
        """PlanInfo can be constructed from API response dict."""
        from agentpep.tool_trust_session import PlanInfo

        data = {
            "plan_id": "550e8400-e29b-41d4-a716-446655440000",
            "action": "Test plan",
            "issuer": "alice@corp.com",
            "status": "ACTIVE",
            "signature": "sig123",
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": None,
        }
        info = PlanInfo(data)
        assert info.plan_id == "550e8400-e29b-41d4-a716-446655440000"
        assert info.action == "Test plan"
        assert info.status == "ACTIVE"
        assert info.expires_at is None

    def test_plan_info_repr(self):
        """PlanInfo has a useful repr."""
        from agentpep.tool_trust_session import PlanInfo

        info = PlanInfo({"plan_id": "abc", "action": "test", "status": "ACTIVE"})
        assert "abc" in repr(info)
        assert "test" in repr(info)

    def test_audit_tree_from_dict(self):
        """AuditTree can be constructed from API response dict."""
        from agentpep.tool_trust_session import AuditTree

        tree = AuditTree({
            "plan_id": "abc",
            "receipts": [{"id": "r1"}, {"id": "r2"}],
            "chain_valid": True,
        })
        assert tree.plan_id == "abc"
        assert tree.total == 2
        assert tree.chain_valid is True

    def test_delegation_result_allowed(self):
        """DelegationResult captures allow status."""
        from agentpep.tool_trust_session import DelegationResult

        dr = DelegationResult(
            allowed=True,
            child_agent_id="child-bot",
            decision="ALLOW",
            reason="Within scope",
        )
        assert dr.allowed is True
        assert dr.child_agent_id == "child-bot"

    def test_delegation_result_denied(self):
        """DelegationResult captures deny status."""
        from agentpep.tool_trust_session import DelegationResult

        dr = DelegationResult(
            allowed=False,
            child_agent_id="child-bot",
            decision="DENY",
            reason="Not in delegates_to",
        )
        assert dr.allowed is False
        assert "DENY" in repr(dr)

    def test_tool_trust_session_init(self):
        """ToolTrustSession initializes with sensible defaults."""
        from agentpep.tool_trust_session import ToolTrustSession

        session = ToolTrustSession(
            base_url="http://localhost:8000",
            session_id="test-session",
            agent_id="test-agent",
        )
        assert session.session_id == "test-session"
        assert session.agent_id == "test-agent"
        assert session.plan is None

    def test_tool_trust_session_no_plan_raises(self):
        """Operations requiring a plan raise RuntimeError when no plan is bound."""
        from agentpep.tool_trust_session import ToolTrustSession

        session = ToolTrustSession()
        with pytest.raises(RuntimeError, match="No plan bound"):
            import asyncio
            asyncio.get_event_loop().run_until_complete(session.audit())


# ===========================================================================
# APEP-347: Integration Tests
# ===========================================================================


class TestSprint43Integration:
    """Integration tests spanning multiple Sprint 43 components."""

    def test_simulator_with_library_template(self):
        """Simulate using scope patterns from a library template."""
        # Get a built-in template
        service = ScopePatternLibraryService()
        service._ensure_initialized()

        # Find "Read-Only Public Data" template
        templates = list(service._templates.values())
        read_only = next(
            (t for t in templates if "Read-Only Public Data" in t.name),
            None,
        )
        assert read_only is not None

        # Simulate with the template's scope patterns
        result = scope_simulator.simulate_sync(
            scope=read_only.scope_patterns,
            requires_checkpoint=read_only.checkpoint_patterns,
            tool_name="file.read.public.report",
        )
        assert result.effective_decision == "ALLOW"

        # Write should be denied
        result2 = scope_simulator.simulate_sync(
            scope=read_only.scope_patterns,
            requires_checkpoint=read_only.checkpoint_patterns,
            tool_name="file.write.secret.key",
        )
        assert result2.effective_decision == "DENY"

    def test_simulator_with_critical_template(self):
        """Simulate with a critical-risk template triggers checkpoints."""
        service = ScopePatternLibraryService()
        service._ensure_initialized()

        # Find "Secret Manager" template
        templates = list(service._templates.values())
        secret_mgr = next(
            (t for t in templates if "Secret Manager" in t.name),
            None,
        )
        assert secret_mgr is not None

        # Reading a secret should trigger checkpoint
        result = scope_simulator.simulate_sync(
            scope=secret_mgr.scope_patterns,
            requires_checkpoint=secret_mgr.checkpoint_patterns,
            tool_name="file.read.secret.credentials",
        )
        assert result.checkpoint_triggered is True
        assert result.effective_decision == "ESCALATE"

    @pytest.mark.asyncio
    async def test_pattern_library_create_then_simulate(self):
        """Create a custom template and simulate against it."""
        service = ScopePatternLibraryService()
        template = await service.create_template(
            CreatePatternTemplateRequest(
                name="CI Pipeline Access",
                category=PatternCategory.DEPLOYMENT,
                risk_level=PatternRiskLevel.MEDIUM,
                scope_patterns=["read:internal:pipeline.*", "execute:internal:deploy.staging*"],
                checkpoint_patterns=["execute:internal:deploy.prod*"],
                tags=["ci-cd", "integration-test"],
            )
        )

        # Simulate staging deploy
        result = scope_simulator.simulate_sync(
            scope=template.scope_patterns,
            requires_checkpoint=template.checkpoint_patterns,
            tool_name="exec.internal.deploy.staging.v1",
        )
        assert result.scope_allowed is True

    def test_all_builtin_templates_have_valid_patterns(self):
        """Every built-in template has valid scope patterns."""
        from app.services.scope_pattern_parser import scope_pattern_parser

        service = ScopePatternLibraryService()
        service._ensure_initialized()

        for tmpl in service._templates.values():
            for pattern in tmpl.scope_patterns:
                result = scope_pattern_parser.parse(pattern)
                assert result.valid, (
                    f"Template '{tmpl.name}' has invalid scope pattern: "
                    f"{pattern} — {result.error}"
                )
            for pattern in tmpl.checkpoint_patterns:
                result = scope_pattern_parser.parse(pattern)
                assert result.valid, (
                    f"Template '{tmpl.name}' has invalid checkpoint pattern: "
                    f"{pattern} — {result.error}"
                )

    def test_all_builtin_templates_are_enabled(self):
        """All built-in templates ship as enabled."""
        service = ScopePatternLibraryService()
        service._ensure_initialized()
        for tmpl in service._templates.values():
            assert tmpl.enabled, f"Template '{tmpl.name}' is disabled"
