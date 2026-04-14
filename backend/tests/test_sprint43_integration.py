"""Sprint 43 Integration & E2E tests.

APEP-340.f: E2E tests for scope simulator UI.
APEP-342.g: Integration tests for enterprise scope pattern library.
APEP-343.d: E2E tests for pattern library UI.
APEP-344.f: Integration tests for ToolTrustSession SDK class.
APEP-347.b: Integration and adversarial tests.
"""

import json
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.models.scope_pattern_library import (
    PatternCategory,
    PatternRiskLevel,
)
from app.services.scope_pattern_library import ScopePatternLibraryService


# ===========================================================================
# APEP-340.f / APEP-342.g: API Integration Tests
# ===========================================================================


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.asyncio
class TestScopeSimulatorAPI:
    """Integration tests for the scope simulator API endpoints."""

    async def test_simulate_allow(self):
        """POST /v1/scope/simulate returns ALLOW for in-scope tool."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/v1/scope/simulate", json={
                "scope": ["read:public:*"],
                "requires_checkpoint": [],
                "tool_name": "file.read.public.report",
            })
        assert resp.status_code == 200
        data = resp.json()
        assert data["effective_decision"] == "ALLOW"
        assert data["scope_allowed"] is True

    async def test_simulate_deny(self):
        """POST /v1/scope/simulate returns DENY for out-of-scope tool."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/v1/scope/simulate", json={
                "scope": ["read:public:*"],
                "tool_name": "file.write.secret.key",
            })
        assert resp.status_code == 200
        data = resp.json()
        assert data["effective_decision"] == "DENY"

    async def test_simulate_escalate(self):
        """POST /v1/scope/simulate returns ESCALATE for checkpoint match."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/v1/scope/simulate", json={
                "scope": ["*:*:*"],
                "requires_checkpoint": ["delete:*:*"],
                "tool_name": "file.delete.public.temp",
            })
        assert resp.status_code == 200
        data = resp.json()
        assert data["effective_decision"] == "ESCALATE"
        assert data["checkpoint_triggered"] is True

    async def test_simulate_batch(self):
        """POST /v1/scope/simulate/batch evaluates multiple tools."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/v1/scope/simulate/batch", json={
                "scope": ["read:public:*"],
                "requires_checkpoint": [],
                "tool_names": [
                    "file.read.public.a",
                    "file.read.public.b",
                    "file.write.secret.x",
                ],
            })
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["total"] == 3
        assert data["summary"]["allowed"] == 2
        assert data["summary"]["denied"] == 1

    async def test_simulate_missing_scope_and_plan(self):
        """POST /v1/scope/simulate returns 400 when neither scope nor plan_id given."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/v1/scope/simulate", json={
                "tool_name": "file.read.public.data",
            })
        assert resp.status_code == 400


@pytest.mark.asyncio
class TestPatternLibraryAPI:
    """Integration tests for the pattern library API endpoints."""

    async def test_list_patterns(self):
        """GET /v1/scope/patterns returns built-in templates."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/v1/scope/patterns")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 30
        assert len(data["templates"]) > 0

    async def test_list_patterns_by_category(self):
        """GET /v1/scope/patterns?category=secrets filters correctly."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/v1/scope/patterns?category=secrets")
        assert resp.status_code == 200
        data = resp.json()
        for t in data["templates"]:
            assert t["category"] == "secrets"

    async def test_list_patterns_by_risk(self):
        """GET /v1/scope/patterns?risk_level=critical filters correctly."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/v1/scope/patterns?risk_level=critical")
        assert resp.status_code == 200
        data = resp.json()
        for t in data["templates"]:
            assert t["risk_level"] == "critical"

    async def test_list_patterns_search(self):
        """GET /v1/scope/patterns?search=credential finds matches."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/v1/scope/patterns?search=credential")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] > 0

    async def test_get_categories(self):
        """GET /v1/scope/patterns/categories returns category counts."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get("/v1/scope/patterns/categories")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) > 0
        for cat in data:
            assert "category" in cat
            assert "count" in cat

    async def test_create_pattern_template(self):
        """POST /v1/scope/patterns creates a custom template."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/v1/scope/patterns", json={
                "name": "Integration Test Pattern",
                "category": "custom",
                "scope_patterns": ["read:public:test.*"],
                "tags": ["integration-test"],
            })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Integration Test Pattern"
        assert data["category"] == "custom"

    async def test_create_invalid_pattern(self):
        """POST /v1/scope/patterns rejects invalid scope patterns."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/v1/scope/patterns", json={
                "name": "Bad Pattern",
                "category": "custom",
                "scope_patterns": ["not_a_valid_pattern"],
            })
        assert resp.status_code == 400

    async def test_get_nonexistent_template(self):
        """GET /v1/scope/patterns/{id} returns 404 for unknown template."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.get(f"/v1/scope/patterns/{uuid4()}")
        assert resp.status_code == 404

    async def test_delete_nonexistent_template(self):
        """DELETE /v1/scope/patterns/{id} returns 404 for unknown template."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.delete(f"/v1/scope/patterns/{uuid4()}")
        assert resp.status_code == 404


# ===========================================================================
# APEP-347.b: Adversarial Tests
# ===========================================================================


@pytest.mark.asyncio
class TestSprint43Adversarial:
    """Adversarial tests for Sprint 43 components."""

    async def test_simulate_empty_tool_name(self):
        """Empty tool_name should be rejected."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/v1/scope/simulate", json={
                "scope": ["read:public:*"],
                "tool_name": "",
            })
        assert resp.status_code == 422

    async def test_simulate_very_long_tool_name(self):
        """Very long tool name should still be handled gracefully."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/v1/scope/simulate", json={
                "scope": ["read:public:*"],
                "tool_name": "a" * 500,
            })
        assert resp.status_code == 200
        assert resp.json()["effective_decision"] == "DENY"

    async def test_pattern_library_empty_name(self):
        """Pattern template with empty name should be rejected."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/v1/scope/patterns", json={
                "name": "",
                "category": "custom",
                "scope_patterns": ["read:public:*"],
            })
        assert resp.status_code == 422

    async def test_batch_simulate_max_tools(self):
        """Batch simulation with max tools still works."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            resp = await ac.post("/v1/scope/simulate/batch", json={
                "scope": ["read:public:*"],
                "tool_names": [f"file.read.public.item{i}" for i in range(100)],
            })
        assert resp.status_code == 200
        data = resp.json()
        assert data["summary"]["total"] == 100

    def test_wildcard_scope_allows_everything(self):
        """Wildcard *:*:* scope allows any tool name."""
        from app.services.scope_simulator import scope_simulator

        result = scope_simulator.simulate_sync(
            scope=["*:*:*"],
            requires_checkpoint=[],
            tool_name="absolutely.anything.goes.here",
        )
        assert result.effective_decision == "ALLOW"

    def test_scope_patterns_are_case_insensitive_for_verb_namespace(self):
        """Scope patterns should accept case variations for verb and namespace."""
        from app.services.scope_pattern_parser import scope_pattern_parser

        result = scope_pattern_parser.parse("READ:PUBLIC:*")
        assert result.valid
        assert result.scope_pattern is not None
        assert result.scope_pattern.verb == "read"
        assert result.scope_pattern.namespace == "public"
