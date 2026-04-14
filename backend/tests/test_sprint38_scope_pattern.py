"""Tests for Sprint 38 -- Scope Pattern Language & DSL Compiler.

APEP-300: Scope pattern syntax unit tests.
APEP-301: ScopePatternParser unit tests.
APEP-302: ScopePatternCompiler unit tests.
APEP-303: PlanCheckpointFilter unit tests.
APEP-304: PlanScopeFilter unit tests.
APEP-305: CLI scope compile tests.
APEP-306: CLI scope validate tests.
APEP-307: Unit and component tests.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from tests.conftest import _get_auth_headers

from app.models.scope_pattern import (
    WILDCARD,
    MAX_SCOPE_LENGTH,
    CheckpointCheckRequest,
    CheckpointCheckResponse,
    CheckpointMatchResult,
    CheckScopeRequest,
    CheckScopeResponse,
    CompiledScope,
    CompileScopeRequest,
    CompileScopeResponse,
    CompileResult,
    ParseScopeRequest,
    ParseScopeResponse,
    ScopeCheckResult,
    ScopeParseError,
    ScopeParseResult,
    ScopeToken,
    ScopeVerb,
)
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


# ---------------------------------------------------------------------------
# APEP-300: Scope Pattern Syntax Tests
# ---------------------------------------------------------------------------


class TestScopePatternSyntax:
    """Unit tests for scope pattern syntax constants and enums."""

    def test_scope_separator(self):
        assert WILDCARD == "*"

    def test_scope_verb_enum_values(self):
        assert ScopeVerb.READ == "read"
        assert ScopeVerb.WRITE == "write"
        assert ScopeVerb.EXECUTE == "execute"
        assert ScopeVerb.DELETE == "delete"
        assert ScopeVerb.ADMIN == "admin"
        assert ScopeVerb.LIST == "list"
        assert ScopeVerb.CREATE == "create"
        assert ScopeVerb.UPDATE == "update"
        assert ScopeVerb.WILDCARD == "*"

    def test_scope_token_properties(self):
        token = ScopeToken(raw="read:public:docs", verb="read", namespace="public", resource="docs")
        assert not token.verb_is_wildcard
        assert not token.namespace_is_wildcard
        assert not token.resource_is_wildcard

    def test_scope_token_wildcard_properties(self):
        token = ScopeToken(raw="*:*:*", verb="*", namespace="*", resource="*")
        assert token.verb_is_wildcard
        assert token.namespace_is_wildcard
        assert token.resource_is_wildcard

    def test_scope_token_resource_segments(self):
        token = ScopeToken(
            raw="read:public:reports.q3.finance",
            verb="read", namespace="public", resource="reports.q3.finance",
        )
        assert token.resource_segments == ["reports", "q3", "finance"]

    def test_scope_token_single_resource_segment(self):
        token = ScopeToken(raw="read:public:docs", verb="read", namespace="public", resource="docs")
        assert token.resource_segments == ["docs"]

    def test_max_scope_length_constant(self):
        assert MAX_SCOPE_LENGTH == 256


# ---------------------------------------------------------------------------
# APEP-301: ScopePatternParser Tests
# ---------------------------------------------------------------------------


class TestScopePatternParser:
    """Unit tests for ScopePatternParser."""

    def test_parse_valid_simple(self):
        result = scope_pattern_parser.parse("read:public:docs")
        assert isinstance(result, ScopeToken)
        assert result.verb == "read"
        assert result.namespace == "public"
        assert result.resource == "docs"
        assert result.raw == "read:public:docs"

    def test_parse_valid_wildcard_all(self):
        result = scope_pattern_parser.parse("*:*:*")
        assert isinstance(result, ScopeToken)
        assert result.verb == "*"
        assert result.namespace == "*"
        assert result.resource == "*"

    def test_parse_valid_wildcard_verb(self):
        result = scope_pattern_parser.parse("*:internal:reports")
        assert isinstance(result, ScopeToken)
        assert result.verb == "*"
        assert result.namespace == "internal"
        assert result.resource == "reports"

    def test_parse_valid_wildcard_resource(self):
        result = scope_pattern_parser.parse("read:public:*")
        assert isinstance(result, ScopeToken)
        assert result.resource == "*"

    def test_parse_valid_dotted_resource(self):
        result = scope_pattern_parser.parse("write:internal:reports.q3.finance")
        assert isinstance(result, ScopeToken)
        assert result.resource == "reports.q3.finance"

    def test_parse_valid_glob_resource(self):
        result = scope_pattern_parser.parse("read:public:reports.*")
        assert isinstance(result, ScopeToken)
        assert result.resource == "reports.*"

    def test_parse_valid_hyphenated_segments(self):
        result = scope_pattern_parser.parse("read:my-namespace:my-resource")
        assert isinstance(result, ScopeToken)
        assert result.namespace == "my-namespace"
        assert result.resource == "my-resource"

    def test_parse_valid_underscored_segments(self):
        result = scope_pattern_parser.parse("read:my_ns:my_res")
        assert isinstance(result, ScopeToken)
        assert result.namespace == "my_ns"

    def test_parse_valid_mixed_case(self):
        result = scope_pattern_parser.parse("Read:Public:Docs")
        assert isinstance(result, ScopeToken)
        assert result.verb == "Read"

    def test_parse_strips_whitespace(self):
        result = scope_pattern_parser.parse("  read:public:docs  ")
        assert isinstance(result, ScopeToken)
        assert result.raw == "read:public:docs"

    def test_parse_error_empty(self):
        result = scope_pattern_parser.parse("")
        assert isinstance(result, ScopeParseError)
        assert "Empty" in result.error

    def test_parse_error_whitespace_only(self):
        result = scope_pattern_parser.parse("   ")
        assert isinstance(result, ScopeParseError)
        assert "Empty" in result.error

    def test_parse_error_too_few_segments(self):
        result = scope_pattern_parser.parse("read:public")
        assert isinstance(result, ScopeParseError)
        assert "exactly 3" in result.error

    def test_parse_error_too_many_segments(self):
        result = scope_pattern_parser.parse("read:public:docs:extra")
        assert isinstance(result, ScopeParseError)
        assert "exactly 3" in result.error

    def test_parse_error_single_segment(self):
        result = scope_pattern_parser.parse("read")
        assert isinstance(result, ScopeParseError)

    def test_parse_error_empty_verb(self):
        result = scope_pattern_parser.parse(":public:docs")
        assert isinstance(result, ScopeParseError)
        assert "verb" in result.error.lower() or "Empty" in result.error

    def test_parse_error_empty_namespace(self):
        result = scope_pattern_parser.parse("read::docs")
        assert isinstance(result, ScopeParseError)
        assert "namespace" in result.error.lower() or "Empty" in result.error

    def test_parse_error_empty_resource(self):
        result = scope_pattern_parser.parse("read:public:")
        assert isinstance(result, ScopeParseError)
        assert "resource" in result.error.lower() or "Empty" in result.error

    def test_parse_error_invalid_characters(self):
        result = scope_pattern_parser.parse("read:pub lic:docs")
        assert isinstance(result, ScopeParseError)
        assert "Invalid characters" in result.error

    def test_parse_error_special_characters(self):
        result = scope_pattern_parser.parse("read:public:docs@home")
        assert isinstance(result, ScopeParseError)

    def test_parse_error_exceeds_max_length(self):
        long_pattern = "read:public:" + "a" * 250
        result = scope_pattern_parser.parse(long_pattern)
        assert isinstance(result, ScopeParseError)
        assert "maximum length" in result.error

    def test_parse_many_all_valid(self):
        patterns = ["read:public:*", "write:internal:reports.*", "*:*:*"]
        result = scope_pattern_parser.parse_many(patterns)
        assert isinstance(result, ScopeParseResult)
        assert result.valid is True
        assert len(result.tokens) == 3
        assert len(result.errors) == 0

    def test_parse_many_mixed(self):
        patterns = ["read:public:*", "invalid", "write:internal:docs"]
        result = scope_pattern_parser.parse_many(patterns)
        assert result.valid is False
        assert len(result.tokens) == 2
        assert len(result.errors) == 1

    def test_parse_many_all_invalid(self):
        patterns = ["bad", "also-bad", "nope"]
        result = scope_pattern_parser.parse_many(patterns)
        assert result.valid is False
        assert len(result.tokens) == 0
        assert len(result.errors) == 3

    def test_parse_many_empty_list(self):
        result = scope_pattern_parser.parse_many([])
        assert result.valid is True
        assert len(result.tokens) == 0

    def test_singleton_exists(self):
        assert scope_pattern_parser is not None
        assert isinstance(scope_pattern_parser, ScopePatternParser)


# ---------------------------------------------------------------------------
# APEP-302: ScopePatternCompiler Tests
# ---------------------------------------------------------------------------


class TestScopePatternCompiler:
    """Unit tests for ScopePatternCompiler."""

    def test_compile_all_wildcard(self):
        result = scope_pattern_compiler.compile("*:*:*")
        assert isinstance(result, CompiledScope)
        assert result.tool_glob == "*"

    def test_compile_specific_resource(self):
        result = scope_pattern_compiler.compile("*:*:file.read")
        assert isinstance(result, CompiledScope)
        assert result.tool_glob == "file.read"

    def test_compile_wildcard_resource(self):
        result = scope_pattern_compiler.compile("*:*:reports.*")
        assert isinstance(result, CompiledScope)
        assert result.tool_glob == "reports.*"

    def test_compile_with_verb_prefix(self):
        result = scope_pattern_compiler.compile("read:*:reports")
        assert isinstance(result, CompiledScope)
        assert result.tool_glob == "read.reports"

    def test_compile_with_namespace_prefix(self):
        result = scope_pattern_compiler.compile("*:internal:reports")
        assert isinstance(result, CompiledScope)
        assert result.tool_glob == "internal.reports"

    def test_compile_with_verb_and_namespace(self):
        result = scope_pattern_compiler.compile("read:internal:reports")
        assert isinstance(result, CompiledScope)
        assert result.tool_glob == "internal.read.reports"

    def test_compile_preserves_source(self):
        result = scope_pattern_compiler.compile("read:public:docs")
        assert isinstance(result, CompiledScope)
        assert result.source_pattern == "read:public:docs"
        assert result.verb == "read"
        assert result.namespace == "public"
        assert result.resource == "docs"

    def test_compile_invalid_pattern(self):
        result = scope_pattern_compiler.compile("invalid")
        assert isinstance(result, ScopeParseError)

    def test_compile_many_all_valid(self):
        patterns = ["*:*:*", "read:public:*", "write:internal:docs"]
        result = scope_pattern_compiler.compile_many(patterns)
        assert isinstance(result, CompileResult)
        assert result.valid is True
        assert len(result.compiled) == 3
        assert len(result.errors) == 0

    def test_compile_many_mixed(self):
        patterns = ["read:public:*", "bad-pattern", "*:*:tools"]
        result = scope_pattern_compiler.compile_many(patterns)
        assert result.valid is False
        assert len(result.compiled) == 2
        assert len(result.errors) == 1

    def test_compile_glob_resource_wildcard(self):
        result = scope_pattern_compiler.compile("read:public:reports.*")
        assert isinstance(result, CompiledScope)
        assert result.tool_glob == "public.read.reports.*"

    def test_compile_deeply_nested_resource(self):
        result = scope_pattern_compiler.compile("*:*:db.users.profile.avatar")
        assert isinstance(result, CompiledScope)
        assert result.tool_glob == "db.users.profile.avatar"

    def test_singleton_exists(self):
        assert scope_pattern_compiler is not None
        assert isinstance(scope_pattern_compiler, ScopePatternCompiler)

    def test_compiler_uses_parser(self):
        parser = ScopePatternParser()
        compiler = ScopePatternCompiler(parser=parser)
        result = compiler.compile("read:public:docs")
        assert isinstance(result, CompiledScope)


# ---------------------------------------------------------------------------
# APEP-303: PlanCheckpointFilter Tests
# ---------------------------------------------------------------------------


class TestPlanCheckpointFilter:
    """Unit tests for PlanCheckpointFilter."""

    def test_no_match(self):
        result = plan_checkpoint_filter.matches("file.read", ["write:secret:*"])
        assert isinstance(result, CheckpointMatchResult)
        assert result.matches is False
        assert result.matched_pattern is None

    def test_match_via_compiled_glob(self):
        result = plan_checkpoint_filter.matches("secret.write.db", ["write:secret:db"])
        assert result.matches is True
        assert result.matched_pattern == "write:secret:db"

    def test_match_via_wildcard_resource(self):
        # *:*:* compiles to glob "*" which matches everything
        result = plan_checkpoint_filter.matches("anything", ["*:*:*"])
        assert result.matches is True

    def test_match_via_direct_glob_fallback(self):
        # Simple glob patterns (no colon) fall through to direct fnmatch
        result = plan_checkpoint_filter.matches("file.read", ["file.*"])
        assert result.matches is True
        assert result.matched_pattern == "file.*"

    def test_match_first_pattern_wins(self):
        result = plan_checkpoint_filter.matches(
            "secret.write.db",
            ["read:public:*", "write:secret:db", "*:*:*"],
        )
        assert result.matches is True
        assert result.matched_pattern == "write:secret:db"

    def test_no_match_empty_patterns(self):
        result = plan_checkpoint_filter.matches("file.read", [])
        assert result.matches is False

    def test_tool_name_preserved(self):
        result = plan_checkpoint_filter.matches("my-tool", ["read:public:*"])
        assert result.tool_name == "my-tool"

    def test_detail_on_match(self):
        result = plan_checkpoint_filter.matches("anything", ["*:*:*"])
        assert result.detail != ""

    def test_detail_on_no_match(self):
        result = plan_checkpoint_filter.matches("tool", ["read:internal:x"])
        assert "did not match" in result.detail

    def test_singleton_exists(self):
        assert plan_checkpoint_filter is not None
        assert isinstance(plan_checkpoint_filter, PlanCheckpointFilter)

    def test_custom_compiler_injection(self):
        compiler = ScopePatternCompiler()
        cpf = PlanCheckpointFilter(compiler=compiler)
        result = cpf.matches("anything", ["*:*:*"])
        assert result.matches is True


# ---------------------------------------------------------------------------
# APEP-304: PlanScopeFilter Tests
# ---------------------------------------------------------------------------


class TestPlanScopeFilter:
    """Unit tests for PlanScopeFilter."""

    def test_empty_scope_allows_all(self):
        result = plan_scope_filter.check("any.tool", [])
        assert isinstance(result, ScopeCheckResult)
        assert result.allowed is True
        assert "No scope restrictions" in result.detail

    def test_wildcard_allows_all(self):
        result = plan_scope_filter.check("any.tool", ["*:*:*"])
        assert result.allowed is True

    def test_matching_scope_allows(self):
        result = plan_scope_filter.check(
            "public.read.docs",
            ["read:public:docs"],
        )
        assert result.allowed is True
        assert result.matched_pattern == "read:public:docs"

    def test_non_matching_scope_denies(self):
        result = plan_scope_filter.check("secret.delete.db", ["read:public:*"])
        assert result.allowed is False
        assert result.matched_pattern is None

    def test_multiple_scopes_first_match(self):
        result = plan_scope_filter.check(
            "docs",
            ["read:public:reports", "*:*:docs", "write:internal:*"],
        )
        assert result.allowed is True
        assert result.matched_pattern == "*:*:docs"

    def test_direct_glob_fallback(self):
        result = plan_scope_filter.check("file.read", ["file.*"])
        assert result.allowed is True

    def test_tool_name_preserved(self):
        result = plan_scope_filter.check("my-tool", ["read:public:*"])
        assert result.tool_name == "my-tool"

    def test_detail_on_deny(self):
        result = plan_scope_filter.check("tool", ["read:internal:x"])
        assert "not allowed" in result.detail

    def test_singleton_exists(self):
        assert plan_scope_filter is not None
        assert isinstance(plan_scope_filter, PlanScopeFilter)

    def test_custom_compiler_injection(self):
        compiler = ScopePatternCompiler()
        psf = PlanScopeFilter(compiler=compiler)
        result = psf.check("any.tool", ["*:*:*"])
        assert result.allowed is True

    def test_resource_glob_matching(self):
        # "reports.*" resource with wildcard verb/ns compiles to "reports.*"
        result = plan_scope_filter.check("reports.q3", ["*:*:reports.*"])
        assert result.allowed is True

    def test_resource_glob_no_match(self):
        result = plan_scope_filter.check("users.list", ["*:*:reports.*"])
        assert result.allowed is False


# ---------------------------------------------------------------------------
# APEP-300/301/302: Pydantic Model Tests
# ---------------------------------------------------------------------------


class TestScopePatternModels:
    """Unit tests for Sprint 38 Pydantic models."""

    def test_scope_token_serialization(self):
        token = ScopeToken(raw="read:public:docs", verb="read", namespace="public", resource="docs")
        data = token.model_dump()
        assert data["raw"] == "read:public:docs"
        assert data["verb"] == "read"

    def test_scope_parse_error_model(self):
        err = ScopeParseError(pattern="bad", error="Invalid", position=0)
        data = err.model_dump()
        assert data["pattern"] == "bad"
        assert data["position"] == 0

    def test_scope_parse_result_model(self):
        result = ScopeParseResult(
            tokens=[ScopeToken(raw="r:p:d", verb="r", namespace="p", resource="d")],
            errors=[],
            valid=True,
        )
        assert len(result.tokens) == 1
        assert result.valid

    def test_compiled_scope_model(self):
        cs = CompiledScope(
            source_pattern="read:public:docs",
            tool_glob="public.read.docs",
            verb="read",
            namespace="public",
            resource="docs",
        )
        data = cs.model_dump()
        assert data["tool_glob"] == "public.read.docs"

    def test_compile_result_model(self):
        cr = CompileResult(compiled=[], errors=[], valid=True)
        assert cr.valid

    def test_checkpoint_match_result_model(self):
        cmr = CheckpointMatchResult(
            matches=True, matched_pattern="*:*:*", tool_name="tool", detail="matched"
        )
        assert cmr.matches
        assert cmr.matched_pattern == "*:*:*"

    def test_scope_check_result_model(self):
        scr = ScopeCheckResult(
            allowed=True, matched_pattern="read:public:*", tool_name="docs", detail="ok"
        )
        assert scr.allowed

    def test_parse_scope_request_model(self):
        req = ParseScopeRequest(patterns=["read:public:*"])
        assert len(req.patterns) == 1

    def test_compile_scope_request_model(self):
        req = CompileScopeRequest(patterns=["read:public:*"])
        assert len(req.patterns) == 1

    def test_check_scope_request_model(self):
        req = CheckScopeRequest(tool_name="file.read", scope=["read:public:*"])
        assert req.tool_name == "file.read"

    def test_checkpoint_check_request_model(self):
        req = CheckpointCheckRequest(
            tool_name="db.write", requires_checkpoint=["write:secret:*"]
        )
        assert req.tool_name == "db.write"


# ---------------------------------------------------------------------------
# APEP-301/302/303/304: API Endpoint Tests
# ---------------------------------------------------------------------------


class TestScopePatternAPI:
    """API integration tests for Sprint 38 scope endpoints."""

    @pytest.mark.asyncio
    async def test_parse_valid_patterns(self):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers=_get_auth_headers(),
        ) as client:
            response = await client.post(
                "/v1/scopes/parse",
                json={"patterns": ["read:public:*", "write:internal:docs"]},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert len(data["tokens"]) == 2
        assert len(data["errors"]) == 0

    @pytest.mark.asyncio
    async def test_parse_invalid_patterns(self):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers=_get_auth_headers(),
        ) as client:
            response = await client.post(
                "/v1/scopes/parse",
                json={"patterns": ["invalid", "also-bad"]},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert len(data["errors"]) == 2

    @pytest.mark.asyncio
    async def test_parse_mixed_patterns(self):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers=_get_auth_headers(),
        ) as client:
            response = await client.post(
                "/v1/scopes/parse",
                json={"patterns": ["read:public:*", "bad"]},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False
        assert len(data["tokens"]) == 1
        assert len(data["errors"]) == 1

    @pytest.mark.asyncio
    async def test_compile_valid_patterns(self):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers=_get_auth_headers(),
        ) as client:
            response = await client.post(
                "/v1/scopes/compile",
                json={"patterns": ["*:*:*", "read:public:docs"]},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert len(data["compiled"]) == 2
        assert data["compiled"][0]["tool_glob"] == "*"

    @pytest.mark.asyncio
    async def test_compile_invalid_patterns(self):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers=_get_auth_headers(),
        ) as client:
            response = await client.post(
                "/v1/scopes/compile",
                json={"patterns": ["not-valid"]},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False

    @pytest.mark.asyncio
    async def test_check_scope_allowed(self):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers=_get_auth_headers(),
        ) as client:
            response = await client.post(
                "/v1/scopes/check",
                json={"tool_name": "anything", "scope": ["*:*:*"]},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["allowed"] is True

    @pytest.mark.asyncio
    async def test_check_scope_denied(self):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers=_get_auth_headers(),
        ) as client:
            response = await client.post(
                "/v1/scopes/check",
                json={"tool_name": "secret.delete", "scope": ["read:public:*"]},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["allowed"] is False

    @pytest.mark.asyncio
    async def test_checkpoint_matches(self):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers=_get_auth_headers(),
        ) as client:
            response = await client.post(
                "/v1/scopes/checkpoint",
                json={
                    "tool_name": "anything",
                    "requires_checkpoint": ["*:*:*"],
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["matches"] is True

    @pytest.mark.asyncio
    async def test_checkpoint_no_match(self):
        from app.main import app

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test",
            headers=_get_auth_headers(),
        ) as client:
            response = await client.post(
                "/v1/scopes/checkpoint",
                json={
                    "tool_name": "file.read",
                    "requires_checkpoint": ["write:secret:db"],
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["matches"] is False


# ---------------------------------------------------------------------------
# APEP-305: CLI scope compile Tests
# ---------------------------------------------------------------------------


class TestCLIScopeCompile:
    """Tests for agentpep scope compile CLI command."""

    def test_compile_single_pattern(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "sdk"))
        from agentpep.cli import main

        exit_code = main(["scope", "compile", "read:public:docs"])
        assert exit_code == 0

    def test_compile_multiple_patterns(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "sdk"))
        from agentpep.cli import main

        exit_code = main(["scope", "compile", "read:public:*", "*:*:*"])
        assert exit_code == 0

    def test_compile_invalid_pattern(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "sdk"))
        from agentpep.cli import main

        exit_code = main(["scope", "compile", "invalid"])
        assert exit_code == 1

    def test_compile_json_output(self, capsys):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "sdk"))
        from agentpep.cli import main

        exit_code = main(["scope", "compile", "--json", "read:public:docs"])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["valid"] is True
        assert "tool_glob" in data[0]


# ---------------------------------------------------------------------------
# APEP-306: CLI scope validate Tests
# ---------------------------------------------------------------------------


class TestCLIScopeValidate:
    """Tests for agentpep scope validate CLI command."""

    def test_validate_valid_plan(self, tmp_path):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "sdk"))
        from agentpep.cli import main

        plan_file = tmp_path / "plan.yaml"
        plan_file.write_text(
            "action: Analyze reports\n"
            "issuer: admin@example.com\n"
            "scope:\n"
            "  - read:public:*\n"
            "  - write:internal:reports.*\n"
            "requires_checkpoint:\n"
            "  - write:secret:*\n"
        )
        exit_code = main(["scope", "validate", str(plan_file)])
        assert exit_code == 0

    def test_validate_invalid_patterns(self, tmp_path):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "sdk"))
        from agentpep.cli import main

        plan_file = tmp_path / "plan.yaml"
        plan_file.write_text(
            "scope:\n"
            "  - invalid-pattern\n"
            "  - also bad\n"
        )
        exit_code = main(["scope", "validate", str(plan_file)])
        assert exit_code == 1

    def test_validate_no_patterns(self, tmp_path, capsys):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "sdk"))
        from agentpep.cli import main

        plan_file = tmp_path / "plan.yaml"
        plan_file.write_text("action: do something\n")
        exit_code = main(["scope", "validate", str(plan_file)])
        assert exit_code == 0

    def test_validate_file_not_found(self):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "sdk"))
        from agentpep.cli import main

        exit_code = main(["scope", "validate", "/nonexistent/plan.yaml"])
        assert exit_code == 1

    def test_validate_json_output(self, tmp_path, capsys):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "sdk"))
        from agentpep.cli import main

        plan_file = tmp_path / "plan.yaml"
        plan_file.write_text(
            "scope:\n  - read:public:*\nrequires_checkpoint:\n  - write:secret:*\n"
        )
        exit_code = main(["scope", "validate", "--json", str(plan_file)])
        assert exit_code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["valid"] is True
        assert data["total_patterns"] == 2


# ---------------------------------------------------------------------------
# APEP-307: Component & Adversarial Tests
# ---------------------------------------------------------------------------


class TestScopePatternComponent:
    """Component tests that verify end-to-end scope pattern workflows."""

    def test_parse_compile_match_workflow(self):
        """Parse -> Compile -> Match: full pipeline."""
        pattern = "read:public:reports.*"

        # Parse
        token = scope_pattern_parser.parse(pattern)
        assert isinstance(token, ScopeToken)

        # Compile
        compiled = scope_pattern_compiler.compile(pattern)
        assert isinstance(compiled, CompiledScope)

        # Match via PlanScopeFilter
        result = plan_scope_filter.check("public.read.reports.q3", [pattern])
        assert result.allowed is True

    def test_checkpoint_and_scope_independence(self):
        """Checkpoint filter and scope filter operate independently."""
        scope_patterns = ["read:public:*"]
        checkpoint_patterns = ["write:secret:*"]

        # A tool that's allowed by scope but triggers checkpoint
        scope_result = plan_scope_filter.check("secret.write.db", scope_patterns)
        checkpoint_result = plan_checkpoint_filter.matches(
            "secret.write.db", checkpoint_patterns
        )

        # Scope should deny (doesn't match read:public:*)
        assert scope_result.allowed is False
        # Checkpoint should match (matches write:secret:*)
        assert checkpoint_result.matches is True

    def test_batch_compile_consistency(self):
        """Compiling many patterns yields same results as individual compiles."""
        patterns = [
            "read:public:*",
            "*:*:*",
            "write:internal:reports.q3",
            "delete:pii:users.*",
        ]

        batch_result = scope_pattern_compiler.compile_many(patterns)
        assert batch_result.valid is True

        for i, pattern in enumerate(patterns):
            individual = scope_pattern_compiler.compile(pattern)
            assert isinstance(individual, CompiledScope)
            assert individual.tool_glob == batch_result.compiled[i].tool_glob


class TestScopePatternAdversarial:
    """Adversarial tests for scope pattern security."""

    def test_injection_in_pattern(self):
        """Patterns with injection-like characters are rejected."""
        result = scope_pattern_parser.parse("read:pub$(whoami):docs")
        assert isinstance(result, ScopeParseError)

    def test_path_traversal_in_resource(self):
        result = scope_pattern_parser.parse("read:public:../../etc/passwd")
        assert isinstance(result, ScopeParseError)

    def test_null_byte_in_pattern(self):
        result = scope_pattern_parser.parse("read:public:docs\x00evil")
        assert isinstance(result, ScopeParseError)

    def test_unicode_escape_in_pattern(self):
        result = scope_pattern_parser.parse("read:public:docs\u0000evil")
        assert isinstance(result, ScopeParseError)

    def test_very_long_resource_segment(self):
        long_resource = "a" * 300
        result = scope_pattern_parser.parse(f"read:public:{long_resource}")
        assert isinstance(result, ScopeParseError)

    def test_many_dots_in_resource(self):
        """Deeply nested resources should still parse (but shouldn't crash)."""
        resource = ".".join(["seg"] * 50)
        result = scope_pattern_parser.parse(f"*:*:{resource}")
        assert isinstance(result, ScopeToken)

    def test_wildcard_only_segments(self):
        """All-wildcard segments are valid."""
        result = scope_pattern_parser.parse("*:*:*")
        assert isinstance(result, ScopeToken)

    def test_glob_expansion_does_not_escape(self):
        """Glob matching should not access filesystem."""
        compiled = scope_pattern_compiler.compile("*:*:*")
        assert isinstance(compiled, CompiledScope)
        import fnmatch
        # The glob * should match any string but not cause filesystem access
        assert fnmatch.fnmatch("safe_tool", compiled.tool_glob)

    def test_empty_patterns_list_scope_check(self):
        """Empty scope list should allow all (permissive default)."""
        result = plan_scope_filter.check("dangerous.tool", [])
        assert result.allowed is True

    def test_scope_filter_with_only_invalid_patterns(self):
        """Invalid patterns don't compile — tool should not be allowed."""
        # Invalid patterns produce ScopeParseError from compile,
        # and won't match via direct fnmatch either
        result = plan_scope_filter.check("tool", ["invalid-no-colons"])
        # "invalid-no-colons" does not fnmatch "tool", so denied
        assert result.allowed is False
