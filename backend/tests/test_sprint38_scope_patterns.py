"""Tests for Sprint 38 -- Scope Pattern Language & DSL Compiler.

APEP-300: Scope pattern syntax unit tests.
APEP-301: ScopePatternParser unit tests.
APEP-302: ScopePatternCompiler unit tests.
APEP-303: PlanCheckpointFilter scope matching unit tests.
APEP-304: PlanScopeFilter scope allow-check unit tests.
APEP-305: CLI scope compile command tests.
APEP-306: CLI scope validate command tests.
APEP-307: Unit and component tests.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from app.models.mission_plan import MissionPlan, PlanBudget
from app.models.scope_pattern import (
    CheckpointScopeMatch,
    ScopeAllowResult,
    ScopeBatchCompileResponse,
    ScopeCompileResult,
    ScopeParseResult,
    ScopePattern,
    ScopeValidationResult,
    ScopeVerb,
    ScopeNamespace,
)
from app.services.scope_filter import (
    PlanCheckpointFilter,
    PlanScopeFilter,
    plan_checkpoint_filter,
    plan_scope_filter,
)
from app.services.scope_pattern_compiler import ScopePatternCompiler, scope_pattern_compiler
from app.services.scope_pattern_parser import (
    ScopePatternParser,
    VALID_VERBS,
    VALID_NAMESPACES,
    scope_pattern_parser,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_plan(**overrides) -> MissionPlan:
    """Create a MissionPlan with sensible defaults for testing."""
    defaults = {
        "action": "Test scope patterns",
        "issuer": "admin@example.com",
        "scope": ["read:public:*", "write:internal:reports.*"],
        "requires_checkpoint": ["write:secret:*", "delete:*:*"],
        "delegates_to": ["agent-alpha"],
        "budget": PlanBudget(max_delegations=10),
    }
    defaults.update(overrides)
    return MissionPlan(**defaults)


# ===========================================================================
# APEP-300: Scope Pattern Syntax Tests
# ===========================================================================


class TestScopePatternSyntax:
    """Tests for scope pattern syntax definition (verb:namespace:resource)."""

    def test_valid_verbs(self):
        """All valid verbs are recognized."""
        assert VALID_VERBS == {"read", "write", "delete", "execute", "send", "*"}

    def test_valid_namespaces(self):
        """All valid namespaces are recognized."""
        assert VALID_NAMESPACES == {"public", "secret", "internal", "external", "*"}

    def test_scope_verb_enum(self):
        """ScopeVerb enum has all valid values."""
        assert ScopeVerb.READ == "read"
        assert ScopeVerb.WRITE == "write"
        assert ScopeVerb.DELETE == "delete"
        assert ScopeVerb.EXECUTE == "execute"
        assert ScopeVerb.SEND == "send"
        assert ScopeVerb.WILDCARD == "*"

    def test_scope_namespace_enum(self):
        """ScopeNamespace enum has all valid values."""
        assert ScopeNamespace.PUBLIC == "public"
        assert ScopeNamespace.SECRET == "secret"
        assert ScopeNamespace.INTERNAL == "internal"
        assert ScopeNamespace.EXTERNAL == "external"
        assert ScopeNamespace.WILDCARD == "*"

    def test_scope_pattern_model_fields(self):
        """ScopePattern model has all required fields."""
        sp = ScopePattern(
            pattern="read:public:*",
            verb="read",
            namespace="public",
            resource_glob="*",
            mapped_rbac_patterns=["file.read.public.*"],
        )
        assert sp.pattern == "read:public:*"
        assert sp.verb == "read"
        assert sp.namespace == "public"
        assert sp.resource_glob == "*"
        assert sp.mapped_rbac_patterns == ["file.read.public.*"]

    def test_scope_pattern_minimal(self):
        """ScopePattern can be created with only pattern field."""
        sp = ScopePattern(pattern="read:public:*")
        assert sp.pattern == "read:public:*"
        assert sp.verb is None
        assert sp.namespace is None
        assert sp.resource_glob is None
        assert sp.mapped_rbac_patterns == []


# ===========================================================================
# APEP-301: ScopePatternParser Tests
# ===========================================================================


class TestScopePatternParser:
    """Tests for the ScopePatternParser service."""

    def setup_method(self):
        self.parser = ScopePatternParser()

    # --- Valid patterns ---

    def test_parse_simple_wildcard(self):
        """Parse a simple wildcard pattern."""
        result = self.parser.parse("read:public:*")
        assert result.valid is True
        assert result.scope_pattern is not None
        assert result.scope_pattern.verb == "read"
        assert result.scope_pattern.namespace == "public"
        assert result.scope_pattern.resource_glob == "*"

    def test_parse_specific_resource(self):
        """Parse a pattern with specific resource glob."""
        result = self.parser.parse("write:secret:credentials.*")
        assert result.valid is True
        assert result.scope_pattern is not None
        assert result.scope_pattern.verb == "write"
        assert result.scope_pattern.namespace == "secret"
        assert result.scope_pattern.resource_glob == "credentials.*"

    def test_parse_all_wildcard(self):
        """Parse the universal wildcard pattern."""
        result = self.parser.parse("*:*:*")
        assert result.valid is True
        assert result.scope_pattern is not None
        assert result.scope_pattern.verb == "*"
        assert result.scope_pattern.namespace == "*"
        assert result.scope_pattern.resource_glob == "*"

    def test_parse_execute_internal(self):
        """Parse execute:internal pattern."""
        result = self.parser.parse("execute:internal:deploy.*")
        assert result.valid is True
        sp = result.scope_pattern
        assert sp is not None
        assert sp.verb == "execute"
        assert sp.namespace == "internal"
        assert sp.resource_glob == "deploy.*"

    def test_parse_send_external(self):
        """Parse send:external pattern."""
        result = self.parser.parse("send:external:email.*")
        assert result.valid is True
        sp = result.scope_pattern
        assert sp is not None
        assert sp.verb == "send"
        assert sp.namespace == "external"

    def test_parse_case_insensitive(self):
        """Verb and namespace are case-insensitive."""
        result = self.parser.parse("READ:PUBLIC:reports.*")
        assert result.valid is True
        sp = result.scope_pattern
        assert sp is not None
        assert sp.verb == "read"
        assert sp.namespace == "public"
        assert sp.resource_glob == "reports.*"

    def test_parse_all_verb_namespace_combos(self):
        """Every verb+namespace combination is valid."""
        for verb in VALID_VERBS:
            for ns in VALID_NAMESPACES:
                result = self.parser.parse(f"{verb}:{ns}:test")
                assert result.valid is True, f"Failed for {verb}:{ns}:test"

    def test_parse_resource_with_path(self):
        """Resource glob can contain path separators."""
        result = self.parser.parse("read:internal:reports/q3/*")
        assert result.valid is True
        assert result.scope_pattern.resource_glob == "reports/q3/*"

    def test_parse_resource_with_question_mark(self):
        """Resource glob supports ? wildcard."""
        result = self.parser.parse("read:public:file?.txt")
        assert result.valid is True
        assert result.scope_pattern.resource_glob == "file?.txt"

    # --- Invalid patterns ---

    def test_parse_empty_string(self):
        """Empty string is invalid."""
        result = self.parser.parse("")
        assert result.valid is False
        assert "non-empty" in result.error

    def test_parse_missing_parts(self):
        """Pattern without colons is invalid."""
        result = self.parser.parse("read")
        assert result.valid is False
        assert "expected format" in result.error

    def test_parse_two_parts(self):
        """Pattern with only two parts is invalid."""
        result = self.parser.parse("read:public")
        assert result.valid is False
        assert "2 part(s)" in result.error

    def test_parse_four_parts(self):
        """Pattern with four parts is invalid."""
        result = self.parser.parse("read:public:foo:bar")
        assert result.valid is False
        assert "4 part(s)" in result.error

    def test_parse_invalid_verb(self):
        """Invalid verb is rejected."""
        result = self.parser.parse("update:public:*")
        assert result.valid is False
        assert "Invalid verb" in result.error

    def test_parse_invalid_namespace(self):
        """Invalid namespace is rejected."""
        result = self.parser.parse("read:private:*")
        assert result.valid is False
        assert "Invalid namespace" in result.error

    def test_parse_empty_resource(self):
        """Empty resource glob is rejected."""
        result = self.parser.parse("read:public:")
        assert result.valid is False
        assert "Empty resource" in result.error

    def test_parse_invalid_resource_chars(self):
        """Resource glob with invalid characters is rejected."""
        result = self.parser.parse("read:public:test;rm -rf")
        assert result.valid is False
        assert "Invalid resource glob" in result.error

    def test_parse_too_long(self):
        """Pattern exceeding max length is rejected."""
        long_pattern = "read:public:" + "a" * 250
        result = self.parser.parse(long_pattern)
        assert result.valid is False
        assert "maximum length" in result.error

    # --- Batch parsing ---

    def test_parse_many(self):
        """Parse multiple patterns at once."""
        results = self.parser.parse_many([
            "read:public:*",
            "invalid",
            "write:secret:creds.*",
        ])
        assert len(results) == 3
        assert results[0].valid is True
        assert results[1].valid is False
        assert results[2].valid is True

    def test_is_valid(self):
        """Quick validity check."""
        assert self.parser.is_valid("read:public:*") is True
        assert self.parser.is_valid("bad:pattern") is False

    # --- Singleton ---

    def test_module_singleton(self):
        """Module-level singleton is available."""
        assert scope_pattern_parser is not None
        result = scope_pattern_parser.parse("read:public:*")
        assert result.valid is True


# ===========================================================================
# APEP-302: ScopePatternCompiler Tests
# ===========================================================================


class TestScopePatternCompiler:
    """Tests for the ScopePatternCompiler service."""

    def setup_method(self):
        self.compiler = ScopePatternCompiler()

    def test_compile_read_public_wildcard(self):
        """Compile read:public:* produces read-oriented RBAC patterns."""
        result = self.compiler.compile("read:public:*")
        assert len(result.rbac_patterns) > 0
        assert result.warnings == []
        # Should include file.read.public.*, db.read.public.*, etc.
        assert "file.read.public.*" in result.rbac_patterns
        assert "db.read.public.*" in result.rbac_patterns
        assert "api.get.public.*" in result.rbac_patterns

    def test_compile_write_secret(self):
        """Compile write:secret:creds.* produces write+secret RBAC patterns."""
        result = self.compiler.compile("write:secret:creds.*")
        assert len(result.rbac_patterns) > 0
        assert "file.write.secret.creds.*" in result.rbac_patterns
        assert "file.write.credential.creds.*" in result.rbac_patterns

    def test_compile_full_wildcard(self):
        """Compile *:*:* produces unrestricted pattern."""
        result = self.compiler.compile("*:*:*")
        assert result.rbac_patterns == ["*"]

    def test_compile_execute_internal(self):
        """Compile execute:internal produces execute-oriented patterns."""
        result = self.compiler.compile("execute:internal:deploy.*")
        assert len(result.rbac_patterns) > 0
        assert "exec.internal.deploy.*" in result.rbac_patterns
        assert "shell.internal.deploy.*" in result.rbac_patterns
        assert "exec.admin.deploy.*" in result.rbac_patterns

    def test_compile_send_external(self):
        """Compile send:external produces send-oriented patterns."""
        result = self.compiler.compile("send:external:*")
        assert len(result.rbac_patterns) > 0
        assert "email.send.external.*" in result.rbac_patterns
        assert "slack.send.external.*" in result.rbac_patterns

    def test_compile_delete_wildcard_ns(self):
        """Compile delete:*:* produces delete patterns with wildcard namespace."""
        result = self.compiler.compile("delete:*:*")
        assert len(result.rbac_patterns) > 0
        assert "file.delete.*.*" in result.rbac_patterns

    def test_compile_wildcard_verb_public(self):
        """Compile *:public:* produces wildcard verb patterns."""
        result = self.compiler.compile("*:public:reports.*")
        assert len(result.rbac_patterns) > 0
        assert "*.public.reports.*" in result.rbac_patterns

    def test_compile_invalid_pattern(self):
        """Compiling invalid pattern returns warnings."""
        result = self.compiler.compile("invalid-pattern")
        assert result.rbac_patterns == []
        assert len(result.warnings) > 0

    def test_compile_no_duplicates(self):
        """Compiled patterns are deduplicated."""
        result = self.compiler.compile("read:public:*")
        assert len(result.rbac_patterns) == len(set(result.rbac_patterns))

    def test_compile_preserves_scope_pattern(self):
        """Compiled result includes the source scope pattern."""
        result = self.compiler.compile("read:public:*")
        assert result.scope_pattern.pattern == "read:public:*"
        assert result.scope_pattern.verb == "read"
        assert result.scope_pattern.namespace == "public"

    def test_compile_many(self):
        """Compile multiple patterns and get aggregated results."""
        response = self.compiler.compile_many([
            "read:public:*",
            "write:secret:creds.*",
        ])
        assert len(response.results) == 2
        assert response.results[0].scope_pattern.verb == "read"
        assert response.results[1].scope_pattern.verb == "write"
        # all_rbac_patterns is the union of both
        assert len(response.all_rbac_patterns) > 0

    def test_matches_tool_positive(self):
        """matches_tool returns scope pattern that matches."""
        matched = self.compiler.matches_tool(
            ["read:public:*", "write:secret:*"],
            "file.read.public.report.csv",
        )
        assert matched == "read:public:*"

    def test_matches_tool_negative(self):
        """matches_tool returns None when no match."""
        matched = self.compiler.matches_tool(
            ["read:public:*"],
            "file.write.secret.credentials",
        )
        assert matched is None

    def test_matches_tool_universal(self):
        """Universal wildcard matches everything."""
        matched = self.compiler.matches_tool(
            ["*:*:*"],
            "anything.at.all",
        )
        assert matched == "*:*:*"

    # --- Singleton ---

    def test_module_singleton(self):
        """Module-level singleton is available."""
        assert scope_pattern_compiler is not None
        result = scope_pattern_compiler.compile("read:public:*")
        assert len(result.rbac_patterns) > 0


# ===========================================================================
# APEP-303: PlanCheckpointFilter Tests
# ===========================================================================


class TestPlanCheckpointFilter:
    """Tests for PlanCheckpointFilter scope matching."""

    def setup_method(self):
        self.filter = PlanCheckpointFilter()

    def test_checkpoint_match_scope_pattern(self):
        """Tool matching a checkpoint scope pattern is flagged."""
        plan = _make_plan(requires_checkpoint=["write:secret:*"])
        result = self.filter.check(plan, "file.write.secret.credentials")
        assert result.matches is True
        assert result.matched_pattern == "write:secret:*"
        assert result.tool_name == "file.write.secret.credentials"

    def test_checkpoint_no_match(self):
        """Tool not matching any checkpoint pattern passes."""
        plan = _make_plan(requires_checkpoint=["write:secret:*"])
        result = self.filter.check(plan, "file.read.public.report")
        assert result.matches is False
        assert result.matched_pattern is None

    def test_checkpoint_empty_list(self):
        """Empty checkpoint list never matches."""
        plan = _make_plan(requires_checkpoint=[])
        result = self.filter.check(plan, "anything")
        assert result.matches is False

    def test_checkpoint_fallback_glob(self):
        """Non-scope patterns use fnmatch fallback (Sprint 37 compat)."""
        plan = _make_plan(requires_checkpoint=["file.write.*"])
        result = self.filter.check(plan, "file.write.secret.creds")
        assert result.matches is True
        assert result.matched_pattern == "file.write.*"
        assert "direct glob" in result.reason

    def test_checkpoint_scope_and_glob_mixed(self):
        """Mix of scope patterns and globs works correctly."""
        plan = _make_plan(requires_checkpoint=[
            "delete:*:*",          # scope pattern
            "admin.override.*",    # direct glob
        ])
        # Matches scope pattern
        result1 = self.filter.check(plan, "file.delete.internal.report")
        assert result1.matches is True

        # Matches direct glob
        result2 = self.filter.check(plan, "admin.override.reset")
        assert result2.matches is True

        # Matches neither
        result3 = self.filter.check(plan, "file.read.public.data")
        assert result3.matches is False

    def test_checkpoint_delete_wildcard(self):
        """delete:*:* matches any delete tool."""
        plan = _make_plan(requires_checkpoint=["delete:*:*"])
        result = self.filter.check(plan, "file.delete.public.temp")
        assert result.matches is True

    # --- Singleton ---

    def test_module_singleton(self):
        """Module-level singleton is available."""
        assert plan_checkpoint_filter is not None


# ===========================================================================
# APEP-304: PlanScopeFilter Tests
# ===========================================================================


class TestPlanScopeFilter:
    """Tests for PlanScopeFilter scope allow-check."""

    def setup_method(self):
        self.filter = PlanScopeFilter()

    def test_scope_allow_matching_tool(self):
        """Tool within plan scope is allowed."""
        plan = _make_plan(scope=["read:public:*", "write:internal:reports.*"])
        result = self.filter.check(plan, "file.read.public.data.csv")
        assert result.allowed is True
        assert result.matched_scope == "read:public:*"

    def test_scope_deny_outside_scope(self):
        """Tool outside plan scope is denied."""
        plan = _make_plan(scope=["read:public:*"])
        result = self.filter.check(plan, "file.write.secret.credentials")
        assert result.allowed is False
        assert result.matched_scope is None
        assert "outside the plan's allowed scope" in result.reason

    def test_scope_empty_allows_all(self):
        """Empty scope list means no restrictions."""
        plan = _make_plan(scope=[])
        result = self.filter.check(plan, "anything.at.all")
        assert result.allowed is True
        assert "no scope restrictions" in result.reason

    def test_scope_universal_wildcard(self):
        """*:*:* scope allows everything."""
        plan = _make_plan(scope=["*:*:*"])
        result = self.filter.check(plan, "file.write.secret.credentials")
        assert result.allowed is True

    def test_scope_fallback_glob(self):
        """Non-scope patterns use fnmatch fallback."""
        plan = _make_plan(scope=["file.read.*", "api.get.*"])
        result = self.filter.check(plan, "file.read.public.data")
        assert result.allowed is True
        assert result.matched_scope == "file.read.*"

    def test_scope_multiple_patterns(self):
        """Second pattern matches when first doesn't."""
        plan = _make_plan(scope=[
            "read:public:reports.*",
            "write:internal:*",
        ])
        result = self.filter.check(plan, "file.write.internal.config")
        assert result.allowed is True
        assert result.matched_scope == "write:internal:*"

    def test_scope_write_internal_reports(self):
        """write:internal:reports.* matches specific tool."""
        plan = _make_plan(scope=["write:internal:reports.*"])
        result = self.filter.check(plan, "file.write.internal.reports.q3")
        assert result.allowed is True

    # --- Singleton ---

    def test_module_singleton(self):
        """Module-level singleton is available."""
        assert plan_scope_filter is not None


# ===========================================================================
# APEP-305: CLI scope compile Tests
# ===========================================================================


class TestCLIScopeCompile:
    """Tests for the 'agentpep scope compile' CLI command."""

    def test_compile_valid_pattern(self):
        """Compiling a valid pattern succeeds."""
        from agentpep.cli import main

        ret = main(["scope", "compile", "read:public:*"])
        assert ret == 0

    def test_compile_invalid_pattern(self):
        """Compiling an invalid pattern fails."""
        from agentpep.cli import main

        ret = main(["scope", "compile", "invalid"])
        assert ret == 1

    def test_compile_invalid_verb(self):
        """Compiling with invalid verb fails."""
        from agentpep.cli import main

        ret = main(["scope", "compile", "update:public:*"])
        assert ret == 1

    def test_compile_json_output(self):
        """JSON output includes expected fields."""
        import io
        from contextlib import redirect_stdout

        from agentpep.cli import main

        buf = io.StringIO()
        with redirect_stdout(buf):
            ret = main(["scope", "compile", "read:public:*", "--json"])

        assert ret == 0
        output = json.loads(buf.getvalue())
        assert output["scope_pattern"] == "read:public:*"
        assert output["verb"] == "read"
        assert output["namespace"] == "public"
        assert output["resource_glob"] == "*"
        assert len(output["rbac_patterns"]) > 0

    def test_compile_universal_wildcard(self):
        """Compiling *:*:* produces single wildcard pattern."""
        import io
        from contextlib import redirect_stdout

        from agentpep.cli import main

        buf = io.StringIO()
        with redirect_stdout(buf):
            ret = main(["scope", "compile", "*:*:*", "--json"])

        assert ret == 0
        output = json.loads(buf.getvalue())
        assert output["rbac_patterns"] == ["*"]


# ===========================================================================
# APEP-306: CLI scope validate Tests
# ===========================================================================


class TestCLIScopeValidate:
    """Tests for the 'agentpep scope validate' CLI command."""

    def _write_plan_yaml(self, data: dict) -> str:
        """Write plan data as a YAML file and return the path."""
        import yaml

        fd, path = tempfile.mkstemp(suffix=".yaml")
        os.close(fd)
        Path(path).write_text(yaml.dump(data))
        return path

    def test_validate_all_valid(self):
        """Plan with all valid scope patterns passes."""
        from agentpep.cli import main

        path = self._write_plan_yaml({
            "scope": ["read:public:*", "write:internal:reports.*"],
            "requires_checkpoint": ["delete:secret:*"],
        })
        try:
            ret = main(["scope", "validate", path])
            assert ret == 0
        finally:
            os.unlink(path)

    def test_validate_invalid_patterns(self):
        """Plan with invalid scope patterns fails."""
        from agentpep.cli import main

        path = self._write_plan_yaml({
            "scope": ["read:public:*", "invalid-pattern"],
        })
        try:
            ret = main(["scope", "validate", path])
            assert ret == 1
        finally:
            os.unlink(path)

    def test_validate_no_patterns(self):
        """Plan with no scope patterns succeeds."""
        from agentpep.cli import main

        path = self._write_plan_yaml({
            "action": "Test plan",
        })
        try:
            ret = main(["scope", "validate", path])
            assert ret == 0
        finally:
            os.unlink(path)

    def test_validate_json_output(self):
        """JSON output includes validation details."""
        import io
        from contextlib import redirect_stdout

        from agentpep.cli import main

        path = self._write_plan_yaml({
            "scope": ["read:public:*", "bad-pattern"],
            "requires_checkpoint": ["write:secret:*"],
        })
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                ret = main(["scope", "validate", path, "--json"])

            assert ret == 1
            output = json.loads(buf.getvalue())
            assert output["valid"] is False
            assert output["total_patterns"] == 3
            assert output["valid_patterns"] == 2
            assert output["invalid_patterns"] == 1
            assert len(output["errors"]) == 1
        finally:
            os.unlink(path)

    def test_validate_missing_file(self):
        """Missing file returns error."""
        from agentpep.cli import main

        ret = main(["scope", "validate", "/nonexistent/plan.yaml"])
        assert ret == 1


# ===========================================================================
# APEP-307: Component Tests (cross-cutting)
# ===========================================================================


class TestScopePatternComponents:
    """Cross-cutting component tests for Sprint 38."""

    def test_parse_then_compile_roundtrip(self):
        """Parsing then compiling a pattern produces valid RBAC globs."""
        parser = ScopePatternParser()
        compiler = ScopePatternCompiler()

        parse_result = parser.parse("read:public:reports.*")
        assert parse_result.valid is True

        compile_result = compiler.compile(parse_result.scope_pattern.pattern)
        assert len(compile_result.rbac_patterns) > 0
        assert compile_result.scope_pattern.verb == "read"

    def test_compiler_and_filter_agreement(self):
        """ScopePatternCompiler and PlanScopeFilter agree on scope checks."""
        compiler = ScopePatternCompiler()
        scope_filter = PlanScopeFilter()

        scope = ["read:public:*"]
        tool = "file.read.public.report.csv"

        # Compiler says it matches
        matched = compiler.matches_tool(scope, tool)
        assert matched is not None

        # Filter also allows it
        plan = _make_plan(scope=scope)
        result = scope_filter.check(plan, tool)
        assert result.allowed is True

    def test_checkpoint_filter_uses_compiled_scope(self):
        """PlanCheckpointFilter uses compiled scope patterns for matching."""
        filt = PlanCheckpointFilter()

        plan = _make_plan(requires_checkpoint=["write:secret:*"])
        # This tool matches the compiled RBAC glob pattern
        result = filt.check(plan, "file.write.secret.credentials")
        assert result.matches is True
        assert "write:secret:*" in result.matched_pattern

    def test_scope_filter_denies_then_checkpoint_not_reached(self):
        """If scope filter denies, checkpoint filter doesn't matter."""
        scope_filter = PlanScopeFilter()
        checkpoint_filter = PlanCheckpointFilter()

        plan = _make_plan(
            scope=["read:public:*"],
            requires_checkpoint=["write:secret:*"],
        )
        tool = "file.write.secret.credentials"

        scope_result = scope_filter.check(plan, tool)
        assert scope_result.allowed is False

        # Even though checkpoint would match, scope blocks first
        checkpoint_result = checkpoint_filter.check(plan, tool)
        assert checkpoint_result.matches is True
        # In the pipeline, scope denial takes precedence

    def test_all_verbs_compile(self):
        """Every verb compiles to at least one RBAC pattern."""
        compiler = ScopePatternCompiler()
        for verb in VALID_VERBS:
            result = compiler.compile(f"{verb}:public:*")
            assert len(result.rbac_patterns) > 0, f"No patterns for verb '{verb}'"

    def test_all_namespaces_compile(self):
        """Every namespace compiles to at least one RBAC pattern."""
        compiler = ScopePatternCompiler()
        for ns in VALID_NAMESPACES:
            result = compiler.compile(f"read:{ns}:*")
            assert len(result.rbac_patterns) > 0, f"No patterns for namespace '{ns}'"

    def test_scope_pattern_serialization(self):
        """ScopePattern can be serialized and deserialized."""
        sp = ScopePattern(
            pattern="read:public:*",
            verb="read",
            namespace="public",
            resource_glob="*",
            mapped_rbac_patterns=["file.read.public.*"],
        )
        data = sp.model_dump(mode="json")
        sp2 = ScopePattern(**data)
        assert sp2.pattern == sp.pattern
        assert sp2.verb == sp.verb
        assert sp2.mapped_rbac_patterns == sp.mapped_rbac_patterns

    def test_compile_result_serialization(self):
        """ScopeCompileResult can be serialized."""
        compiler = ScopePatternCompiler()
        result = compiler.compile("read:public:*")
        data = result.model_dump(mode="json")
        assert "scope_pattern" in data
        assert "rbac_patterns" in data
        assert len(data["rbac_patterns"]) > 0

    def test_batch_compile_response_serialization(self):
        """ScopeBatchCompileResponse can be serialized."""
        compiler = ScopePatternCompiler()
        response = compiler.compile_many(["read:public:*", "write:secret:*"])
        data = response.model_dump(mode="json")
        assert "results" in data
        assert "all_rbac_patterns" in data
        assert len(data["results"]) == 2


# ===========================================================================
# APEP-307: Adversarial / Edge Case Tests
# ===========================================================================


class TestScopePatternAdversarial:
    """Adversarial and edge case tests for scope patterns."""

    def test_injection_in_resource_glob(self):
        """Resource glob with injection characters is rejected."""
        parser = ScopePatternParser()
        # Semicolons, backticks, and other shell injection chars
        assert parser.is_valid("read:public:$(rm -rf /)") is False
        assert parser.is_valid("read:public:`whoami`") is False
        assert parser.is_valid("read:public:test;ls") is False
        assert parser.is_valid("read:public:test|cat") is False
        assert parser.is_valid("read:public:test&&echo") is False

    def test_empty_verb(self):
        """Empty verb is rejected."""
        parser = ScopePatternParser()
        result = parser.parse(":public:*")
        assert result.valid is False

    def test_empty_namespace(self):
        """Empty namespace is rejected."""
        parser = ScopePatternParser()
        result = parser.parse("read::*")
        assert result.valid is False

    def test_whitespace_in_parts(self):
        """Whitespace in scope parts is rejected."""
        parser = ScopePatternParser()
        assert parser.is_valid("read :public:*") is False
        assert parser.is_valid("read: public:*") is False
        assert parser.is_valid("read:public: *") is False

    def test_none_input(self):
        """None input is handled gracefully."""
        parser = ScopePatternParser()
        result = parser.parse(None)  # type: ignore[arg-type]
        assert result.valid is False

    def test_very_deep_resource_path(self):
        """Deep resource path is valid if within length."""
        parser = ScopePatternParser()
        deep_resource = "/".join(["a"] * 20)
        result = parser.parse(f"read:public:{deep_resource}")
        assert result.valid is True

    def test_compiler_with_custom_prefix_map(self):
        """Compiler uses custom prefix maps when provided."""
        compiler = ScopePatternCompiler(
            verb_prefixes={"read": ["custom.read"]},
            namespace_segments={"public": ["pub"]},
        )
        result = compiler.compile("read:public:*")
        assert result.rbac_patterns == ["custom.read.pub.*"]
        assert len(result.warnings) == 0

    def test_compiler_with_unknown_verb_warns(self):
        """Compiler warns when verb has no prefix mapping."""
        compiler = ScopePatternCompiler(
            verb_prefixes={"write": ["file.write"]},
            namespace_segments={"public": ["pub"]},
        )
        result = compiler.compile("read:public:*")
        assert len(result.rbac_patterns) > 0
        assert len(result.warnings) > 0
        assert "No tool prefix mapping" in result.warnings[0]

    def test_filter_with_adversarial_tool_name(self):
        """Filters handle adversarial tool names safely."""
        filt = PlanScopeFilter()
        plan = _make_plan(scope=["read:public:*"])
        # Tool name that looks like it might cause issues
        result = filt.check(plan, "../../../etc/passwd")
        # Should simply not match
        assert result.allowed is False

    def test_checkpoint_filter_with_many_patterns(self):
        """Checkpoint filter handles many patterns efficiently."""
        filt = PlanCheckpointFilter()
        patterns = [f"write:secret:resource{i}.*" for i in range(100)]
        plan = _make_plan(requires_checkpoint=patterns)
        # Match the last pattern
        result = filt.check(plan, "file.write.secret.resource99.data")
        assert result.matches is True
        assert "resource99" in result.matched_pattern
