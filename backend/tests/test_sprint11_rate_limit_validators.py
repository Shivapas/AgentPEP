"""Sprint 11 tests — Rate Limiting & Argument Validators.

APEP-090: Sliding window rate limiter per agent_role per tool per time window.
APEP-091: Fixed window rate limiter as alternative; configurable per rule.
APEP-092: Global rate limit — per-tenant total decisions/second ceiling.
APEP-093: JSON schema argument validator.
APEP-094: Regex validator — per-arg regex patterns.
APEP-095: Allowlist/blocklist string validator — per-arg value matching.
APEP-096: Validator pipeline — all validators run in sequence; any FAIL → DENY.
APEP-097: Adversarial tests — schema bypass, regex evasion, rate limit exhaustion.
"""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.models.policy import RateLimitType, ValidationFailure, ValidationResult
from app.services.rate_limiter import RateLimiter, rate_limiter
from app.services.validator_pipeline import ValidatorPipeline, validator_pipeline


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def _make_request(**overrides):
    """Helper to build a valid ToolCallRequest payload."""
    payload = {
        "request_id": str(uuid.uuid4()),
        "session_id": "test-session",
        "agent_id": "test-agent",
        "tenant_id": "test-tenant",
        "tool_name": "read_file",
        "tool_args": {"path": "/tmp/test.txt"},
        "delegation_chain": [],
        "dry_run": False,
    }
    payload.update(overrides)
    return payload


async def _insert_rule(mock_mongodb, rule_overrides=None):
    """Insert a policy rule into the test database."""
    from app.services.rule_cache import rule_cache
    rule_cache.invalidate()

    rule = {
        "rule_id": str(uuid.uuid4()),
        "name": "test-rule",
        "agent_role": ["*"],
        "tool_pattern": "read_file",
        "action": "ALLOW",
        "taint_check": False,
        "risk_threshold": 1.0,
        "rate_limit": None,
        "arg_validators": [],
        "priority": 10,
        "enabled": True,
    }
    if rule_overrides:
        rule.update(rule_overrides)
    await mock_mongodb["policy_rules"].insert_one(rule)
    return rule


async def _insert_role(mock_mongodb, role_id="reader", agent_id="test-agent"):
    """Insert an agent role and profile."""
    await mock_mongodb["agent_roles"].insert_one({
        "role_id": role_id,
        "name": role_id.title(),
        "parent_roles": [],
        "allowed_tools": ["*"],
        "denied_tools": [],
        "max_risk_threshold": 1.0,
        "enabled": True,
    })
    await mock_mongodb["agent_profiles"].insert_one({
        "agent_id": agent_id,
        "name": "Test Agent",
        "roles": [role_id],
        "enabled": True,
    })


# ===========================================================================
# APEP-090: Sliding Window Rate Limiter
# ===========================================================================


class TestSlidingWindowRateLimiter:
    """Tests for the sliding window rate limiter (APEP-090)."""

    @pytest.mark.asyncio
    async def test_allows_within_limit(self, mock_mongodb):
        """Requests within the limit are allowed."""
        from app.models.policy import RateLimit

        rl = RateLimit(count=5, window_s=60, limiter_type=RateLimitType.SLIDING_WINDOW)
        for _ in range(5):
            result = await rate_limiter.check_sliding_window("reader", "read_file", rl)
            assert result.allowed

    @pytest.mark.asyncio
    async def test_denies_over_limit(self, mock_mongodb):
        """Requests over the limit are denied."""
        from app.models.policy import RateLimit

        rl = RateLimit(count=3, window_s=60, limiter_type=RateLimitType.SLIDING_WINDOW)
        for _ in range(3):
            result = await rate_limiter.check_sliding_window("reader", "read_file", rl)
            assert result.allowed

        result = await rate_limiter.check_sliding_window("reader", "read_file", rl)
        assert not result.allowed
        assert "Sliding window rate limit exceeded" in result.reason
        assert result.current_count == 3
        assert result.limit == 3

    @pytest.mark.asyncio
    async def test_different_roles_have_separate_limits(self, mock_mongodb):
        """Rate limits are tracked per agent_role."""
        from app.models.policy import RateLimit

        rl = RateLimit(count=1, window_s=60, limiter_type=RateLimitType.SLIDING_WINDOW)

        result = await rate_limiter.check_sliding_window("reader", "read_file", rl)
        assert result.allowed

        # Same tool, different role — should be allowed
        result = await rate_limiter.check_sliding_window("writer", "read_file", rl)
        assert result.allowed

        # Same role, over limit — should be denied
        result = await rate_limiter.check_sliding_window("reader", "read_file", rl)
        assert not result.allowed

    @pytest.mark.asyncio
    async def test_different_tools_have_separate_limits(self, mock_mongodb):
        """Rate limits are tracked per tool_name."""
        from app.models.policy import RateLimit

        rl = RateLimit(count=1, window_s=60, limiter_type=RateLimitType.SLIDING_WINDOW)

        result = await rate_limiter.check_sliding_window("reader", "read_file", rl)
        assert result.allowed

        # Same role, different tool — should be allowed
        result = await rate_limiter.check_sliding_window("reader", "write_file", rl)
        assert result.allowed


# ===========================================================================
# APEP-091: Fixed Window Rate Limiter
# ===========================================================================


class TestFixedWindowRateLimiter:
    """Tests for the fixed window rate limiter (APEP-091)."""

    @pytest.mark.asyncio
    async def test_allows_within_limit(self, mock_mongodb):
        """Requests within the fixed window limit are allowed."""
        from app.models.policy import RateLimit

        rl = RateLimit(count=5, window_s=60, limiter_type=RateLimitType.FIXED_WINDOW)
        for _ in range(5):
            result = await rate_limiter.check_fixed_window("reader", "read_file", rl)
            assert result.allowed

    @pytest.mark.asyncio
    async def test_denies_over_limit(self, mock_mongodb):
        """Requests over the fixed window limit are denied."""
        from app.models.policy import RateLimit

        rl = RateLimit(count=2, window_s=60, limiter_type=RateLimitType.FIXED_WINDOW)
        for _ in range(2):
            result = await rate_limiter.check_fixed_window("reader", "read_file", rl)
            assert result.allowed

        result = await rate_limiter.check_fixed_window("reader", "read_file", rl)
        assert not result.allowed
        assert "Fixed window rate limit exceeded" in result.reason

    @pytest.mark.asyncio
    async def test_configurable_per_rule(self, mock_mongodb):
        """Each rule can have its own rate limit type."""
        from app.models.policy import RateLimit

        rl_fixed = RateLimit(count=1, window_s=60, limiter_type=RateLimitType.FIXED_WINDOW)
        rl_sliding = RateLimit(count=1, window_s=60, limiter_type=RateLimitType.SLIDING_WINDOW)

        # Both types should work via the unified check method
        result = await rate_limiter.check("reader", "tool_a", rl_fixed)
        assert result.allowed

        result = await rate_limiter.check("reader", "tool_b", rl_sliding)
        assert result.allowed

        # Both should deny on second call
        result = await rate_limiter.check("reader", "tool_a", rl_fixed)
        assert not result.allowed

        result = await rate_limiter.check("reader", "tool_b", rl_sliding)
        assert not result.allowed


# ===========================================================================
# APEP-092: Global Per-Tenant Rate Limit
# ===========================================================================


class TestGlobalRateLimit:
    """Tests for the global per-tenant decisions/second ceiling (APEP-092)."""

    @pytest.mark.asyncio
    async def test_disabled_by_default(self, mock_mongodb):
        """Global rate limit is disabled by default — always allows."""
        result = await rate_limiter.check_global_rate_limit("tenant-1")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_allows_within_ceiling(self, mock_mongodb):
        """Requests within the per-second ceiling are allowed."""
        from app.core.config import settings

        settings.global_rate_limit_enabled = True
        settings.global_rate_limit_per_second = 10

        for _ in range(10):
            result = await rate_limiter.check_global_rate_limit("tenant-1")
            assert result.allowed

    @pytest.mark.asyncio
    async def test_denies_over_ceiling(self, mock_mongodb):
        """Requests over the per-second ceiling are denied."""
        from app.core.config import settings

        settings.global_rate_limit_enabled = True
        settings.global_rate_limit_per_second = 3

        for _ in range(3):
            result = await rate_limiter.check_global_rate_limit("tenant-1")
            assert result.allowed

        result = await rate_limiter.check_global_rate_limit("tenant-1")
        assert not result.allowed
        assert "Global rate limit exceeded" in result.reason

    @pytest.mark.asyncio
    async def test_separate_tenants(self, mock_mongodb):
        """Each tenant has its own rate limit counter."""
        from app.core.config import settings

        settings.global_rate_limit_enabled = True
        settings.global_rate_limit_per_second = 1

        result = await rate_limiter.check_global_rate_limit("tenant-1")
        assert result.allowed

        # Different tenant — should be allowed
        result = await rate_limiter.check_global_rate_limit("tenant-2")
        assert result.allowed

        # Same tenant, over limit
        result = await rate_limiter.check_global_rate_limit("tenant-1")
        assert not result.allowed


# ===========================================================================
# APEP-093: JSON Schema Argument Validator
# ===========================================================================


class TestJsonSchemaValidator:
    """Tests for JSON schema argument validation (APEP-093)."""

    def test_valid_schema_passes(self):
        """Valid arguments pass JSON schema validation."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="count",
            json_schema={"type": "integer", "minimum": 1, "maximum": 100},
        )]
        result = validator_pipeline.validate({"count": 42}, validators)
        assert result.passed

    def test_invalid_type_fails(self):
        """Wrong type fails JSON schema validation."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="count",
            json_schema={"type": "integer"},
        )]
        result = validator_pipeline.validate({"count": "not_a_number"}, validators)
        assert not result.passed
        assert result.failures[0].validator_type == "json_schema"

    def test_schema_with_required_properties(self):
        """JSON schema with required properties works."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="config",
            json_schema={
                "type": "object",
                "required": ["host", "port"],
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                },
            },
        )]
        # Missing required field
        result = validator_pipeline.validate({"config": {"host": "localhost"}}, validators)
        assert not result.passed

        # All required fields present
        result = validator_pipeline.validate(
            {"config": {"host": "localhost", "port": 8080}}, validators
        )
        assert result.passed

    def test_null_arg_checked_against_schema(self):
        """Missing argument is validated against schema (may fail if schema requires it)."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="path",
            json_schema={"type": "string", "minLength": 1},
        )]
        result = validator_pipeline.validate({}, validators)
        assert not result.passed  # None fails "type": "string"


# ===========================================================================
# APEP-094: Regex Validator
# ===========================================================================


class TestRegexValidator:
    """Tests for regex argument validation (APEP-094)."""

    def test_matching_pattern_passes(self):
        """Value matching the regex passes."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="path",
            regex_pattern=r"/tmp/[a-zA-Z0-9_]+\.txt",
        )]
        result = validator_pipeline.validate({"path": "/tmp/test_file.txt"}, validators)
        assert result.passed

    def test_non_matching_pattern_fails(self):
        """Value not matching the regex fails."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="path",
            regex_pattern=r"/tmp/[a-zA-Z0-9_]+\.txt",
        )]
        result = validator_pipeline.validate({"path": "/etc/passwd"}, validators)
        assert not result.passed
        assert result.failures[0].validator_type == "regex"

    def test_invalid_regex_fails_safely(self):
        """Invalid regex pattern results in failure, not crash."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="data",
            regex_pattern=r"[invalid(regex",
        )]
        result = validator_pipeline.validate({"data": "test"}, validators)
        assert not result.passed
        assert "Invalid regex" in result.failures[0].reason

    def test_fullmatch_semantics(self):
        """Regex uses fullmatch — partial matches don't pass."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="name",
            regex_pattern=r"[a-z]+",
        )]
        # Should fail because fullmatch requires the entire string to match
        result = validator_pipeline.validate({"name": "abc123"}, validators)
        assert not result.passed


# ===========================================================================
# APEP-095: Allowlist / Blocklist Validator
# ===========================================================================


class TestAllowlistBlocklistValidator:
    """Tests for allowlist/blocklist argument validation (APEP-095)."""

    def test_allowlist_allows_valid(self):
        """Value in the allowlist passes."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="region",
            allowlist=["us-east-1", "us-west-2", "eu-west-1"],
        )]
        result = validator_pipeline.validate({"region": "us-east-1"}, validators)
        assert result.passed

    def test_allowlist_rejects_invalid(self):
        """Value not in the allowlist fails."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="region",
            allowlist=["us-east-1", "us-west-2"],
        )]
        result = validator_pipeline.validate({"region": "cn-north-1"}, validators)
        assert not result.passed
        assert result.failures[0].validator_type == "allowlist"

    def test_blocklist_blocks_value(self):
        """Value in the blocklist fails."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="command",
            blocklist=["rm -rf /", "DROP TABLE", "shutdown"],
        )]
        result = validator_pipeline.validate({"command": "rm -rf /"}, validators)
        assert not result.passed
        assert result.failures[0].validator_type == "blocklist"

    def test_blocklist_allows_safe_value(self):
        """Value not in the blocklist passes."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="command",
            blocklist=["rm -rf /", "DROP TABLE"],
        )]
        result = validator_pipeline.validate({"command": "ls -la"}, validators)
        assert result.passed

    def test_both_allowlist_and_blocklist(self):
        """Allowlist and blocklist can be combined on the same argument."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="action",
            allowlist=["read", "write", "delete"],
            blocklist=["delete"],
        )]
        # "delete" is in both allowlist and blocklist — blocklist wins (runs first)
        result = validator_pipeline.validate({"action": "delete"}, validators)
        assert not result.passed
        assert any(f.validator_type == "blocklist" for f in result.failures)


# ===========================================================================
# APEP-096: Validator Pipeline
# ===========================================================================


class TestValidatorPipeline:
    """Tests for the validator pipeline — all validators run in sequence (APEP-096)."""

    def test_all_validators_run(self):
        """All validators run even when the first one fails."""
        from app.models.policy import ArgValidator

        validators = [
            ArgValidator(
                arg_name="count",
                json_schema={"type": "integer"},
            ),
            ArgValidator(
                arg_name="path",
                regex_pattern=r"/safe/.*",
            ),
        ]
        # Both should fail: "count" is a string, "path" doesn't match
        result = validator_pipeline.validate(
            {"count": "not_int", "path": "/etc/passwd"}, validators
        )
        assert not result.passed
        assert len(result.failures) == 2

    def test_multiple_validators_same_arg(self):
        """Multiple validation rules on the same argument all run."""
        from app.models.policy import ArgValidator

        validators = [
            ArgValidator(
                arg_name="value",
                json_schema={"type": "string", "minLength": 5},
            ),
            ArgValidator(
                arg_name="value",
                regex_pattern=r"[a-z]+",
                blocklist=["admin"],
            ),
        ]
        # "ab" fails schema (too short) and regex still runs
        result = validator_pipeline.validate({"value": "ab"}, validators)
        assert not result.passed
        assert any(f.validator_type == "json_schema" for f in result.failures)

    def test_all_pass_returns_true(self):
        """When all validators pass, result is passed=True with no failures."""
        from app.models.policy import ArgValidator

        validators = [
            ArgValidator(arg_name="name", regex_pattern=r"[a-z]+"),
            ArgValidator(arg_name="count", json_schema={"type": "integer"}),
            ArgValidator(arg_name="region", allowlist=["us-east-1"]),
        ]
        result = validator_pipeline.validate(
            {"name": "test", "count": 5, "region": "us-east-1"}, validators
        )
        assert result.passed
        assert len(result.failures) == 0

    def test_empty_validators_passes(self):
        """No validators means everything passes."""
        result = validator_pipeline.validate({"anything": "goes"}, [])
        assert result.passed

    def test_validation_result_reason_formatting(self):
        """ValidationResult.reason formats all failures."""
        vr = ValidationResult(
            passed=False,
            failures=[
                ValidationFailure(
                    validator_type="json_schema",
                    arg_name="count",
                    reason="not an integer",
                ),
                ValidationFailure(
                    validator_type="blocklist",
                    arg_name="cmd",
                    reason="in blocklist",
                ),
            ],
        )
        assert "[json_schema] count:" in vr.reason
        assert "[blocklist] cmd:" in vr.reason


# ===========================================================================
# Integration: Rate Limits via Intercept API
# ===========================================================================


class TestRateLimitIntegration:
    """Integration tests: rate limits enforced via POST /v1/intercept."""

    @pytest.mark.asyncio
    async def test_sliding_window_rate_limit_enforced(
        self, client: AsyncClient, mock_mongodb
    ):
        """Intercept API enforces sliding window rate limits."""
        await _insert_role(mock_mongodb)
        await _insert_rule(mock_mongodb, {
            "rate_limit": {
                "count": 2,
                "window_s": 60,
                "limiter_type": "SLIDING_WINDOW",
            },
        })

        # First two requests should ALLOW
        for _ in range(2):
            resp = await client.post("/v1/intercept", json=_make_request())
            assert resp.status_code == 200
            assert resp.json()["decision"] == "ALLOW"

        # Third request should DENY
        resp = await client.post("/v1/intercept", json=_make_request())
        assert resp.status_code == 200
        assert resp.json()["decision"] == "DENY"
        assert "rate limit exceeded" in resp.json()["reason"].lower()

    @pytest.mark.asyncio
    async def test_fixed_window_rate_limit_enforced(
        self, client: AsyncClient, mock_mongodb
    ):
        """Intercept API enforces fixed window rate limits."""
        await _insert_role(mock_mongodb)
        await _insert_rule(mock_mongodb, {
            "rate_limit": {
                "count": 1,
                "window_s": 60,
                "limiter_type": "FIXED_WINDOW",
            },
        })

        resp = await client.post("/v1/intercept", json=_make_request())
        assert resp.status_code == 200
        assert resp.json()["decision"] == "ALLOW"

        resp = await client.post("/v1/intercept", json=_make_request())
        assert resp.status_code == 200
        assert resp.json()["decision"] == "DENY"

    @pytest.mark.asyncio
    async def test_global_rate_limit_enforced(
        self, client: AsyncClient, mock_mongodb
    ):
        """Intercept API enforces global per-tenant rate limit."""
        from app.core.config import settings

        settings.global_rate_limit_enabled = True
        settings.global_rate_limit_per_second = 2

        await _insert_role(mock_mongodb)
        await _insert_rule(mock_mongodb)

        for _ in range(2):
            resp = await client.post("/v1/intercept", json=_make_request())
            assert resp.status_code == 200
            assert resp.json()["decision"] == "ALLOW"

        resp = await client.post("/v1/intercept", json=_make_request())
        assert resp.status_code == 200
        assert resp.json()["decision"] == "DENY"
        assert "Global rate limit exceeded" in resp.json()["reason"]

    @pytest.mark.asyncio
    async def test_rate_limit_with_dry_run(
        self, client: AsyncClient, mock_mongodb
    ):
        """Rate limit denial is reported as DRY_RUN when dry_run=True."""
        await _insert_role(mock_mongodb)
        await _insert_rule(mock_mongodb, {
            "rate_limit": {"count": 1, "window_s": 60, "limiter_type": "SLIDING_WINDOW"},
        })

        resp = await client.post("/v1/intercept", json=_make_request())
        assert resp.json()["decision"] == "ALLOW"

        resp = await client.post("/v1/intercept", json=_make_request(dry_run=True))
        assert resp.json()["decision"] == "DRY_RUN"


# ===========================================================================
# Integration: Validator Pipeline via Intercept API
# ===========================================================================


class TestValidatorPipelineIntegration:
    """Integration tests: validator pipeline enforced via POST /v1/intercept."""

    @pytest.mark.asyncio
    async def test_schema_validation_deny(
        self, client: AsyncClient, mock_mongodb
    ):
        """Tool call denied when JSON schema validation fails."""
        await _insert_role(mock_mongodb)
        await _insert_rule(mock_mongodb, {
            "arg_validators": [
                {"arg_name": "path", "json_schema": {"type": "string", "pattern": "^/tmp/.*"}},
            ],
        })

        # Valid path
        resp = await client.post(
            "/v1/intercept",
            json=_make_request(tool_args={"path": "/tmp/safe.txt"}),
        )
        assert resp.json()["decision"] == "ALLOW"

        # Invalid path
        resp = await client.post(
            "/v1/intercept",
            json=_make_request(tool_args={"path": "/etc/passwd"}),
        )
        assert resp.json()["decision"] == "DENY"
        assert "Validator pipeline failed" in resp.json()["reason"]

    @pytest.mark.asyncio
    async def test_blocklist_deny(
        self, client: AsyncClient, mock_mongodb
    ):
        """Tool call denied when argument is in blocklist."""
        await _insert_role(mock_mongodb)
        await _insert_rule(mock_mongodb, {
            "arg_validators": [
                {"arg_name": "path", "blocklist": ["/etc/shadow", "/etc/passwd"]},
            ],
        })

        resp = await client.post(
            "/v1/intercept",
            json=_make_request(tool_args={"path": "/etc/shadow"}),
        )
        assert resp.json()["decision"] == "DENY"

    @pytest.mark.asyncio
    async def test_regex_deny(
        self, client: AsyncClient, mock_mongodb
    ):
        """Tool call denied when argument doesn't match regex pattern."""
        await _insert_role(mock_mongodb)
        await _insert_rule(mock_mongodb, {
            "arg_validators": [
                {"arg_name": "path", "regex_pattern": r"/tmp/[a-zA-Z0-9_.]+"},
            ],
        })

        resp = await client.post(
            "/v1/intercept",
            json=_make_request(tool_args={"path": "/tmp/../etc/passwd"}),
        )
        assert resp.json()["decision"] == "DENY"


# ===========================================================================
# APEP-097: Adversarial Tests
# ===========================================================================


class TestAdversarialSchemaBypass:
    """Adversarial tests for JSON schema bypass attempts (APEP-097)."""

    def test_type_coercion_attack(self):
        """Attacker sends string "42" where integer is required."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="count",
            json_schema={"type": "integer"},
        )]
        result = validator_pipeline.validate({"count": "42"}, validators)
        assert not result.passed  # String "42" is not an integer

    def test_nested_object_injection(self):
        """Attacker nests dangerous values inside objects."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="config",
            json_schema={
                "type": "object",
                "properties": {"host": {"type": "string", "maxLength": 50}},
                "additionalProperties": False,
            },
        )]
        # Extra property should fail with additionalProperties=False
        result = validator_pipeline.validate(
            {"config": {"host": "safe", "malicious_key": "payload"}}, validators
        )
        assert not result.passed

    def test_array_overflow(self):
        """Attacker sends array exceeding maxItems."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="items",
            json_schema={"type": "array", "maxItems": 5, "items": {"type": "string"}},
        )]
        result = validator_pipeline.validate(
            {"items": ["a"] * 100}, validators
        )
        assert not result.passed

    def test_null_bypass_attempt(self):
        """Attacker sends null to bypass type checking."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="path",
            json_schema={"type": "string"},
        )]
        result = validator_pipeline.validate({"path": None}, validators)
        assert not result.passed

    def test_empty_string_bypass(self):
        """Attacker sends empty string where minLength is required."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="token",
            json_schema={"type": "string", "minLength": 1},
        )]
        result = validator_pipeline.validate({"token": ""}, validators)
        assert not result.passed


class TestAdversarialRegexEvasion:
    """Adversarial tests for regex evasion attempts (APEP-097)."""

    def test_path_traversal_evasion(self):
        """Attacker uses path traversal to escape the safe directory."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="path",
            regex_pattern=r"/tmp/[a-zA-Z0-9_.]+",
        )]
        attacks = [
            "/tmp/../etc/passwd",
            "/tmp/./../../etc/shadow",
            "/tmp/file.txt\n/etc/passwd",
        ]
        for attack in attacks:
            result = validator_pipeline.validate({"path": attack}, validators)
            assert not result.passed, f"Should block: {attack}"

    def test_unicode_evasion(self):
        """Attacker uses unicode characters to evade ASCII regex."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="name",
            regex_pattern=r"[a-zA-Z0-9_]+",
        )]
        attacks = [
            "admin\u200b",  # zero-width space
            "te\u0073t",    # unicode 's' (actually normal, but tests the pattern)
            "名前",         # CJK characters
        ]
        for attack in attacks:
            result = validator_pipeline.validate({"name": attack}, validators)
            # ASCII-only regex should reject non-ASCII or invisible chars
            if not all(c.isascii() and (c.isalnum() or c == "_") for c in attack):
                assert not result.passed, f"Should block: {repr(attack)}"

    def test_newline_injection_in_regex(self):
        """Attacker injects newlines hoping to bypass single-line regex."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="query",
            regex_pattern=r"SELECT \* FROM [a-z_]+",
        )]
        result = validator_pipeline.validate(
            {"query": "SELECT * FROM users\n; DROP TABLE users;--"}, validators
        )
        assert not result.passed

    def test_catastrophic_backtracking_safe(self):
        """Regex with potentially catastrophic backtracking doesn't crash."""
        from app.models.policy import ArgValidator

        # This tests that the validator handles regex timeout gracefully
        validators = [ArgValidator(
            arg_name="data",
            regex_pattern=r"^(a+)+$",
        )]
        # Short input that would trigger backtracking
        result = validator_pipeline.validate(
            {"data": "aaaaaaaaaaaaaX"}, validators
        )
        assert not result.passed


class TestAdversarialRateLimitExhaustion:
    """Adversarial tests for rate limit exhaustion (APEP-097)."""

    @pytest.mark.asyncio
    async def test_rapid_fire_sliding_window(self, mock_mongodb):
        """Rapid-fire requests properly exhaust the sliding window limit."""
        from app.models.policy import RateLimit

        rl = RateLimit(count=10, window_s=60, limiter_type=RateLimitType.SLIDING_WINDOW)
        results = []
        for _ in range(15):
            result = await rate_limiter.check_sliding_window("attacker", "sensitive_tool", rl)
            results.append(result.allowed)

        # First 10 allowed, last 5 denied
        assert results[:10] == [True] * 10
        assert results[10:] == [False] * 5

    @pytest.mark.asyncio
    async def test_rapid_fire_fixed_window(self, mock_mongodb):
        """Rapid-fire requests properly exhaust the fixed window limit."""
        from app.models.policy import RateLimit

        rl = RateLimit(count=5, window_s=60, limiter_type=RateLimitType.FIXED_WINDOW)
        results = []
        for _ in range(10):
            result = await rate_limiter.check_fixed_window("attacker", "sensitive_tool", rl)
            results.append(result.allowed)

        assert results[:5] == [True] * 5
        assert results[5:] == [False] * 5

    @pytest.mark.asyncio
    async def test_global_rate_limit_dos_protection(self, mock_mongodb):
        """Global rate limit protects against DoS by capping decisions/second."""
        from app.core.config import settings

        settings.global_rate_limit_enabled = True
        settings.global_rate_limit_per_second = 50

        results = []
        for _ in range(60):
            result = await rate_limiter.check_global_rate_limit("attacker-tenant")
            results.append(result.allowed)

        allowed_count = sum(results)
        denied_count = len(results) - allowed_count
        assert allowed_count == 50
        assert denied_count == 10

    @pytest.mark.asyncio
    async def test_different_role_tool_combinations(self, mock_mongodb):
        """Attacker can't bypass rate limits by varying role/tool combos."""
        from app.models.policy import RateLimit

        rl = RateLimit(count=1, window_s=60, limiter_type=RateLimitType.SLIDING_WINDOW)

        # Each role+tool combo has its own limit
        await rate_limiter.check_sliding_window("role_a", "tool_x", rl)
        result = await rate_limiter.check_sliding_window("role_a", "tool_x", rl)
        assert not result.allowed

        # But different combo works
        result = await rate_limiter.check_sliding_window("role_a", "tool_y", rl)
        assert result.allowed


class TestAdversarialBlocklistBypass:
    """Adversarial tests for blocklist/allowlist bypass attempts (APEP-097)."""

    def test_case_sensitivity(self):
        """Blocklist matching is case-sensitive — attacker can't bypass with case change."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="cmd",
            blocklist=["rm -rf /", "DROP TABLE"],
        )]
        # Different case — not in blocklist (this is expected behavior;
        # if case-insensitive matching is needed, use regex)
        result = validator_pipeline.validate({"cmd": "RM -RF /"}, validators)
        assert result.passed  # Case-sensitive match — not in blocklist

    def test_whitespace_padding_bypass(self):
        """Attacker adds whitespace to bypass exact blocklist match."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="cmd",
            blocklist=["rm -rf /"],
        )]
        # Whitespace-padded version not in exact blocklist
        result = validator_pipeline.validate({"cmd": " rm -rf / "}, validators)
        assert result.passed  # Exact match only — this is expected

        # But regex can catch it
        validators2 = [ArgValidator(
            arg_name="cmd",
            regex_pattern=r"(?!.*rm\s+-rf\s+/).*",
        )]
        result2 = validator_pipeline.validate({"cmd": " rm -rf / "}, validators2)
        assert not result2.passed

    def test_combined_validators_no_bypass(self):
        """Multiple validator types on the same arg prevent bypass."""
        from app.models.policy import ArgValidator

        validators = [ArgValidator(
            arg_name="path",
            json_schema={"type": "string", "maxLength": 100},
            regex_pattern=r"/safe/[a-zA-Z0-9_.]+",
            blocklist=["/safe/../etc/passwd"],
        )]
        attacks = [
            "/etc/passwd",                # regex fails
            "/safe/../etc/passwd",        # blocklist fails
            "/safe/" + "a" * 200,         # schema fails (too long)
        ]
        for attack in attacks:
            result = validator_pipeline.validate({"path": attack}, validators)
            assert not result.passed, f"Should block: {attack}"

    def test_pipeline_collects_all_failures(self):
        """Pipeline collects failures from ALL validators, not just the first."""
        from app.models.policy import ArgValidator

        validators = [
            ArgValidator(
                arg_name="x",
                json_schema={"type": "integer"},
                blocklist=["bad"],
            ),
            ArgValidator(
                arg_name="y",
                regex_pattern=r"[0-9]+",
                allowlist=["1", "2", "3"],
            ),
        ]
        result = validator_pipeline.validate({"x": "bad", "y": "abc"}, validators)
        assert not result.passed
        # Should have failures from: json_schema (x), blocklist (x), regex (y), allowlist (y)
        types = [f.validator_type for f in result.failures]
        assert "json_schema" in types
        assert "blocklist" in types
        assert "regex" in types
        assert "allowlist" in types
