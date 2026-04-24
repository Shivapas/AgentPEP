"""Integration tests — PreToolUse interceptor → PDP → ALLOW/DENY round trip.

Validates the full evaluation path:
  request_builder → PDPClient → OPAEngine (native stub) → response_parser
  → EnforcementLog

Tests use the RegoNativeEvaluator (no OPA binary required) which implements
the stub bundle rules from scripts/mock_aapm_registry.py.

Sprint S-E04 (E04-T06, E04-T07)
"""

from __future__ import annotations

import asyncio

import pytest

from app.pdp.client import PDPClient, PDPClientResult
from app.pdp.engine import OPAEngine, RegoNativeEvaluator
from app.pdp.enforcement_log import EnforcementLog
from app.pdp.request_builder import AuthorizationRequestBuilder
from app.pdp.response_parser import PDPDecision, ReasonCode, response_parser

# ---------------------------------------------------------------------------
# Stub bundle — matches scripts/mock_aapm_registry.py REGO_POLICY
# ---------------------------------------------------------------------------

_STUB_REGO = b"""\
package agentpep.core

import rego.v1

default allow := false

allow if {
    input.tool_name in {"read_file", "list_dir", "search_code"}
    input.deployment_tier == "HOMEGROWN"
}
"""

_STUB_MODULES: dict[str, bytes] = {"policies/core.rego": _STUB_REGO}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def native_engine() -> OPAEngine:
    """OPA engine using the native stub evaluator (no OPA binary needed)."""
    return OPAEngine(evaluator=RegoNativeEvaluator())


@pytest.fixture
def log() -> EnforcementLog:
    log = EnforcementLog(max_entries=200)
    return log


@pytest.fixture
def client(native_engine: OPAEngine, log: EnforcementLog) -> PDPClient:
    """PDPClient wired to the native engine and a fresh log."""
    c = PDPClient(engine=native_engine, timeout_s=5.0, rego_modules=_STUB_MODULES)
    # Patch the enforcement_log singleton used internally
    import app.pdp.client as _client_mod
    original = _client_mod.enforcement_log
    _client_mod.enforcement_log = log
    yield c
    _client_mod.enforcement_log = original


@pytest.fixture
def builder() -> AuthorizationRequestBuilder:
    return AuthorizationRequestBuilder()


# ---------------------------------------------------------------------------
# Round-trip: ALLOW path
# ---------------------------------------------------------------------------


class TestAllowPath:
    @pytest.mark.asyncio
    async def test_read_file_homegrown_is_allowed(self, client: PDPClient, log: EnforcementLog):
        result = await client.decide(
            tool_name="read_file",
            tool_args={"path": "/tmp/test.txt"},
            agent_id="agent-001",
            session_id="sess-001",
            deployment_tier="HOMEGROWN",
        )

        assert result.is_allow, f"Expected ALLOW, got {result.response.reason_code}"
        assert result.response.decision == PDPDecision.ALLOW
        assert result.response.reason_code in (ReasonCode.TOOL_ALLOWED, ReasonCode.POLICY_EVALUATED)

    @pytest.mark.asyncio
    async def test_list_dir_homegrown_is_allowed(self, client: PDPClient):
        result = await client.decide(
            tool_name="list_dir",
            tool_args={"path": "/tmp"},
            deployment_tier="HOMEGROWN",
        )
        assert result.is_allow

    @pytest.mark.asyncio
    async def test_search_code_homegrown_is_allowed(self, client: PDPClient):
        result = await client.decide(
            tool_name="search_code",
            tool_args={"query": "TODO"},
            deployment_tier="HOMEGROWN",
        )
        assert result.is_allow

    @pytest.mark.asyncio
    async def test_allow_decision_is_logged(self, client: PDPClient, log: EnforcementLog):
        log.clear()
        await client.decide(
            tool_name="read_file",
            tool_args={"path": "/tmp/x"},
            agent_id="agent-log-test",
            session_id="sess-log-test",
            deployment_tier="HOMEGROWN",
        )
        entries = log.recent(limit=1)
        assert entries, "Expected at least one log entry"
        entry = entries[0]
        assert entry.decision == "ALLOW"
        assert entry.agent_id == "agent-log-test"
        assert entry.session_id == "sess-log-test"
        assert entry.bundle_version != ""  # version string is present

    @pytest.mark.asyncio
    async def test_allow_log_entry_contains_latency(self, client: PDPClient, log: EnforcementLog):
        log.clear()
        await client.decide(
            tool_name="read_file",
            tool_args={"path": "/tmp/x"},
            deployment_tier="HOMEGROWN",
        )
        entry = log.recent(limit=1)[0]
        assert entry.latency_ms >= 0.0


# ---------------------------------------------------------------------------
# Round-trip: DENY path
# ---------------------------------------------------------------------------


class TestDenyPath:
    @pytest.mark.asyncio
    async def test_bash_is_denied(self, client: PDPClient):
        result = await client.decide(
            tool_name="bash",
            tool_args={"command": "ls /"},
            deployment_tier="HOMEGROWN",
        )
        assert result.is_deny
        assert result.response.decision == PDPDecision.DENY

    @pytest.mark.asyncio
    async def test_write_file_is_denied(self, client: PDPClient):
        result = await client.decide(
            tool_name="write_file",
            tool_args={"path": "/etc/passwd", "content": "hacked"},
            deployment_tier="HOMEGROWN",
        )
        assert result.is_deny

    @pytest.mark.asyncio
    async def test_read_file_enterprise_tier_is_denied(self, client: PDPClient):
        """Stub bundle only allows HOMEGROWN; other tiers → DENY."""
        result = await client.decide(
            tool_name="read_file",
            tool_args={"path": "/tmp/x"},
            deployment_tier="ENTERPRISE",
        )
        assert result.is_deny

    @pytest.mark.asyncio
    async def test_tainted_input_is_denied(self, client: PDPClient):
        result = await client.decide(
            tool_name="read_file",
            tool_args={"path": "/tmp/x"},
            deployment_tier="HOMEGROWN",
            taint_level="TAINTED",
        )
        assert result.is_deny
        assert result.response.reason_code == ReasonCode.TAINTED_INPUT

    @pytest.mark.asyncio
    async def test_deny_decision_is_logged(self, client: PDPClient, log: EnforcementLog):
        log.clear()
        await client.decide(
            tool_name="bash",
            tool_args={"command": "id"},
            agent_id="agent-deny-test",
        )
        entries = log.recent(limit=1)
        assert entries
        entry = entries[0]
        assert entry.decision == "DENY"
        assert entry.agent_id == "agent-deny-test"


# ---------------------------------------------------------------------------
# Round-trip: complexity gate fires before OPA
# ---------------------------------------------------------------------------


class TestComplexityGate:
    @pytest.mark.asyncio
    async def test_oversized_args_denied_before_opa(
        self, native_engine: OPAEngine, log: EnforcementLog, monkeypatch
    ):
        """A request exceeding max_arg_bytes must be DENY + gated_by_complexity=True."""
        import app.pdp.client as _client_mod

        # Patch the enforcement_log used by the client module
        monkeypatch.setattr(_client_mod, "enforcement_log", log)

        # Inject a tight checker directly in app.pdp.client's namespace
        from app.enforcement.complexity_budget import ComplexityBudgetChecker

        tight_checker = ComplexityBudgetChecker(
            max_arg_bytes=10,        # very tight — "/tmp/very-long-path" exceeds this
            max_subcommand_count=100,
            max_nesting_depth=100,
        )
        monkeypatch.setattr(_client_mod, "complexity_checker", tight_checker)
        log.clear()

        from app.pdp.client import PDPClient as _PDPClient

        c = _PDPClient(engine=native_engine, timeout_s=5.0, rego_modules=_STUB_MODULES)
        result = await c.decide(
            tool_name="read_file",
            tool_args={"path": "/tmp/very-long-path-here-exceeds-10-bytes"},
            deployment_tier="HOMEGROWN",
        )

        assert result.is_deny
        entries = log.recent(limit=1)
        assert entries
        assert entries[0].gated_by_complexity is True


# ---------------------------------------------------------------------------
# Enforcement log counters
# ---------------------------------------------------------------------------


class TestEnforcementLogCounters:
    @pytest.mark.asyncio
    async def test_counters_increment_correctly(
        self, client: PDPClient, log: EnforcementLog
    ):
        log.clear()

        await client.decide(
            tool_name="read_file", tool_args={"path": "/x"}, deployment_tier="HOMEGROWN"
        )
        await client.decide(
            tool_name="read_file", tool_args={"path": "/x"}, deployment_tier="HOMEGROWN"
        )
        await client.decide(
            tool_name="bash", tool_args={"cmd": "id"}, deployment_tier="HOMEGROWN"
        )

        counts = log.counts()
        assert counts["ALLOW"] == 2
        assert counts["DENY"] == 1


# ---------------------------------------------------------------------------
# Request builder
# ---------------------------------------------------------------------------


class TestRequestBuilder:
    def test_build_defaults_applied(self, builder: AuthorizationRequestBuilder):
        req = builder.build(tool_name="read_file", tool_args={})
        assert req.taint_level == "CLEAN"
        assert req.trust_score == 1.0
        assert req.deployment_tier == "HOMEGROWN"
        assert req.blast_radius_score == 0.0
        assert req.request_id != ""

    def test_blast_radius_clamped(self, builder: AuthorizationRequestBuilder):
        req = builder.build(tool_name="bash", tool_args={}, blast_radius_score=99.9)
        assert req.blast_radius_score == 1.0

    def test_trust_score_clamped(self, builder: AuthorizationRequestBuilder):
        req = builder.build(tool_name="bash", tool_args={}, trust_score=-5.0)
        assert req.trust_score == 0.0

    def test_unknown_taint_normalised(self, builder: AuthorizationRequestBuilder):
        req = builder.build(tool_name="read_file", tool_args={}, taint_level="PURPLE")
        assert req.taint_level == "CLEAN"

    def test_unknown_tier_normalised(self, builder: AuthorizationRequestBuilder):
        req = builder.build(tool_name="read_file", tool_args={}, deployment_tier="MOON")
        assert req.deployment_tier == "HOMEGROWN"

    def test_to_opa_input_is_complete(self, builder: AuthorizationRequestBuilder):
        req = builder.build(
            tool_name="read_file",
            tool_args={"path": "/tmp"},
            agent_id="a1",
            session_id="s1",
        )
        doc = req.to_opa_input()
        required_fields = {
            "agent_id", "session_id", "request_id", "tool_name", "tool_args",
            "taint_level", "trust_score", "principal_chain", "deployment_tier",
            "blast_radius_score", "bundle_version", "timestamp_ms",
        }
        assert required_fields == set(doc.keys()), (
            f"OPA input document missing fields: {required_fields - set(doc.keys())}"
        )

    def test_from_intercept_payload(self, builder: AuthorizationRequestBuilder):
        payload = {
            "tool_name": "write_file",
            "tool_args": {"path": "/etc/hosts"},
            "agent_id": "agent-42",
            "session_id": "session-99",
            "taint_level": "TAINTED",
        }
        req = builder.from_intercept_payload(payload)
        assert req.tool_name == "write_file"
        assert req.agent_id == "agent-42"
        assert req.taint_level == "TAINTED"


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------


class TestResponseParser:
    def test_parse_allow_result(self):
        raw = {"allow": True, "deny": False, "reason_code": "TOOL_ALLOWED", "evaluator": "native_stub"}
        resp = response_parser.parse(raw)
        assert resp.is_allow
        assert resp.reason_code == ReasonCode.TOOL_ALLOWED

    def test_parse_deny_result(self):
        raw = {"allow": False, "deny": True, "reason_code": "TOOL_NOT_PERMITTED", "evaluator": "native_stub"}
        resp = response_parser.parse(raw)
        assert resp.is_deny
        assert resp.reason_code == ReasonCode.TOOL_NOT_PERMITTED

    def test_parse_none_returns_deny(self):
        resp = response_parser.parse_or_deny(None)
        assert resp.is_deny

    def test_parse_ambiguous_both_true_is_deny(self):
        raw = {"allow": True, "deny": True, "reason_code": "TOOL_ALLOWED"}
        resp = response_parser.parse(raw)
        assert resp.is_deny

    def test_parse_unknown_reason_code_normalised(self):
        raw = {"allow": True, "deny": False, "reason_code": "SOME_FUTURE_CODE"}
        resp = response_parser.parse(raw)
        assert resp.is_allow
        assert resp.reason_code == ReasonCode.UNKNOWN

    def test_parse_non_dict_input_is_deny(self):
        resp = response_parser.parse(None)  # type: ignore[arg-type]
        assert resp.is_deny
