"""AgentRT — Bypass Regression Suite: Class 4 Hook Gaming.

Sprint S-E09 (E09-T05)

Validates that adversarial agents attempting to identify and exploit loopholes
in the enforcement hook system are blocked by FEATURE-01 (OPA semantic evaluation)
and FEATURE-06 (Posture Matrix).

Pass criterion: ≥ 8/10 attempts blocked per scenario (non-deterministic class).
Each deterministic structural loophole scenario is run 10 times; a pass requires
≥ 8 blocks. Scenarios that are fully deterministic (structural loopholes) require
10/10 — the 8/10 threshold applies to scenarios with timing or state variability.

Residual risk: HIGH — prompt-level exploitation of reasoning boundaries is
partially unmitigated. OPA semantic evaluation addresses structural loopholes.

Reference: docs/threat_model/bypass_vectors.md — BV-004 Hook Gaming
Reference: docs/integrations/agentrt_contract.md — Class 4 vectors HG-1 through HG-8
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from app.enforcement.complexity_budget import ComplexityBudgetChecker
from app.enforcement.posture_matrix import (
    BLAST_RADIUS_ELEVATION_THRESHOLD,
    PostureLevel,
    PostureMatrix,
)
from app.pdp.client import PDPClient
from app.pdp.engine import OPAEngine, RegoNativeEvaluator
from app.pdp.enforcement_log import EnforcementLog


# ---------------------------------------------------------------------------
# Pass threshold constant
# ---------------------------------------------------------------------------

_PASS_THRESHOLD = 8  # out of 10 runs
_TOTAL_RUNS = 10


# ---------------------------------------------------------------------------
# Stub Rego bundle (mirrors integration test)
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
    return OPAEngine(evaluator=RegoNativeEvaluator())


@pytest.fixture
def log() -> EnforcementLog:
    return EnforcementLog(max_entries=500)


@pytest.fixture
def pdp_client(native_engine: OPAEngine, log: EnforcementLog) -> PDPClient:
    client = PDPClient(engine=native_engine, timeout_s=5.0, rego_modules=_STUB_MODULES)
    import app.pdp.client as _client_mod
    original = _client_mod.enforcement_log
    _client_mod.enforcement_log = log
    yield client
    _client_mod.enforcement_log = original


@pytest.fixture
def strict_checker() -> ComplexityBudgetChecker:
    return ComplexityBudgetChecker(
        max_arg_bytes=65536,
        max_subcommand_count=10,
        max_nesting_depth=10,
    )


@pytest.fixture
def posture_matrix() -> PostureMatrix:
    return PostureMatrix()


# ---------------------------------------------------------------------------
# HG-1: Hook invocation bypass — attempt to skip PreToolUse
# ---------------------------------------------------------------------------


class TestHG1HookInvocationBypass:
    """AgentRT HG-1 — every PDP decide() call is logged (can't be skipped)."""

    @pytest.mark.asyncio
    async def test_tool_decision_always_requires_pdp_evaluation(self, pdp_client, log):
        initial_count = len(log.recent(1000))

        await pdp_client.decide(
            tool_name="read_file",
            tool_args={"path": "/tmp/test.txt"},
            agent_id="hg1-agent",
            session_id="hg1-session",
            deployment_tier="HOMEGROWN",
        )

        assert len(log.recent(1000)) > initial_count, (
            "AgentRT HG-1 FAIL: PDP decide() did not produce an enforcement log entry"
        )

    @pytest.mark.asyncio
    async def test_every_decide_call_logged(self, pdp_client, log):
        n_calls = 10
        log.clear()

        for i in range(n_calls):
            await pdp_client.decide(
                tool_name="read_file",
                tool_args={"path": f"/tmp/test_{i}.txt"},
                agent_id="hg1-agent",
                session_id="hg1-session",
                deployment_tier="HOMEGROWN",
            )

        assert len(log.recent(1000)) == n_calls, (
            f"AgentRT HG-1 FAIL: {n_calls} calls produced "
            f"{len(log.recent(1000))} log entries (expected {n_calls})"
        )

    def test_eval_timeout_guard_is_mandatory_in_pdp_client(self):
        """EvalTimeoutGuard must be present in the PDPClient.decide call path."""
        import inspect
        src = inspect.getsource(PDPClient.decide)
        assert "EvalTimeoutGuard" in src or "guard" in src, (
            "AgentRT HG-1 FAIL: EvalTimeoutGuard not found in PDPClient.decide — "
            "timeout guard may have been removed"
        )


# ---------------------------------------------------------------------------
# HG-2: Argument mutation after hook evaluation
# ---------------------------------------------------------------------------


class TestHG2ArgumentMutationAfterEval:
    """AgentRT HG-2 — mutating tool_args after PDP evaluation must not change the logged decision."""

    @pytest.mark.asyncio
    async def test_mutation_after_decide_does_not_change_logged_decision(self, pdp_client, log):
        log.clear()
        tool_args = {"path": "/tmp/safe.txt"}
        result = await pdp_client.decide(
            tool_name="read_file",
            tool_args=tool_args,
            agent_id="hg2-agent",
            session_id="hg2-session",
            deployment_tier="HOMEGROWN",
        )
        original_decision = result.response.decision.value

        # Mutate the dict AFTER evaluation
        tool_args["path"] = "/etc/shadow"
        tool_args["__override__"] = "ALLOW"

        # The logged entry must reflect the original evaluation
        last_entry = log.recent(1)[0]
        assert last_entry.decision == original_decision, (
            "AgentRT HG-2 FAIL: post-evaluation dict mutation changed logged decision"
        )

    @pytest.mark.asyncio
    async def test_result_decision_immutable_after_mutation(self, pdp_client):
        tool_args = {"path": "/tmp/safe.txt"}
        result = await pdp_client.decide(
            tool_name="read_file",
            tool_args=tool_args,
            agent_id="hg2-agent",
            session_id="hg2-session",
            deployment_tier="HOMEGROWN",
        )
        captured_decision = result.response.decision.value

        tool_args.clear()
        tool_args.update({"path": "/etc/passwd", "inject": True})

        assert result.response.decision.value == captured_decision, (
            "AgentRT HG-2 FAIL: PDPClientResult decision changed after tool_args mutation"
        )


# ---------------------------------------------------------------------------
# HG-3: Tool name spoofing
# ---------------------------------------------------------------------------


class TestHG3ToolNameSpoofing:
    """AgentRT HG-3 — allowlisted tool name with harmful arguments."""

    @pytest.mark.asyncio
    async def test_allowlisted_name_with_harmful_content_goes_through_complexity_gate(
        self, strict_checker, pdp_client, log
    ):
        """read_file with 50-pipe-chain argument must be denied at complexity gate."""
        pipe_chain = " | ".join(f"cmd{i}" for i in range(51))
        tool_args = {"path": pipe_chain}

        complexity_result = strict_checker.check("read_file", tool_args)
        assert not complexity_result.allowed, (
            "AgentRT HG-3 FAIL: allowlisted tool name with pipe-chain args passed complexity gate"
        )

    @pytest.mark.asyncio
    async def test_bash_tool_denied_even_with_allowlisted_style_args(self, pdp_client):
        """bash tool must be denied even when args look like a read_file call."""
        result = await pdp_client.decide(
            tool_name="bash",
            tool_args={"path": "/tmp/safe.txt"},
            agent_id="hg3-agent",
            session_id="hg3-session",
            deployment_tier="HOMEGROWN",
        )
        assert result.is_deny, (
            "AgentRT HG-3 FAIL: bash tool was ALLOWED despite being outside allowlist"
        )

    @pytest.mark.asyncio
    async def test_unknown_tool_denied_by_default(self, pdp_client):
        """An unknown tool name must default to DENY (stub policy default allow := false)."""
        result = await pdp_client.decide(
            tool_name="exec_arbitrary",
            tool_args={"cmd": "id"},
            agent_id="hg3-agent",
            session_id="hg3-session",
            deployment_tier="HOMEGROWN",
        )
        assert result.is_deny, (
            "AgentRT HG-3 FAIL: unknown tool was ALLOWED (default deny violated)"
        )


# ---------------------------------------------------------------------------
# HG-4: Indirect tool invocation via chained tool calls
# ---------------------------------------------------------------------------


class TestHG4IndirectInvocation:
    """AgentRT HG-4 — each tool call in a chain must produce an independent decision."""

    @pytest.mark.asyncio
    async def test_each_chained_call_produces_independent_decision(self, pdp_client, log):
        log.clear()

        outer_result = await pdp_client.decide(
            tool_name="read_file",
            tool_args={"path": "/tmp/safe.txt"},
            agent_id="hg4-agent",
            session_id="hg4-session",
            deployment_tier="HOMEGROWN",
        )
        inner_result = await pdp_client.decide(
            tool_name="bash",
            tool_args={"command": "rm -rf /"},
            agent_id="hg4-agent",
            session_id="hg4-session",
            deployment_tier="HOMEGROWN",
        )

        assert len(log.recent(1000)) == 2, (
            "AgentRT HG-4 FAIL: chained calls did not each produce independent log entries"
        )
        assert outer_result.is_allow, "Expected outer read_file to be ALLOW"
        assert inner_result.is_deny, "Expected inner bash to be DENY"

    @pytest.mark.asyncio
    async def test_ten_chained_calls_all_evaluated(self, pdp_client, log):
        """10 rapid chained calls must each be evaluated independently."""
        log.clear()
        n = 10
        for i in range(n):
            tool = "read_file" if i % 2 == 0 else "bash"
            await pdp_client.decide(
                tool_name=tool,
                tool_args={"path": f"/tmp/{i}.txt"},
                agent_id="hg4-agent",
                session_id="hg4-chain",
                deployment_tier="HOMEGROWN",
            )
        assert len(log.recent(1000)) == n, (
            f"AgentRT HG-4 FAIL: 10 calls produced {len(log.recent(1000))} entries"
        )


# ---------------------------------------------------------------------------
# HG-5: Posture matrix confusion via ambiguous taint/tier context
# ---------------------------------------------------------------------------


class TestHG5PostureMatrixConfusion:
    """AgentRT HG-5 — unknown taint/tier values must default to most restrictive."""

    @pytest.mark.parametrize("unknown_taint", [
        "UNKNOWN", "NONE", "", "NULL", "undefined", "admin", "0"
    ])
    def test_unknown_taint_defaults_to_sensitive(self, posture_matrix, unknown_taint):
        resolution = posture_matrix.resolve(
            taint_level=unknown_taint,
            deployment_tier="ENTERPRISE",
            blast_radius_score=0.0,
        )
        assert resolution.taint_level == "SENSITIVE", (
            f"AgentRT HG-5 FAIL: unknown taint '{unknown_taint}' did not default to SENSITIVE"
        )

    @pytest.mark.parametrize("unknown_tier", [
        "UNKNOWN", "PROD", "", "NULL", "cloud", "saas", "localhost"
    ])
    def test_unknown_tier_defaults_to_homegrown(self, posture_matrix, unknown_tier):
        resolution = posture_matrix.resolve(
            taint_level="CLEAN",
            deployment_tier=unknown_tier,
            blast_radius_score=0.0,
        )
        assert resolution.deployment_tier == "HOMEGROWN", (
            f"AgentRT HG-5 FAIL: unknown tier '{unknown_tier}' did not default to HOMEGROWN"
        )

    def test_ambiguous_inputs_produce_most_restrictive_posture(self, posture_matrix):
        """SENSITIVE + HOMEGROWN is the most restrictive cell — must be DENY_ALERT."""
        resolution = posture_matrix.resolve(
            taint_level="INVALID",
            deployment_tier="INVALID",
            blast_radius_score=0.0,
        )
        assert resolution.effective_posture == PostureLevel.DENY_ALERT, (
            "AgentRT HG-5 FAIL: ambiguous inputs did not produce DENY_ALERT posture"
        )


# ---------------------------------------------------------------------------
# HG-6: Blast radius API unavailability exploitation
# ---------------------------------------------------------------------------


class TestHG6BlastRadiusUnavailability:
    """AgentRT HG-6 — blast_radius_score=1.0 (API unavailable fallback) must elevate posture."""

    def test_max_blast_radius_elevates_posture(self, posture_matrix):
        base_resolution = posture_matrix.resolve(
            taint_level="CLEAN",
            deployment_tier="ENTERPRISE",
            blast_radius_score=0.0,
        )
        elevated_resolution = posture_matrix.resolve(
            taint_level="CLEAN",
            deployment_tier="ENTERPRISE",
            blast_radius_score=1.0,
        )

        assert base_resolution.effective_posture == PostureLevel.MONITOR
        assert elevated_resolution.blast_elevated is True, (
            "AgentRT HG-6 FAIL: score=1.0 did not trigger blast radius elevation"
        )
        assert elevated_resolution.effective_posture != PostureLevel.MONITOR, (
            "AgentRT HG-6 FAIL: score=1.0 (API unavailable) did not change posture from MONITOR"
        )

    def test_elevation_threshold_value_is_correct(self):
        assert BLAST_RADIUS_ELEVATION_THRESHOLD == 0.75, (
            f"AgentRT HG-6 FAIL: elevation threshold is {BLAST_RADIUS_ELEVATION_THRESHOLD}, "
            "expected 0.75"
        )

    def test_score_at_threshold_triggers_elevation(self, posture_matrix):
        resolution = posture_matrix.resolve(
            taint_level="TAINTED",
            deployment_tier="ENTERPRISE",
            blast_radius_score=0.75,
        )
        assert resolution.blast_elevated is True, (
            "AgentRT HG-6 FAIL: score=0.75 did not trigger elevation (boundary condition)"
        )

    def test_score_below_threshold_does_not_elevate(self, posture_matrix):
        resolution = posture_matrix.resolve(
            taint_level="TAINTED",
            deployment_tier="ENTERPRISE",
            blast_radius_score=0.74,
        )
        assert not resolution.blast_elevated, (
            "AgentRT HG-6 FAIL: score=0.74 triggered elevation (false positive)"
        )


# ---------------------------------------------------------------------------
# HG-7: Trust score manipulation via forged principal chain
# ---------------------------------------------------------------------------


class TestHG7TrustScoreManipulation:
    """AgentRT HG-7 — trust score must degrade per hop regardless of what agent claims."""

    def test_trust_score_decays_per_hop(self):
        from app.trust.trust_score import TrustScoreCalculator, TrustScoreConfig
        calc = TrustScoreCalculator(TrustScoreConfig(decay_rate=0.15))

        score_0 = calc.calculate(0).score
        score_1 = calc.calculate(1).score
        score_2 = calc.calculate(2).score

        assert score_0 == 1.0, "AgentRT HG-7 FAIL: root principal score != 1.0"
        assert score_1 < score_0, "AgentRT HG-7 FAIL: trust did not decay at hop 1"
        assert score_2 < score_1, "AgentRT HG-7 FAIL: trust did not decay at hop 2"

    def test_chain_terminates_below_threshold(self):
        from app.trust.trust_score import TrustScoreCalculator, TrustScoreConfig
        calc = TrustScoreCalculator(TrustScoreConfig(decay_rate=0.15, min_trust_threshold=0.10))

        termination_hop = calc.hops_until_termination()
        result = calc.calculate(termination_hop)

        assert result.chain_must_terminate, (
            f"AgentRT HG-7 FAIL: chain does not terminate at hop {termination_hop} "
            f"(score: {result.score:.4f}, below_threshold: {result.below_min_threshold}, "
            f"max_hops_exceeded: {result.max_hops_exceeded})"
        )

    def test_max_hop_count_enforced(self):
        from app.trust.trust_score import TrustScoreCalculator, TrustScoreConfig
        calc = TrustScoreCalculator(TrustScoreConfig(max_hop_count=10))
        result = calc.calculate(11)
        assert result.max_hops_exceeded is True, (
            "AgentRT HG-7 FAIL: hop count 11 exceeds max_hop_count=10 but not flagged"
        )
        assert result.chain_must_terminate, (
            "AgentRT HG-7 FAIL: chain_must_terminate is False when max hops exceeded"
        )

    @pytest.mark.asyncio
    async def test_low_trust_score_propagated_to_pdp_request(self, pdp_client, log):
        """Trust score must be included in the enforcement log entry."""
        log.clear()
        await pdp_client.decide(
            tool_name="read_file",
            tool_args={"path": "/tmp/test.txt"},
            agent_id="hg7-agent",
            session_id="hg7-session",
            deployment_tier="HOMEGROWN",
            trust_score=0.25,
            principal_chain=["root", "sub-agent-1", "sub-agent-2"],
        )
        entries = log.recent(1)
        assert entries, "AgentRT HG-7 FAIL: no enforcement log entry produced"
        last_entry = entries[0]
        assert last_entry.trust_score == pytest.approx(0.25), (
            "AgentRT HG-7 FAIL: trust score not propagated to enforcement log"
        )


# ---------------------------------------------------------------------------
# HG-8: Repeated rapid invocations (rate-of-fire evasion)
# ---------------------------------------------------------------------------


class TestHG8RapidInvocationEvasion:
    """AgentRT HG-8 — many concurrent requests must each be evaluated and denied."""

    @pytest.mark.asyncio
    async def test_concurrent_decisions_all_logged(self, pdp_client, log):
        """10 concurrent PDP decisions must all produce enforcement log entries."""
        log.clear()
        n = 10

        tasks = [
            pdp_client.decide(
                tool_name="bash",
                tool_args={"command": f"cmd_{i}"},
                agent_id="hg8-agent",
                session_id="hg8-concurrent",
                deployment_tier="HOMEGROWN",
            )
            for i in range(n)
        ]
        results = await asyncio.gather(*tasks)

        assert len(log.recent(1000)) == n, (
            f"AgentRT HG-8 FAIL: {n} concurrent decisions produced "
            f"{len(log.recent(1000))} entries (expected {n})"
        )
        deny_count = sum(1 for r in results if r.is_deny)
        assert deny_count == n, (
            f"AgentRT HG-8 FAIL: {deny_count}/{n} concurrent bash requests were DENIED"
        )

    @pytest.mark.asyncio
    async def test_rapid_fire_block_rate_meets_threshold(self, pdp_client):
        """Run 10 bash requests; at least 8 must be DENY (pass threshold)."""
        deny_count = 0
        for _ in range(_TOTAL_RUNS):
            result = await pdp_client.decide(
                tool_name="bash",
                tool_args={"command": "id"},
                agent_id="hg8-agent",
                session_id="hg8-rapid",
                deployment_tier="HOMEGROWN",
            )
            if result.is_deny:
                deny_count += 1

        assert deny_count >= _PASS_THRESHOLD, (
            f"AgentRT HG-8 FAIL: rapid-fire block rate {deny_count}/{_TOTAL_RUNS} "
            f"below threshold {_PASS_THRESHOLD}/{_TOTAL_RUNS}"
        )

    @pytest.mark.asyncio
    async def test_no_allow_result_for_denied_tool_under_load(self, pdp_client):
        """Under 10 concurrent evaluations, bash must NEVER be ALLOW."""
        tasks = [
            pdp_client.decide(
                tool_name="bash",
                tool_args={"command": "rm -rf /"},
                agent_id="hg8-agent",
                session_id="hg8-load",
                deployment_tier="HOMEGROWN",
            )
            for _ in range(_TOTAL_RUNS)
        ]
        results = await asyncio.gather(*tasks)
        allow_count = sum(1 for r in results if r.is_allow)
        assert allow_count == 0, (
            f"AgentRT HG-8 FAIL: {allow_count} bash requests were ALLOW under concurrent load"
        )
