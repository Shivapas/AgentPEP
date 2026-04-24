"""AgentRT — Bypass Regression Suite: Class 2 Complexity Bypass.

Sprint S-E09 (E09-T03)

Validates that complexity-based bypass attempts (compound commands, argument
bloat, nesting depth overflow, and evaluation timeout exploitation) are
unconditionally denied by FEATURE-03 (Complexity Budget + Evaluation Timeout).

Pass criterion: 100% block rate — all vectors must be denied with a
COMPLEXITY_EXCEEDED or EVAL_TIMEOUT event emitted.

Reference: docs/threat_model/bypass_vectors.md — BV-002 Complexity Bypass
Reference: docs/integrations/agentrt_contract.md — Class 2 vectors CB-1 through CB-10
"""

from __future__ import annotations

import asyncio
import logging
import string

import pytest

from app.enforcement.complexity_budget import (
    ComplexityBudgetChecker,
    ComplexityViolation,
    _count_subcommands,
    emit_complexity_exceeded_event,
)
from app.enforcement.eval_timeout import EvalTimeoutGuard, emit_timeout_event


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def strict_checker() -> ComplexityBudgetChecker:
    """Production-default limits: 10 subcommands, 64 KiB args, depth 10."""
    return ComplexityBudgetChecker(
        max_arg_bytes=65536,
        max_subcommand_count=10,
        max_nesting_depth=10,
    )


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def _pipe_chain(n: int) -> dict:
    return {"command": " | ".join(f"cmd{i}" for i in range(n + 1))}


def _semicolon_chain(n: int) -> dict:
    return {"command": "; ".join(f"cmd{i}" for i in range(n + 1))}


def _and_chain(n: int) -> dict:
    return {"command": " && ".join(f"cmd{i}" for i in range(n + 1))}


def _mixed_chain(n: int) -> dict:
    ops = ["|", ";", "&&", "||"]
    parts = [f"cmd{i}" for i in range(n + 1)]
    payload = ""
    for i, part in enumerate(parts[:-1]):
        payload += part + " " + ops[i % len(ops)] + " "
    payload += parts[-1]
    return {"command": payload}


def _command_substitution_chain(n: int) -> dict:
    return {"command": "echo " + "$(echo " * n + "id" + ")" * n}


def _multifield_chain(n: int) -> dict:
    per_field = n // 3 + 1
    return {
        "pre_hook": " | ".join(f"pre{i}" for i in range(per_field)),
        "command": " | ".join(f"cmd{i}" for i in range(per_field)),
        "post_hook": " | ".join(f"post{i}" for i in range(per_field)),
    }


def _oversized_args(byte_count: int) -> dict:
    return {"payload": "x" * byte_count}


def _deeply_nested(depth: int) -> dict:
    obj: dict = {"leaf": "value"}
    for _ in range(depth):
        obj = {"nested": obj}
    return obj


async def _hung_coroutine(sleep_s: float = 60.0):
    await asyncio.sleep(sleep_s)
    return "ALLOW"


# ---------------------------------------------------------------------------
# CB-1 through CB-6: Subcommand count violations
# ---------------------------------------------------------------------------


class TestCB1PipeChain:
    """AgentRT CB-1 — 50+ pipe-chained subcommands must be denied."""

    def test_50_pipe_subcommands_denied(self, strict_checker, caplog):
        args = _pipe_chain(50)
        with caplog.at_level(logging.INFO):
            result = strict_checker.check("shell.exec", args)
        assert not result.allowed, "AgentRT CB-1 FAIL: 50-pipe chain was ALLOWED"
        assert any("COMPLEXITY_EXCEEDED" in r.message for r in caplog.records), (
            "AgentRT CB-1 FAIL: COMPLEXITY_EXCEEDED event not emitted"
        )

    def test_100_pipe_subcommands_denied(self, strict_checker, caplog):
        args = _pipe_chain(100)
        with caplog.at_level(logging.INFO):
            result = strict_checker.check("shell.exec", args)
        assert not result.allowed, "AgentRT CB-1 FAIL: 100-pipe chain was ALLOWED"

    def test_11_pipe_subcommands_denied(self, strict_checker):
        args = _pipe_chain(11)
        result = strict_checker.check("shell.exec", args)
        assert not result.allowed, "AgentRT CB-1 FAIL: 11-pipe chain was ALLOWED"

    def test_10_pipe_subcommands_allowed(self, strict_checker):
        """Boundary: exactly at limit must be ALLOWED (regression guard)."""
        args = _pipe_chain(10)
        assert _count_subcommands(args) == 10
        result = strict_checker.check("shell.exec", args)
        assert result.allowed, "AgentRT CB-1 FAIL: at-limit request was DENIED (false positive)"


class TestCB2SemicolonChain:
    """AgentRT CB-2 — 50+ semicolon-chained subcommands must be denied."""

    def test_50_semicolon_subcommands_denied(self, strict_checker, caplog):
        args = _semicolon_chain(50)
        with caplog.at_level(logging.INFO):
            result = strict_checker.check("shell.exec", args)
        assert not result.allowed, "AgentRT CB-2 FAIL: 50-semicolon chain was ALLOWED"
        assert any("COMPLEXITY_EXCEEDED" in r.message for r in caplog.records)


class TestCB3AndChain:
    """AgentRT CB-3 — 50+ &&-chained subcommands must be denied."""

    def test_50_and_and_subcommands_denied(self, strict_checker, caplog):
        args = _and_chain(50)
        with caplog.at_level(logging.INFO):
            result = strict_checker.check("shell.exec", args)
        assert not result.allowed, "AgentRT CB-3 FAIL: 50-&& chain was ALLOWED"
        assert any("COMPLEXITY_EXCEEDED" in r.message for r in caplog.records)


class TestCB4MixedOperators:
    """AgentRT CB-4 — mixed operator chain evasion must be denied."""

    def test_50_mixed_operators_denied(self, strict_checker, caplog):
        args = _mixed_chain(50)
        with caplog.at_level(logging.INFO):
            result = strict_checker.check("shell.exec", args)
        assert not result.allowed, "AgentRT CB-4 FAIL: mixed-operator chain was ALLOWED"
        assert any("COMPLEXITY_EXCEEDED" in r.message for r in caplog.records)


class TestCB5CommandSubstitution:
    """AgentRT CB-5 — $() command substitution nesting must be denied."""

    def test_50_command_substitutions_denied(self, strict_checker, caplog):
        args = _command_substitution_chain(50)
        with caplog.at_level(logging.INFO):
            result = strict_checker.check("shell.exec", args)
        assert not result.allowed, "AgentRT CB-5 FAIL: 50-substitution nesting was ALLOWED"
        assert any("COMPLEXITY_EXCEEDED" in r.message for r in caplog.records)


class TestCB6MultiFieldSubcommands:
    """AgentRT CB-6 — subcommands spread across multiple args fields must be denied."""

    def test_subcommands_across_fields_denied(self, strict_checker, caplog):
        args = _multifield_chain(51)
        total = _count_subcommands(args)
        assert total > 10, f"Expected >10 total subcommands across fields, got {total}"
        with caplog.at_level(logging.INFO):
            result = strict_checker.check("shell.exec", args)
        assert not result.allowed, (
            "AgentRT CB-6 FAIL: multi-field subcommand spread was ALLOWED"
        )
        assert any("COMPLEXITY_EXCEEDED" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# CB-7: Argument byte size overflow
# ---------------------------------------------------------------------------


class TestCB7ArgByteOverflow:
    """AgentRT CB-7 — oversized argument payload must be denied."""

    def test_oversized_args_denied(self, strict_checker, caplog):
        args = _oversized_args(65537)
        with caplog.at_level(logging.INFO):
            result = strict_checker.check("tool.exec", args)
        assert not result.allowed, "AgentRT CB-7 FAIL: oversized args were ALLOWED"
        violations = [v for v in result.violations if v.dimension == "arg_bytes"]
        assert violations, "AgentRT CB-7 FAIL: no arg_bytes violation recorded"
        assert violations[0].actual > 65536
        assert any("COMPLEXITY_EXCEEDED" in r.message for r in caplog.records)

    def test_exactly_at_byte_limit_allowed(self, strict_checker):
        # json.dumps({"payload": "x"*n}, separators=(",",":")) adds 14 bytes of overhead:
        # '{"payload":"' (12) + '"}'(2) = 14. So n = 65536 - 14 = 65522 hits the limit exactly.
        import json
        n = 65536 - len(json.dumps({"payload": ""}, separators=(",", ":")))
        args = _oversized_args(n)
        assert len(json.dumps(args, separators=(",", ":")).encode()) == 65536
        result = strict_checker.check("tool.exec", args)
        assert result.allowed, "AgentRT CB-7 FAIL: at-byte-limit request was DENIED (false positive)"

    def test_double_budget_arg_denied(self, strict_checker, caplog):
        args = _oversized_args(131072)
        with caplog.at_level(logging.INFO):
            result = strict_checker.check("tool.exec", args)
        assert not result.allowed


# ---------------------------------------------------------------------------
# CB-8: JSON nesting depth overflow
# ---------------------------------------------------------------------------


class TestCB8NestingDepthOverflow:
    """AgentRT CB-8 — deeply nested dict/list structure must be denied."""

    def test_depth_11_denied(self, strict_checker, caplog):
        args = _deeply_nested(11)
        with caplog.at_level(logging.INFO):
            result = strict_checker.check("tool.exec", args)
        assert not result.allowed, "AgentRT CB-8 FAIL: depth-11 nesting was ALLOWED"
        violations = [v for v in result.violations if v.dimension == "nesting_depth"]
        assert violations, "AgentRT CB-8 FAIL: no nesting_depth violation recorded"
        assert any("COMPLEXITY_EXCEEDED" in r.message for r in caplog.records)

    def test_depth_20_denied(self, strict_checker, caplog):
        args = _deeply_nested(20)
        with caplog.at_level(logging.INFO):
            result = strict_checker.check("tool.exec", args)
        assert not result.allowed

    def test_depth_10_allowed(self, strict_checker):
        # _deeply_nested(n) wraps {"leaf":"value"} (depth 1) n more times → final depth = n+1.
        # So to get depth 10 (≤ limit of 10), use _deeply_nested(9).
        args = _deeply_nested(9)
        result = strict_checker.check("tool.exec", args)
        assert result.allowed, "AgentRT CB-8 FAIL: at-depth-limit request was DENIED (false positive)"


# ---------------------------------------------------------------------------
# CB-9: Deliberate evaluation timeout (hung coroutine)
# ---------------------------------------------------------------------------


class TestCB9EvaluationTimeout:
    """AgentRT CB-9 — hung evaluation must trigger DENY via FAIL_CLOSED timeout."""

    @pytest.mark.asyncio
    async def test_hung_evaluation_timed_out(self):
        guard = EvalTimeoutGuard(timeout_s=0.05)
        result, timed_out = await guard.run(_hung_coroutine())
        assert timed_out is True, "AgentRT CB-9 FAIL: hung evaluation was not timed out"
        assert result is None, "AgentRT CB-9 FAIL: timed-out result is not None"

    @pytest.mark.asyncio
    async def test_timed_out_result_is_not_allow(self):
        guard = EvalTimeoutGuard(timeout_s=0.05)
        result, timed_out = await guard.run(_hung_coroutine())
        assert result != "ALLOW", (
            "AgentRT CB-9 FAIL: timeout result is ALLOW — Evaluation Guarantee Invariant violated"
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_timeout_emits_eval_timeout_event(self, caplog):
        guard = EvalTimeoutGuard(timeout_s=0.05)
        with caplog.at_level(logging.WARNING):
            await guard.run(_hung_coroutine())
        assert any(
            "eval_timeout" in r.message or "EVAL_TIMEOUT" in r.message
            for r in caplog.records
        ), "AgentRT CB-9 FAIL: EVAL_TIMEOUT event not emitted on timeout"

    @pytest.mark.asyncio
    async def test_five_consecutive_timeouts_all_deny(self):
        """Repeated timeout attempts must all produce DENY — no cumulative bypass."""
        guard = EvalTimeoutGuard(timeout_s=0.05)
        for i in range(5):
            result, timed_out = await guard.run(_hung_coroutine())
            assert timed_out is True, f"AgentRT CB-9 FAIL: attempt {i + 1} was not timed out"
            assert result is None


# ---------------------------------------------------------------------------
# CB-10: FAIL_CLOSED invariant — no ALLOW on timeout
# ---------------------------------------------------------------------------


class TestCB10FailClosedInvariant:
    """AgentRT CB-10 — the Evaluation Guarantee Invariant must hold on timeout."""

    def test_eval_timeout_guard_has_no_fail_open_param(self):
        """EvalTimeoutGuard must not expose a FAIL_OPEN configuration parameter."""
        import inspect
        sig = inspect.signature(EvalTimeoutGuard.__init__)
        param_names = list(sig.parameters.keys())
        forbidden = {"fail_open", "allow_on_timeout", "default_allow", "permissive"}
        found = forbidden & set(param_names)
        assert not found, (
            f"AgentRT CB-10 FAIL: EvalTimeoutGuard exposes FAIL_OPEN parameters: {found}"
        )

    def test_timeout_event_carries_evaluation_guarantee_flag(self):
        event = emit_timeout_event(
            timeout_s=2.0,
            elapsed_s=2.01,
            session_id="agentrt-sess-001",
            agent_id="agentrt-agent-001",
            tool_name="shell.exec",
        )
        assert event["evaluation_guarantee_invariant"] is True, (
            "AgentRT CB-10 FAIL: timeout event missing evaluation_guarantee_invariant=True"
        )
        assert event["decision"] == "DENY", (
            "AgentRT CB-10 FAIL: timeout event decision is not DENY"
        )

    def test_complexity_event_carries_evaluation_guarantee_flag(self):
        violations = [
            ComplexityViolation(
                dimension="subcommand_count",
                limit=10,
                actual=50,
                detail="Subcommand count 50 exceeds limit 10",
            )
        ]
        event = emit_complexity_exceeded_event(
            tool_name="shell.exec",
            violations=violations,
            session_id="agentrt-sess-002",
            agent_id="agentrt-agent-002",
            request_id="agentrt-req-002",
        )
        assert event["evaluation_guarantee_invariant"] is True, (
            "AgentRT CB-10 FAIL: COMPLEXITY_EXCEEDED event missing evaluation_guarantee_invariant"
        )
        assert event["decision"] == "DENY"

    def test_no_operator_config_produces_allow_on_budget_exceeded(self):
        """Regardless of configured limits, exceeding them must always DENY."""
        for max_subcommand_count in [1, 5, 10, 25, 50]:
            checker = ComplexityBudgetChecker(
                max_arg_bytes=65536,
                max_subcommand_count=max_subcommand_count,
                max_nesting_depth=10,
            )
            oversized = _pipe_chain(max_subcommand_count + 1)
            result = checker.check("shell.exec", oversized)
            assert not result.allowed, (
                f"AgentRT CB-10 FAIL: ALLOW when {max_subcommand_count + 1} subcommands "
                f"exceed limit {max_subcommand_count}"
            )
