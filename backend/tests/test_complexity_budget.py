"""Unit tests for the complexity budget checker and eval timeout guard.

Sprint S-E02 — E02-T05
Covers:
  - Argument size exceeded
  - Subcommand count exceeded
  - Nesting depth exceeded
  - Timeout triggered → DENY
  - All dimensions within budget → ALLOW
  - COMPLEXITY_EXCEEDED event emitted on violation
  - No operator config can produce ALLOW on budget exceeded
"""

from __future__ import annotations

import asyncio

import pytest

from app.enforcement.complexity_budget import (
    ComplexityBudgetChecker,
    ComplexityCheckResult,
    _count_subcommands,
    _max_nesting_depth,
    emit_complexity_exceeded_event,
)
from app.enforcement.eval_timeout import EvalTimeoutGuard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_checker(
    max_arg_bytes: int = 1024,
    max_subcommand_count: int = 3,
    max_nesting_depth: int = 5,
) -> ComplexityBudgetChecker:
    return ComplexityBudgetChecker(
        max_arg_bytes=max_arg_bytes,
        max_subcommand_count=max_subcommand_count,
        max_nesting_depth=max_nesting_depth,
    )


# ---------------------------------------------------------------------------
# _max_nesting_depth
# ---------------------------------------------------------------------------


class TestMaxNestingDepth:
    def test_flat_dict(self):
        assert _max_nesting_depth({"a": 1, "b": "x"}) == 1

    def test_nested_dict(self):
        obj = {"a": {"b": {"c": "val"}}}
        assert _max_nesting_depth(obj) == 3

    def test_list_of_dicts(self):
        obj = [{"a": {"b": 1}}, {"c": 2}]
        assert _max_nesting_depth(obj) == 3

    def test_scalar(self):
        assert _max_nesting_depth("hello") == 0

    def test_empty_dict(self):
        assert _max_nesting_depth({}) == 0

    def test_empty_list(self):
        assert _max_nesting_depth([]) == 0

    def test_deeply_nested(self):
        obj: dict = {}
        cur = obj
        for _ in range(15):
            cur["x"] = {}
            cur = cur["x"]
        assert _max_nesting_depth(obj) == 15


# ---------------------------------------------------------------------------
# _count_subcommands
# ---------------------------------------------------------------------------


class TestCountSubcommands:
    def test_no_operators(self):
        assert _count_subcommands({"cmd": "ls -la"}) == 0

    def test_pipe(self):
        assert _count_subcommands({"cmd": "ls | grep txt"}) == 1

    def test_semicolon(self):
        assert _count_subcommands({"cmd": "ls; rm -rf /"}) == 1

    def test_and_and(self):
        assert _count_subcommands({"cmd": "ls && rm file"}) == 1

    def test_or_or(self):
        assert _count_subcommands({"cmd": "ls || rm file"}) == 1

    def test_backtick(self):
        # Each backtick is a separate metachar match; `id` produces 2 backtick matches
        assert _count_subcommands({"cmd": "echo `id`"}) == 2

    def test_dollar_paren(self):
        assert _count_subcommands({"cmd": "echo $(id)"}) == 1

    def test_multiple_operators(self):
        # "cmd1 | cmd2; cmd3 && cmd4" → 3 operators
        assert _count_subcommands({"cmd": "cmd1 | cmd2; cmd3 && cmd4"}) == 3

    def test_recursive_dict(self):
        obj = {"outer": {"inner": "ls | grep foo"}}
        assert _count_subcommands(obj) == 1

    def test_list_values(self):
        obj = {"cmds": ["ls | grep txt", "echo $(id)"]}
        assert _count_subcommands(obj) == 2

    def test_compound_50_subcommands(self):
        # Simulate an attacker building a 50-subcommand chain
        payload = " | ".join(f"cmd{i}" for i in range(51))  # 50 pipe operators
        obj = {"command": payload}
        assert _count_subcommands(obj) == 50


# ---------------------------------------------------------------------------
# ComplexityBudgetChecker — argument size
# ---------------------------------------------------------------------------


class TestArgSizeCheck:
    def test_within_limit(self):
        checker = make_checker(max_arg_bytes=1024)
        result = checker.check("shell.exec", {"cmd": "ls"})
        assert result.allowed is True
        assert result.violations == []

    def test_exactly_at_limit(self):
        # Build a string that serialises to exactly max_arg_bytes bytes.
        checker = make_checker(max_arg_bytes=100)
        # {"cmd":"<padding>"} where padding fills to exactly 100 bytes
        # Overhead: {"cmd":""} = 10 bytes → need 90 chars of padding
        payload = {"cmd": "A" * 90}
        import json
        assert len(json.dumps(payload, separators=(",", ":")).encode()) == 100
        result = checker.check("tool", payload)
        assert result.allowed is True

    def test_one_byte_over_limit(self):
        checker = make_checker(max_arg_bytes=100)
        payload = {"cmd": "A" * 91}  # 101 bytes
        result = checker.check("tool", payload)
        assert result.allowed is False
        assert any(v.dimension == "arg_bytes" for v in result.violations)

    def test_massive_arg(self):
        checker = make_checker(max_arg_bytes=1024)
        payload = {"data": "X" * 10_000}
        result = checker.check("tool", payload)
        assert result.allowed is False
        assert any(v.dimension == "arg_bytes" for v in result.violations)

    def test_violation_detail_contains_actual_and_limit(self):
        checker = make_checker(max_arg_bytes=10)
        result = checker.check("tool", {"cmd": "hello world"})
        assert result.allowed is False
        v = next(v for v in result.violations if v.dimension == "arg_bytes")
        assert str(v.limit) in v.detail
        assert str(v.actual) in v.detail


# ---------------------------------------------------------------------------
# ComplexityBudgetChecker — subcommand count
# ---------------------------------------------------------------------------


class TestSubcommandCountCheck:
    def test_within_limit(self):
        checker = make_checker(max_subcommand_count=5)
        result = checker.check("shell.exec", {"cmd": "ls | grep txt | sort"})
        assert result.allowed is True  # 2 pipes

    def test_exactly_at_limit(self):
        checker = make_checker(max_subcommand_count=2)
        result = checker.check("tool", {"cmd": "a | b | c"})
        assert _count_subcommands({"cmd": "a | b | c"}) == 2
        assert result.allowed is True

    def test_one_over_limit(self):
        checker = make_checker(max_subcommand_count=2)
        result = checker.check("tool", {"cmd": "a | b | c | d"})  # 3 pipes
        assert result.allowed is False
        assert any(v.dimension == "subcommand_count" for v in result.violations)

    def test_50_subcommands_denied(self):
        checker = make_checker(max_subcommand_count=10)
        payload = " | ".join(f"cmd{i}" for i in range(51))
        result = checker.check("shell.exec", {"command": payload})
        assert result.allowed is False
        v = next(v for v in result.violations if v.dimension == "subcommand_count")
        assert v.actual == 50
        assert v.limit == 10


# ---------------------------------------------------------------------------
# ComplexityBudgetChecker — nesting depth
# ---------------------------------------------------------------------------


class TestNestingDepthCheck:
    def test_within_limit(self):
        checker = make_checker(max_nesting_depth=5)
        obj = {"a": {"b": {"c": "val"}}}
        result = checker.check("tool", obj)
        assert result.allowed is True

    def test_exactly_at_limit(self):
        checker = make_checker(max_nesting_depth=3)
        obj = {"a": {"b": {"c": "val"}}}
        assert _max_nesting_depth(obj) == 3
        result = checker.check("tool", obj)
        assert result.allowed is True

    def test_one_over_limit(self):
        checker = make_checker(max_nesting_depth=3)
        obj = {"a": {"b": {"c": {"d": "val"}}}}
        result = checker.check("tool", obj)
        assert result.allowed is False
        assert any(v.dimension == "nesting_depth" for v in result.violations)

    def test_deep_nesting_denied(self):
        checker = make_checker(max_nesting_depth=5)
        obj: dict = {}
        cur = obj
        for _ in range(20):
            cur["x"] = {}
            cur = cur["x"]
        result = checker.check("tool", obj)
        assert result.allowed is False
        v = next(v for v in result.violations if v.dimension == "nesting_depth")
        assert v.actual == 20


# ---------------------------------------------------------------------------
# Multiple simultaneous violations
# ---------------------------------------------------------------------------


class TestMultipleViolations:
    def test_all_three_exceeded(self):
        checker = make_checker(
            max_arg_bytes=10,
            max_subcommand_count=0,
            max_nesting_depth=0,
        )
        obj = {"cmd": "ls | grep x"}  # size > 10, 1 pipe, depth 1
        result = checker.check("tool", obj)
        assert result.allowed is False
        dims = {v.dimension for v in result.violations}
        assert "arg_bytes" in dims
        assert "subcommand_count" in dims
        assert "nesting_depth" in dims

    def test_reason_contains_all_violations(self):
        checker = make_checker(max_arg_bytes=5, max_subcommand_count=0)
        result = checker.check("tool", {"cmd": "ls | grep"})
        reason_lower = result.reason.lower()
        assert "byte" in reason_lower
        assert "subcommand" in reason_lower


# ---------------------------------------------------------------------------
# No operator config can produce ALLOW on budget exceeded
# ---------------------------------------------------------------------------


class TestNoPermissiveFallback:
    """Verify the Evaluation Guarantee Invariant: no config option yields ALLOW
    when any budget dimension is exceeded."""

    def test_zero_max_arg_bytes_always_denies(self):
        # Even max_arg_bytes=0 must deny any non-empty payload
        checker = ComplexityBudgetChecker(
            max_arg_bytes=0,
            max_subcommand_count=999,
            max_nesting_depth=999,
        )
        result = checker.check("tool", {"x": "y"})
        assert result.allowed is False

    def test_cannot_configure_permissive_fallback(self):
        # Verify that ComplexityBudgetChecker has no "soft_deny" or "warn_only" mode
        import inspect
        checker = make_checker()
        assert not hasattr(checker, "soft_deny")
        assert not hasattr(checker, "warn_only")
        assert not hasattr(checker, "fail_open")


# ---------------------------------------------------------------------------
# COMPLEXITY_EXCEEDED event emission
# ---------------------------------------------------------------------------


class TestComplexityExceededEvent:
    def test_event_emitted_on_violation(self):
        from app.enforcement.complexity_budget import ComplexityViolation

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
            session_id="sess-001",
            agent_id="agent-001",
            request_id="req-001",
        )
        assert event["class_name"] == "COMPLEXITY_EXCEEDED"
        assert event["decision"] == "DENY"
        assert event["evaluation_guarantee_invariant"] is True
        assert event["finding_info"]["violations"][0]["dimension"] == "subcommand_count"
        assert event["finding_info"]["violations"][0]["actual"] == 50

    def test_event_contains_ocsf_required_fields(self):
        from app.enforcement.complexity_budget import ComplexityViolation

        event = emit_complexity_exceeded_event(
            tool_name="tool",
            violations=[
                ComplexityViolation("arg_bytes", 1024, 2048, "detail")
            ],
        )
        for field in ("class_uid", "class_name", "category_uid", "severity_id", "time", "metadata"):
            assert field in event, f"Missing OCSF field: {field}"

    def test_checker_emits_event_on_violation(self, caplog):
        import logging
        checker = make_checker(max_subcommand_count=1)
        with caplog.at_level(logging.INFO):
            result = checker.check("shell.exec", {"cmd": "a | b | c"})
        assert result.allowed is False
        # Event was logged
        assert any("COMPLEXITY_EXCEEDED" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# EvalTimeoutGuard
# ---------------------------------------------------------------------------


class TestEvalTimeoutGuard:
    @pytest.mark.asyncio
    async def test_completes_within_timeout(self):
        guard = EvalTimeoutGuard(timeout_s=5.0)

        async def fast_coro():
            return "ok"

        result, timed_out = await guard.run(fast_coro())
        assert timed_out is False
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_timeout_returns_none_and_timed_out_true(self):
        guard = EvalTimeoutGuard(timeout_s=0.05)

        async def slow_coro():
            await asyncio.sleep(10)
            return "never"

        result, timed_out = await guard.run(slow_coro())
        assert timed_out is True
        assert result is None

    @pytest.mark.asyncio
    async def test_run_or_deny_returns_deny_on_timeout(self):
        guard = EvalTimeoutGuard(timeout_s=0.05)

        async def slow_coro():
            await asyncio.sleep(10)
            return "result"

        deny_value = "DENY_SENTINEL"
        result = await guard.run_or_deny(slow_coro(), lambda: deny_value)
        assert result == deny_value

    @pytest.mark.asyncio
    async def test_run_or_deny_returns_result_when_fast(self):
        guard = EvalTimeoutGuard(timeout_s=5.0)

        async def fast_coro():
            return "allowed"

        result = await guard.run_or_deny(fast_coro(), lambda: "DENY")
        assert result == "allowed"

    def test_invalid_timeout_raises(self):
        with pytest.raises(ValueError, match="positive"):
            EvalTimeoutGuard(timeout_s=0.0)
        with pytest.raises(ValueError, match="positive"):
            EvalTimeoutGuard(timeout_s=-1.0)

    @pytest.mark.asyncio
    async def test_timeout_event_emitted(self, caplog):
        import logging
        guard = EvalTimeoutGuard(timeout_s=0.01)

        async def slow():
            await asyncio.sleep(5)

        with caplog.at_level(logging.INFO):
            await guard.run(slow())

        assert any("EVAL_TIMEOUT" in r.message or "eval_timeout" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Integration: complexity_checker singleton + config
# ---------------------------------------------------------------------------


class TestComplexityCheckerSingleton:
    def test_singleton_uses_config(self, monkeypatch):
        from app.enforcement.complexity_budget import complexity_checker

        # Force reconfigure to pick up monkeypatched settings
        complexity_checker.reconfigure()

        from app.core.config import settings
        monkeypatch.setattr(settings, "complexity_budget_max_subcommand_count", 0)
        complexity_checker.reconfigure()

        # Any pipe should now be denied
        result = complexity_checker.check("tool", {"cmd": "ls | grep"})
        assert result.allowed is False

        # Restore
        complexity_checker.reconfigure()
