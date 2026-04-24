"""Adversarial test — deliberate evaluation timeout → unconditional DENY.

Sprint S-E02 — E02-T07

Verifies that an adversarial agent attempting to exploit a slow or hung
evaluation coroutine (timeout-based bypass) is unconditionally denied.

Bypass vector: Class 2 — Complexity Bypass (timeout sub-class)
  An adversary crafts a request or context that causes policy evaluation to
  hang indefinitely.  If the timeout handler defaulted to ALLOW (FAIL_OPEN),
  the adversary would bypass enforcement.

The Evaluation Guarantee Invariant requires: on timeout → DENY, always.
"""

from __future__ import annotations

import asyncio
import logging

import pytest

from app.enforcement.eval_timeout import EvalTimeoutGuard, emit_timeout_event


# ---------------------------------------------------------------------------
# Slow evaluation simulations
# ---------------------------------------------------------------------------


async def hung_evaluation(sleep_s: float = 60.0):
    """Simulates a policy evaluation that never returns within the deadline."""
    await asyncio.sleep(sleep_s)
    return "ALLOW"  # Should never be reached during adversarial test


async def fast_evaluation():
    return "ALLOW"


async def very_slow_evaluation():
    """Simulates evaluation looping on a pathologically complex request."""
    await asyncio.sleep(30.0)
    return "ALLOW"


# ---------------------------------------------------------------------------
# Core invariant tests
# ---------------------------------------------------------------------------


class TestTimeoutBypassDenied:
    """Core tests: any timeout produces DENY, never ALLOW."""

    @pytest.mark.asyncio
    async def test_hung_evaluation_returns_timed_out(self):
        guard = EvalTimeoutGuard(timeout_s=0.05)
        result, timed_out = await guard.run(hung_evaluation())
        assert timed_out is True, "Expected timed_out=True for hung evaluation"
        assert result is None, "Expected None result on timeout"

    @pytest.mark.asyncio
    async def test_timed_out_result_is_none_not_allow(self):
        """Verify the timeout result cannot be mistaken for an ALLOW decision."""
        guard = EvalTimeoutGuard(timeout_s=0.05)
        result, timed_out = await guard.run(hung_evaluation())
        # result must be None — not "ALLOW" or any truthy permissive value
        assert result != "ALLOW"
        assert result != "allow"
        assert result is None

    @pytest.mark.asyncio
    async def test_run_or_deny_produces_deny_value_on_timeout(self):
        guard = EvalTimeoutGuard(timeout_s=0.05)
        deny_sentinel = object()  # unique deny object
        outcome = await guard.run_or_deny(hung_evaluation(), lambda: deny_sentinel)
        assert outcome is deny_sentinel, "Expected deny_factory result on timeout"

    @pytest.mark.asyncio
    async def test_run_or_deny_does_not_produce_allow_on_timeout(self):
        guard = EvalTimeoutGuard(timeout_s=0.05)
        outcome = await guard.run_or_deny(hung_evaluation(), lambda: "DENY")
        assert outcome != "ALLOW"
        assert outcome == "DENY"

    @pytest.mark.asyncio
    async def test_very_slow_evaluation_also_times_out(self):
        guard = EvalTimeoutGuard(timeout_s=0.1)
        result, timed_out = await guard.run(very_slow_evaluation())
        assert timed_out is True

    @pytest.mark.asyncio
    async def test_multiple_consecutive_timeouts_all_deny(self):
        """Repeated timeout attempts all produce DENY — no cumulative ALLOW bypass."""
        guard = EvalTimeoutGuard(timeout_s=0.05)
        for _ in range(5):
            result, timed_out = await guard.run(hung_evaluation())
            assert timed_out is True
            assert result is None


# ---------------------------------------------------------------------------
# Evaluation Guarantee Invariant: no config can produce ALLOW on timeout
# ---------------------------------------------------------------------------


class TestEvaluationGuaranteeInvariant:
    """Verify the invariant: timeout → DENY, no matter the timeout_s value."""

    @pytest.mark.asyncio
    async def test_minimum_timeout_still_denies(self):
        guard = EvalTimeoutGuard(timeout_s=0.001)
        result, timed_out = await guard.run(hung_evaluation())
        assert timed_out is True
        assert result is None

    @pytest.mark.asyncio
    async def test_guard_has_no_fail_open_option(self):
        """EvalTimeoutGuard must not expose a FAIL_OPEN parameter."""
        import inspect
        sig = inspect.signature(EvalTimeoutGuard.__init__)
        param_names = list(sig.parameters.keys())
        assert "fail_open" not in param_names, (
            "EvalTimeoutGuard must not support FAIL_OPEN mode"
        )
        assert "allow_on_timeout" not in param_names
        assert "default_allow" not in param_names

    @pytest.mark.asyncio
    async def test_evaluation_guarantee_flag_in_timeout_event(self):
        event = emit_timeout_event(
            timeout_s=2.0,
            elapsed_s=2.01,
            session_id="sess-001",
            agent_id="agent-001",
            tool_name="shell.exec",
        )
        assert event["evaluation_guarantee_invariant"] is True
        assert event["decision"] == "DENY"


# ---------------------------------------------------------------------------
# Timeout event structure
# ---------------------------------------------------------------------------


class TestTimeoutEventEmission:
    @pytest.mark.asyncio
    async def test_timeout_event_emitted_on_hung_evaluation(self, caplog):
        guard = EvalTimeoutGuard(timeout_s=0.05)
        with caplog.at_level(logging.WARNING):
            await guard.run(hung_evaluation())

        assert any(
            "eval_timeout" in r.message or "EVAL_TIMEOUT" in r.message
            for r in caplog.records
        ), "Expected timeout event log"

    def test_timeout_event_schema(self):
        event = emit_timeout_event(
            timeout_s=5.0,
            elapsed_s=5.001,
            session_id="sess-timeout-001",
            agent_id="adversary-agent",
            tool_name="shell.exec",
        )
        required_fields = [
            "class_uid", "class_name", "category_uid", "severity_id",
            "time", "metadata", "decision", "evaluation_guarantee_invariant",
        ]
        for field in required_fields:
            assert field in event, f"Missing OCSF field: {field}"

        assert event["class_name"] == "EVAL_TIMEOUT"
        assert event["decision"] == "DENY"
        assert event["evaluation_guarantee_invariant"] is True
        assert event["finding_info"]["timeout_s"] == 5.0
        assert event["finding_info"]["elapsed_s"] == pytest.approx(5.001, rel=1e-3)

    def test_timeout_event_has_actor(self):
        event = emit_timeout_event(
            timeout_s=1.0,
            elapsed_s=1.001,
            session_id="sess-x",
            agent_id="agent-x",
            tool_name="tool-x",
        )
        assert event["actor"]["agent_id"] == "agent-x"
        assert event["actor"]["session_id"] == "sess-x"
        assert event["resources"][0]["name"] == "tool-x"


# ---------------------------------------------------------------------------
# Contrast: fast evaluations are NOT timed out
# ---------------------------------------------------------------------------


class TestFastEvaluationsNotTimedOut:
    @pytest.mark.asyncio
    async def test_fast_coro_not_timed_out(self):
        guard = EvalTimeoutGuard(timeout_s=5.0)
        result, timed_out = await guard.run(fast_evaluation())
        assert timed_out is False
        assert result == "ALLOW"

    @pytest.mark.asyncio
    async def test_instant_result_not_timed_out(self):
        guard = EvalTimeoutGuard(timeout_s=1.0)

        async def instant():
            return "ALLOW"

        result, timed_out = await guard.run(instant())
        assert timed_out is False
        assert result == "ALLOW"


# ---------------------------------------------------------------------------
# Adversarial: cancellation and re-use
# ---------------------------------------------------------------------------


class TestGuardRobustness:
    @pytest.mark.asyncio
    async def test_guard_reusable_after_timeout(self):
        """Guard can be used again after a timeout — no state corruption."""
        guard = EvalTimeoutGuard(timeout_s=0.05)

        # First call: timeout
        _, timed_out1 = await guard.run(hung_evaluation())
        assert timed_out1 is True

        # Second call: fast — should complete
        result2, timed_out2 = await guard.run(fast_evaluation())
        assert timed_out2 is False
        assert result2 == "ALLOW"

    @pytest.mark.asyncio
    async def test_concurrent_guards_independent(self):
        """Multiple guard instances don't share state."""
        g1 = EvalTimeoutGuard(timeout_s=0.05)
        g2 = EvalTimeoutGuard(timeout_s=5.0)

        r1, t1 = await g1.run(hung_evaluation())
        r2, t2 = await g2.run(fast_evaluation())

        assert t1 is True  # g1 timed out
        assert t2 is False  # g2 completed
        assert r2 == "ALLOW"
