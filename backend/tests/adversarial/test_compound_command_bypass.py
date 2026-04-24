"""Adversarial test — compound command bypass via 50+ subcommands.

Sprint S-E02 — E02-T06

Verifies that an adversarial agent attempting to bypass policy enforcement
by embedding 50+ subcommands in a compound shell command is:
  1. Denied by the complexity budget gate (DENY decision)
  2. A COMPLEXITY_EXCEEDED event is emitted

This test class directly simulates bypass vectors described in the bypass
threat model (docs/threat_model/bypass_vectors.md), Class 2: Complexity Bypass.
"""

from __future__ import annotations

import json
import logging

import pytest

from app.enforcement.complexity_budget import (
    ComplexityBudgetChecker,
    _count_subcommands,
)


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def build_pipe_chain(n: int) -> dict:
    """Build a tool_args dict with n pipe-separated subcommands."""
    payload = " | ".join(f"cmd{i}" for i in range(n + 1))
    return {"command": payload}


def build_semicolon_chain(n: int) -> dict:
    """Build a tool_args dict with n semicolon-separated subcommands."""
    payload = "; ".join(f"cmd{i}" for i in range(n + 1))
    return {"command": payload}


def build_ampersand_chain(n: int) -> dict:
    """Build a tool_args dict with n && -chained subcommands."""
    payload = " && ".join(f"cmd{i}" for i in range(n + 1))
    return {"command": payload}


def build_mixed_chain(n: int) -> dict:
    """Alternate between |, ;, && to simulate realistic compound evasion."""
    ops = ["|", ";", "&&", "||"]
    parts = [f"cmd{i}" for i in range(n + 1)]
    payload = ""
    for i, part in enumerate(parts[:-1]):
        payload += part + " " + ops[i % len(ops)] + " "
    payload += parts[-1]
    return {"command": payload}


def build_command_substitution_chain(n: int) -> dict:
    """Nest n $() command substitutions."""
    payload = "echo " + "$(echo " * n + "id" + ")" * n
    return {"command": payload}


def build_multifield_chain(n: int) -> dict:
    """Spread subcommands across multiple tool_args fields."""
    per_field = n // 3 + 1
    return {
        "pre_hook": " | ".join(f"pre{i}" for i in range(per_field)),
        "command": " | ".join(f"cmd{i}" for i in range(per_field)),
        "post_hook": " | ".join(f"post{i}" for i in range(per_field)),
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def strict_checker() -> ComplexityBudgetChecker:
    """Checker with production-default limits: max 10 subcommands."""
    return ComplexityBudgetChecker(
        max_arg_bytes=65536,
        max_subcommand_count=10,
        max_nesting_depth=10,
    )


@pytest.fixture
def lenient_checker() -> ComplexityBudgetChecker:
    """Checker with a relaxed subcommand limit (25) — still denies 50+."""
    return ComplexityBudgetChecker(
        max_arg_bytes=65536,
        max_subcommand_count=25,
        max_nesting_depth=10,
    )


# ---------------------------------------------------------------------------
# Core adversarial tests (50+ subcommands)
# ---------------------------------------------------------------------------


class TestCompoundCommandBypass:
    """Verify DENY + COMPLEXITY_EXCEEDED on 50+ subcommand payloads."""

    def _assert_denied_with_event(
        self,
        checker: ComplexityBudgetChecker,
        tool_args: dict,
        caplog,
    ) -> None:
        with caplog.at_level(logging.INFO):
            result = checker.check("shell.exec", tool_args)

        assert result.allowed is False, (
            f"Expected DENY for {_count_subcommands(tool_args)} subcommands "
            f"but got ALLOW"
        )
        subcommand_violations = [
            v for v in result.violations if v.dimension == "subcommand_count"
        ]
        assert subcommand_violations, "Expected subcommand_count violation"
        assert subcommand_violations[0].actual > checker._max_subcommand_count

        # COMPLEXITY_EXCEEDED event must be logged
        assert any(
            "COMPLEXITY_EXCEEDED" in r.message for r in caplog.records
        ), "COMPLEXITY_EXCEEDED event not emitted"

    def test_50_pipe_subcommands_denied(self, strict_checker, caplog):
        self._assert_denied_with_event(
            strict_checker, build_pipe_chain(50), caplog
        )

    def test_50_semicolon_subcommands_denied(self, strict_checker, caplog):
        self._assert_denied_with_event(
            strict_checker, build_semicolon_chain(50), caplog
        )

    def test_50_and_and_subcommands_denied(self, strict_checker, caplog):
        self._assert_denied_with_event(
            strict_checker, build_ampersand_chain(50), caplog
        )

    def test_50_mixed_operators_denied(self, strict_checker, caplog):
        self._assert_denied_with_event(
            strict_checker, build_mixed_chain(50), caplog
        )

    def test_100_subcommands_denied(self, strict_checker, caplog):
        self._assert_denied_with_event(
            strict_checker, build_pipe_chain(100), caplog
        )

    def test_50_command_substitutions_denied(self, strict_checker, caplog):
        self._assert_denied_with_event(
            strict_checker, build_command_substitution_chain(50), caplog
        )

    def test_multifield_50_subcommands_denied(self, strict_checker, caplog):
        """Adversary splits subcommands across multiple fields."""
        args = build_multifield_chain(51)
        total = _count_subcommands(args)
        assert total > 10, f"Expected >10 total subcommands, got {total}"
        self._assert_denied_with_event(strict_checker, args, caplog)


# ---------------------------------------------------------------------------
# Boundary: exactly at limit is ALLOWED
# ---------------------------------------------------------------------------


class TestBoundaryAtLimit:
    def test_exactly_10_subcommands_allowed(self, strict_checker):
        # 10 pipes → 10 subcommand boundaries (at the limit, not over)
        args = build_pipe_chain(10)
        assert _count_subcommands(args) == 10
        result = strict_checker.check("shell.exec", args)
        assert result.allowed is True

    def test_11_subcommands_denied(self, strict_checker):
        args = build_pipe_chain(11)
        result = strict_checker.check("shell.exec", args)
        assert result.allowed is False


# ---------------------------------------------------------------------------
# Lenient config still denies 50+
# ---------------------------------------------------------------------------


class TestLenientConfigStillDenies50Plus:
    def test_25_subcommands_allowed_under_lenient(self, lenient_checker):
        args = build_pipe_chain(25)
        assert _count_subcommands(args) == 25
        result = lenient_checker.check("shell.exec", args)
        assert result.allowed is True

    def test_50_subcommands_denied_even_under_lenient(self, lenient_checker, caplog):
        args = build_pipe_chain(50)
        with caplog.at_level(logging.INFO):
            result = lenient_checker.check("shell.exec", args)
        assert result.allowed is False
        assert any("COMPLEXITY_EXCEEDED" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Evasion: obfuscation attempts
# ---------------------------------------------------------------------------


class TestObfuscationAttempts:
    """Verify that common obfuscation tricks are still caught."""

    def test_unicode_lookalike_pipe_not_counted(self, strict_checker):
        # U+FF5C (FULLWIDTH VERTICAL LINE) is not a real pipe — not counted
        args = {"cmd": "｜".join(f"cmd{i}" for i in range(50))}
        result = strict_checker.check("tool", args)
        # Unicode lookalike should NOT be counted as a subcommand
        subcommand_count = _count_subcommands(args)
        assert subcommand_count == 0
        assert result.allowed is True

    def test_base64_encoded_commands_within_budget(self, strict_checker):
        # Base64-encoded payloads have no shell metacharacters
        import base64
        evil = " | ".join(f"cmd{i}" for i in range(50))
        encoded = base64.b64encode(evil.encode()).decode()
        args = {"payload": encoded}
        result = strict_checker.check("tool", args)
        # Base64 has no shell operators → within budget
        assert result.allowed is True

    def test_json_escaped_operators_still_caught(self, strict_checker, caplog):
        # The checker operates on Python string values (after JSON decode)
        # so JSON-escaped characters are the actual chars after deserialisation.
        # Operators: | (1), ; (2), ; (3), $( (4) = 4 total
        args = {"cmd": "ls | grep foo; rm -rf /; echo $(id)"}
        assert _count_subcommands(args) == 4
        with caplog.at_level(logging.INFO):
            checker = ComplexityBudgetChecker(
                max_arg_bytes=65536,
                max_subcommand_count=2,
                max_nesting_depth=10,
            )
            result = checker.check("shell.exec", args)
        assert result.allowed is False


# ---------------------------------------------------------------------------
# COMPLEXITY_EXCEEDED event schema validation
# ---------------------------------------------------------------------------


class TestComplexityExceededEventOnBypass:
    def test_event_has_correct_decision(self, strict_checker):
        args = build_pipe_chain(50)
        from app.enforcement.complexity_budget import emit_complexity_exceeded_event, ComplexityViolation

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
            session_id="sess-adv-001",
            agent_id="adv-agent",
            request_id="req-adv-001",
        )
        assert event["decision"] == "DENY"
        assert event["evaluation_guarantee_invariant"] is True
        assert event["finding_info"]["violations"][0]["actual"] == 50

    def test_event_violation_count_matches(self, strict_checker, caplog):
        args = build_pipe_chain(50)
        with caplog.at_level(logging.INFO):
            result = strict_checker.check("shell.exec", args)
        assert not result.allowed
        violation = next(
            v for v in result.violations if v.dimension == "subcommand_count"
        )
        assert violation.actual == 50
