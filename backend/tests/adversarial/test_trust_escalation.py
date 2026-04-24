"""Adversarial test — subagent permission escalation via delegation chain.

Sprint S-E06 — E06-T07

Verifies that an adversarial subagent attempting to claim permissions beyond
those held by the root principal is:
  1. Detected by EffectivePermissionCalculator (escalation_detected=True)
  2. Denied — effective permissions never exceed root principal's set
  3. A TRUST_VIOLATION event with reason PERMISSION_ESCALATION is emitted

Also verifies that trust score degradation terminates over-long chains
regardless of the permissions claimed.

This test class directly simulates bypass vectors described in the bypass
threat model (docs/threat_model/bypass_vectors.md), Class 3: Reasoning Boundary
and Class 4: Hook Gaming (trust escalation sub-vector).
"""

from __future__ import annotations

import logging

import pytest

from app.trust.delegation_context import DelegationContext
from app.trust.events import TrustViolationReason, emit_trust_violation_event
from app.trust.permission_intersection import (
    EffectivePermissionCalculator,
    permission_calculator,
)
from app.trust.trust_score import TrustScoreCalculator, TrustScoreConfig


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def root_ctx() -> DelegationContext:
    """Root principal with a limited permission set."""
    return DelegationContext.for_root(
        "human-operator",
        permissions=["read_files", "write_files", "list_directory"],
    )


@pytest.fixture
def calc() -> EffectivePermissionCalculator:
    return EffectivePermissionCalculator()


@pytest.fixture
def default_trust_calc() -> TrustScoreCalculator:
    return TrustScoreCalculator(
        TrustScoreConfig(decay_rate=0.15, min_trust_threshold=0.10, max_hop_count=10)
    )


# ---------------------------------------------------------------------------
# Class 1: Direct permission escalation — single hop
# ---------------------------------------------------------------------------


class TestDirectPermissionEscalation:
    """Subagent at hop 1 claims permissions not held by root."""

    def _escalation_scenario(
        self,
        root_ctx: DelegationContext,
        calc: EffectivePermissionCalculator,
        claimed_permissions: list[str],
        caplog,
    ) -> None:
        ctx = root_ctx.create_child("adversarial-agent")
        result = calc.compute(
            root_permissions=root_ctx.root_permissions,
            requested_permissions=claimed_permissions,
        )

        assert result.escalation_detected is True, (
            f"Expected escalation detection for claimed={claimed_permissions!r} "
            f"but escalation_detected=False"
        )

        # Effective permissions must never exceed root
        forbidden = result.effective - root_ctx.root_permissions
        assert not forbidden, (
            f"Effective permissions {result.effective!r} contain items not in "
            f"root permissions {root_ctx.root_permissions!r}: {forbidden!r}"
        )

        # Emit TRUST_VIOLATION event
        with caplog.at_level(logging.ERROR):
            event = emit_trust_violation_event(
                reason=TrustViolationReason.PERMISSION_ESCALATION,
                detail=f"Claimed {result.escalated!r} beyond root",
                principal_chain=ctx.chain_as_list(),
                hop_count=ctx.hop_count,
                trust_score=0.85,
                root_principal=ctx.root_principal,
                agent_id=ctx.current_agent,
                escalated_permissions=sorted(result.escalated),
            )

        assert event["decision"] == "DENY"
        assert event["finding_info"]["reason"] == "PERMISSION_ESCALATION"
        assert any("TRUST_VIOLATION" in r.message for r in caplog.records)

    def test_claims_execute_shell_not_in_root(self, root_ctx, calc, caplog):
        self._escalation_scenario(
            root_ctx, calc, ["read_files", "write_files", "execute_shell"], caplog
        )

    def test_claims_admin_access(self, root_ctx, calc, caplog):
        self._escalation_scenario(
            root_ctx, calc, ["admin", "read_files"], caplog
        )

    def test_claims_database_access(self, root_ctx, calc, caplog):
        self._escalation_scenario(
            root_ctx, calc, ["read_files", "database_write", "database_read"], caplog
        )

    def test_claims_network_access(self, root_ctx, calc, caplog):
        self._escalation_scenario(
            root_ctx, calc, ["read_files", "network_egress", "dns_lookup"], caplog
        )

    def test_claims_all_permissions_via_wildcard_string(self, root_ctx, calc, caplog):
        # Adversary attempts a wildcard-string escalation
        self._escalation_scenario(
            root_ctx, calc, ["*", "read_files"], caplog
        )


# ---------------------------------------------------------------------------
# Class 2: Deep chain escalation — permission claimed at deep hop
# ---------------------------------------------------------------------------


class TestDeepChainEscalation:
    """Adversarial agent buried in a deep chain attempts escalation."""

    def test_escalation_at_hop_5_blocked(self, root_ctx, calc, caplog):
        ctx = root_ctx
        for i in range(5):
            ctx = ctx.create_child(f"agent-{i}")

        claimed = ["read_files", "execute_shell"]  # execute_shell not in root
        result = calc.compute(root_ctx.root_permissions, claimed)

        assert result.escalation_detected is True
        assert "execute_shell" in result.escalated
        assert "execute_shell" not in result.effective

    def test_effective_permissions_stay_bounded_at_every_hop(self, root_ctx, calc):
        ctx = root_ctx
        claimed = ["read_files", "write_files", "admin", "execute_shell"]

        for i in range(8):
            ctx = ctx.create_child(f"hop-{i}")
            result = calc.compute(root_ctx.root_permissions, claimed)
            # Effective permissions must always be ⊆ root_permissions
            assert result.effective <= root_ctx.root_permissions, (
                f"At hop {i + 1}: effective {result.effective!r} exceeds root "
                f"{root_ctx.root_permissions!r}"
            )
            # Escalation must always be detected
            assert result.escalation_detected is True

    def test_legitimate_subagent_not_blocked(self, root_ctx, calc):
        # An agent claiming only a subset of root permissions is NOT escalation
        ctx = root_ctx.create_child("honest-agent")
        result = calc.compute(
            root_permissions=root_ctx.root_permissions,
            requested_permissions=["read_files"],
        )
        assert result.escalation_detected is False
        assert result.effective == frozenset({"read_files"})


# ---------------------------------------------------------------------------
# Class 3: Trust score degradation terminates over-long chains
# ---------------------------------------------------------------------------


class TestTrustScoreDegradation:
    """Trust score falls below threshold, terminating the chain."""

    def test_chain_terminates_after_enough_hops(self, default_trust_calc):
        n = default_trust_calc.hops_until_termination()
        result = default_trust_calc.calculate(n)
        assert result.chain_must_terminate is True, (
            f"Expected chain to terminate at hop {n}, "
            f"score={result.score:.4f}"
        )

    def test_score_below_threshold_emits_trust_violation(self, caplog):
        config = TrustScoreConfig(decay_rate=0.50, min_trust_threshold=0.20)
        calc = TrustScoreCalculator(config)

        # hop 0: 1.0, hop 1: 0.5, hop 2: 0.25, hop 3: 0.125 < 0.20 → terminate
        result = calc.calculate(3)
        assert result.below_threshold is True

        chain = ["root"] + [f"agent-{i}" for i in range(3)]
        with caplog.at_level(logging.ERROR):
            event = emit_trust_violation_event(
                reason=TrustViolationReason.TRUST_BELOW_THRESHOLD,
                detail=f"Trust score {result.score:.4f} below threshold {config.min_trust_threshold}",
                principal_chain=chain,
                hop_count=result.hop_count,
                trust_score=result.score,
            )

        assert event["decision"] == "DENY"
        assert event["finding_info"]["reason"] == "TRUST_BELOW_THRESHOLD"
        assert event["finding_info"]["trust_score"] < config.min_trust_threshold
        assert any("TRUST_VIOLATION" in r.message for r in caplog.records)

    def test_max_hop_count_exceeded_emits_trust_violation(self, caplog):
        config = TrustScoreConfig(max_hop_count=3)
        calc = TrustScoreCalculator(config)

        result = calc.calculate(4)
        assert result.max_hops_exceeded is True

        with caplog.at_level(logging.ERROR):
            event = emit_trust_violation_event(
                reason=TrustViolationReason.MAX_HOP_COUNT_EXCEEDED,
                detail=f"Hop count {result.hop_count} exceeds max {config.max_hop_count}",
                principal_chain=["root"] + [f"a-{i}" for i in range(4)],
                hop_count=result.hop_count,
                trust_score=result.score,
            )

        assert event["decision"] == "DENY"
        assert event["finding_info"]["reason"] == "MAX_HOP_COUNT_EXCEEDED"

    def test_exactly_at_max_hops_is_allowed(self, default_trust_calc):
        result = default_trust_calc.calculate(10)
        assert result.max_hops_exceeded is False

    def test_one_beyond_max_hops_is_blocked(self, default_trust_calc):
        result = default_trust_calc.calculate(11)
        assert result.max_hops_exceeded is True
        assert result.chain_must_terminate is True


# ---------------------------------------------------------------------------
# Class 4: Adversarial patterns — subtle escalation attempts
# ---------------------------------------------------------------------------


class TestSubtleEscalationAttempts:
    """Simulate adversarial agents using subtle tactics to gain extra permissions."""

    def test_case_variation_does_not_bypass(self, calc):
        # Permissions stored as "read_files"; attacker claims "READ_FILES" (different string)
        # The string set check is case-sensitive — "READ_FILES" is NOT in root → escalation
        root_perms = ["read_files", "write_files"]
        claimed = ["READ_FILES", "write_files"]
        result = calc.compute(root_perms, claimed)
        # "READ_FILES" is not in root_perms (case-sensitive) → escalation
        assert result.escalation_detected is True
        assert "READ_FILES" in result.escalated

    def test_extra_whitespace_in_permission_name(self, calc):
        # " read_files" (leading space) is a different string from "read_files"
        root_perms = ["read_files"]
        claimed = [" read_files"]
        result = calc.compute(root_perms, claimed)
        assert result.escalation_detected is True

    def test_permission_with_path_traversal_suffix(self, calc):
        # Adversary injects "../" suffix to try to "extend" a permission
        root_perms = ["read_files"]
        claimed = ["read_files", "read_files/../admin"]
        result = calc.compute(root_perms, claimed)
        assert result.escalation_detected is True
        assert "read_files/../admin" in result.escalated

    def test_empty_permission_string_not_in_non_empty_root(self, calc):
        root_perms = ["read_files"]
        claimed = [""]
        result = calc.compute(root_perms, claimed)
        assert result.escalation_detected is True
        assert "" in result.escalated

    def test_claiming_subset_incrementally_across_hops(self, calc):
        # Attempt: each hop claims one more permission, accumulating to an escalation
        root_perms = frozenset(["read_files"])
        # hop 1: claim read_files — OK
        r1 = calc.compute(root_perms, ["read_files"])
        assert r1.escalation_detected is False
        # hop 2: claim read_files + write_files — ESCALATION
        r2 = calc.compute(root_perms, ["read_files", "write_files"])
        assert r2.escalation_detected is True

    def test_large_permission_set_escalation(self, calc):
        # Adversary claims 1000 permissions; only a few are in root
        root_perms = [f"perm_{i}" for i in range(5)]
        all_perms = [f"perm_{i}" for i in range(1000)]
        result = calc.compute(root_perms, all_perms)
        assert result.escalation_detected is True
        assert result.effective == frozenset(f"perm_{i}" for i in range(5))
        assert len(result.escalated) == 995


# ---------------------------------------------------------------------------
# Class 5: No-op passes — legitimate delegation must not trigger false positives
# ---------------------------------------------------------------------------


class TestLegitimateChainNotBlocked:
    """Verify that legitimate delegation patterns do not produce false positives."""

    def test_root_agent_no_delegation_allowed(self, default_trust_calc, calc):
        ctx = DelegationContext.for_root("root", permissions=["read_files", "write_files"])
        result = calc.compute(ctx.root_permissions, list(ctx.root_permissions))
        assert result.escalation_detected is False

        ts = default_trust_calc.from_context(ctx)
        assert not ts.chain_must_terminate

    def test_five_hop_chain_not_terminated_by_default_config(self, default_trust_calc):
        # Sprint S-E06 E06-T08 validates that the 15% default decay does not
        # over-terminate a 5-hop LangGraph workflow
        result = default_trust_calc.calculate(5)
        assert not result.chain_must_terminate, (
            f"Default 15% decay prematurely terminates at hop 5 "
            f"(score={result.score:.4f})"
        )

    def test_narrow_permission_subset_not_escalation(self, calc):
        root_perms = ["read_files", "write_files", "list_directory", "execute_shell"]
        # Agent only claims read access — strict subset, no escalation
        result = calc.compute(root_perms, ["read_files"])
        assert result.escalation_detected is False
        assert result.effective == frozenset({"read_files"})

    def test_permission_intersection_shrinks_through_chain(self, calc):
        # Simulate a chain where each level claims fewer permissions
        root_perms = frozenset(["r", "w", "x", "a"])
        level1_claims = ["r", "w", "x"]          # drops "a"
        level2_claims = ["r", "w"]               # drops "x"
        level3_claims = ["r"]                    # drops "w"

        r1 = calc.compute(root_perms, level1_claims)
        r2 = calc.compute(r1.effective, level2_claims)
        r3 = calc.compute(r2.effective, level3_claims)

        assert not r1.escalation_detected
        assert not r2.escalation_detected
        assert not r3.escalation_detected
        assert r3.effective == frozenset({"r"})


# ---------------------------------------------------------------------------
# TRUST_VIOLATION event — comprehensive schema validation
# ---------------------------------------------------------------------------


class TestTrustViolationEventSchema:
    def test_event_decision_is_always_deny(self):
        for reason in TrustViolationReason:
            event = emit_trust_violation_event(
                reason=reason,
                detail="test",
                principal_chain=["root"],
                hop_count=0,
                trust_score=1.0,
            )
            assert event["decision"] == "DENY", f"Non-DENY decision for {reason.value}"

    def test_trust_enforcement_fail_closed_always_true(self):
        for reason in TrustViolationReason:
            event = emit_trust_violation_event(
                reason=reason,
                detail="test",
                principal_chain=["root"],
                hop_count=0,
                trust_score=1.0,
            )
            assert event["trust_enforcement_fail_closed"] is True

    def test_type_uid_is_distinct_from_security_violation(self):
        # TRUST_VIOLATION uses type_uid 400203; SECURITY_VIOLATION uses 400202
        event = emit_trust_violation_event(
            reason=TrustViolationReason.PERMISSION_ESCALATION,
            detail="test",
            principal_chain=["root"],
            hop_count=0,
            trust_score=1.0,
        )
        assert event["type_uid"] == 400203
