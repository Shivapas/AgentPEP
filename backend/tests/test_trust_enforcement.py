"""Unit tests for Sprint S-E06 — Recursive Trust Enforcement.

Sprint S-E06 — E06-T06
Covers:
  - DelegationContext: construction, hop count, child creation, serialisation
  - TrustScoreCalculator: single hop, multi-hop, max hop termination, decay rate
  - TrustScoreConfig: validation, boundary values
  - EffectivePermissionCalculator: intersection, escalation detection
  - emit_trust_violation_event: OCSF structure, all reason codes
  - AuthorizationRequestBuilder: delegation_context integration, hop_count derivation
  - Integration: end-to-end delegation chain → OPA input document
"""

from __future__ import annotations

import logging

import pytest

from app.trust.delegation_context import DelegationContext
from app.trust.events import TrustViolationReason, emit_trust_violation_event
from app.trust.permission_intersection import (
    EffectivePermissionCalculator,
    PermissionIntersectionResult,
    permission_calculator,
)
from app.trust.trust_score import (
    TrustScore,
    TrustScoreCalculator,
    TrustScoreConfig,
    trust_score_calculator,
)


# ===========================================================================
# DelegationContext
# ===========================================================================


class TestDelegationContextConstruction:
    def test_for_root_creates_single_hop_chain(self):
        ctx = DelegationContext.for_root("root-agent")
        assert ctx.root_principal == "root-agent"
        assert ctx.principal_chain == ("root-agent",)
        assert ctx.hop_count == 0
        assert ctx.current_agent == "root-agent"

    def test_for_root_with_permissions(self):
        ctx = DelegationContext.for_root("root", permissions=["read", "write"])
        assert ctx.root_permissions == frozenset({"read", "write"})

    def test_for_root_no_permissions_defaults_to_empty(self):
        ctx = DelegationContext.for_root("root")
        assert ctx.root_permissions == frozenset()

    def test_for_root_deduplicates_permissions(self):
        ctx = DelegationContext.for_root("root", permissions=["read", "read", "write"])
        assert ctx.root_permissions == frozenset({"read", "write"})

    def test_context_is_immutable(self):
        ctx = DelegationContext.for_root("root")
        with pytest.raises((TypeError, AttributeError)):
            ctx.root_principal = "changed"  # type: ignore[misc]


class TestDelegationContextHopCount:
    def test_root_has_zero_hops(self):
        ctx = DelegationContext.for_root("root")
        assert ctx.hop_count == 0

    def test_single_child_has_one_hop(self):
        ctx = DelegationContext.for_root("root").create_child("agent-1")
        assert ctx.hop_count == 1

    def test_two_hops(self):
        ctx = (
            DelegationContext.for_root("root")
            .create_child("agent-1")
            .create_child("agent-2")
        )
        assert ctx.hop_count == 2

    def test_five_hops(self):
        ctx = DelegationContext.for_root("root")
        for i in range(5):
            ctx = ctx.create_child(f"agent-{i}")
        assert ctx.hop_count == 5

    def test_current_agent_updates_with_chain(self):
        ctx = DelegationContext.for_root("root")
        assert ctx.current_agent == "root"
        ctx = ctx.create_child("child-1")
        assert ctx.current_agent == "child-1"
        ctx = ctx.create_child("child-2")
        assert ctx.current_agent == "child-2"


class TestDelegationContextChildCreation:
    def test_child_preserves_root_principal(self):
        root = DelegationContext.for_root("root-agent")
        child = root.create_child("child-agent")
        assert child.root_principal == "root-agent"

    def test_child_preserves_root_permissions(self):
        root = DelegationContext.for_root("root", permissions=["read", "write"])
        child = root.create_child("child")
        assert child.root_permissions == frozenset({"read", "write"})

    def test_child_chain_includes_parent(self):
        root = DelegationContext.for_root("root")
        child = root.create_child("child-1")
        grandchild = child.create_child("child-2")
        assert grandchild.principal_chain == ("root", "child-1", "child-2")

    def test_create_child_does_not_mutate_parent(self):
        root = DelegationContext.for_root("root")
        _ = root.create_child("child")
        assert root.hop_count == 0
        assert root.principal_chain == ("root",)


class TestDelegationContextSerialisation:
    def test_chain_as_list(self):
        ctx = DelegationContext.for_root("root").create_child("c1").create_child("c2")
        assert ctx.chain_as_list() == ["root", "c1", "c2"]

    def test_permissions_as_list_is_sorted(self):
        ctx = DelegationContext.for_root("root", permissions=["write", "read", "execute"])
        assert ctx.permissions_as_list() == ["execute", "read", "write"]

    def test_chain_as_list_is_not_the_internal_tuple(self):
        ctx = DelegationContext.for_root("root")
        lst = ctx.chain_as_list()
        lst.append("injected")
        assert len(ctx.principal_chain) == 1  # unchanged


# ===========================================================================
# TrustScoreConfig
# ===========================================================================


class TestTrustScoreConfig:
    def test_default_values(self):
        config = TrustScoreConfig()
        assert config.decay_rate == 0.15
        assert config.min_trust_threshold == 0.10
        assert config.max_hop_count == 10

    def test_valid_custom_config(self):
        config = TrustScoreConfig(decay_rate=0.2, min_trust_threshold=0.05, max_hop_count=5)
        assert config.decay_rate == 0.2

    def test_decay_rate_zero_raises(self):
        with pytest.raises(ValueError, match="decay_rate"):
            TrustScoreConfig(decay_rate=0.0)

    def test_decay_rate_one_raises(self):
        with pytest.raises(ValueError, match="decay_rate"):
            TrustScoreConfig(decay_rate=1.0)

    def test_decay_rate_negative_raises(self):
        with pytest.raises(ValueError, match="decay_rate"):
            TrustScoreConfig(decay_rate=-0.1)

    def test_min_trust_threshold_negative_raises(self):
        with pytest.raises(ValueError, match="min_trust_threshold"):
            TrustScoreConfig(min_trust_threshold=-0.1)

    def test_min_trust_threshold_one_raises(self):
        with pytest.raises(ValueError, match="min_trust_threshold"):
            TrustScoreConfig(min_trust_threshold=1.0)

    def test_min_trust_threshold_zero_is_valid(self):
        config = TrustScoreConfig(min_trust_threshold=0.0)
        assert config.min_trust_threshold == 0.0

    def test_max_hop_count_zero_raises(self):
        with pytest.raises(ValueError, match="max_hop_count"):
            TrustScoreConfig(max_hop_count=0)

    def test_max_hop_count_negative_raises(self):
        with pytest.raises(ValueError, match="max_hop_count"):
            TrustScoreConfig(max_hop_count=-1)


# ===========================================================================
# TrustScoreCalculator
# ===========================================================================


class TestTrustScoreCalculatorBasic:
    def test_root_has_full_trust(self):
        result = trust_score_calculator.calculate(0)
        assert result.score == 1.0
        assert result.hop_count == 0
        assert result.below_threshold is False
        assert result.max_hops_exceeded is False
        assert result.chain_must_terminate is False

    def test_negative_hop_count_raises(self):
        with pytest.raises(ValueError, match="hop_count"):
            trust_score_calculator.calculate(-1)

    def test_score_decreases_with_hops(self):
        scores = [trust_score_calculator.calculate(n).score for n in range(6)]
        for i in range(len(scores) - 1):
            assert scores[i] > scores[i + 1], f"score at hop {i} not > hop {i+1}"

    def test_score_clamped_to_zero(self):
        # Force a very high decay rate so score hits zero
        calc = TrustScoreCalculator(TrustScoreConfig(decay_rate=0.999, min_trust_threshold=0.0))
        result = calc.calculate(100)
        assert result.score >= 0.0

    def test_score_never_exceeds_one(self):
        for n in range(15):
            assert trust_score_calculator.calculate(n).score <= 1.0


class TestTrustScoreCalculatorDecay:
    def test_15_percent_decay_one_hop(self):
        calc = TrustScoreCalculator(TrustScoreConfig(decay_rate=0.15))
        result = calc.calculate(1)
        assert abs(result.score - 0.85) < 1e-9

    def test_15_percent_decay_two_hops(self):
        calc = TrustScoreCalculator(TrustScoreConfig(decay_rate=0.15))
        result = calc.calculate(2)
        expected = 0.85 ** 2
        assert abs(result.score - expected) < 1e-9

    def test_15_percent_decay_five_hops(self):
        calc = TrustScoreCalculator(TrustScoreConfig(decay_rate=0.15))
        result = calc.calculate(5)
        expected = 0.85 ** 5
        assert abs(result.score - expected) < 1e-9

    def test_custom_decay_rate(self):
        calc = TrustScoreCalculator(TrustScoreConfig(decay_rate=0.25))
        result = calc.calculate(3)
        expected = 0.75 ** 3
        assert abs(result.score - expected) < 1e-9


class TestTrustScoreTermination:
    def test_below_threshold_flag(self):
        config = TrustScoreConfig(decay_rate=0.5, min_trust_threshold=0.2)
        calc = TrustScoreCalculator(config)
        # hop 0: 1.0, hop 1: 0.5, hop 2: 0.25, hop 3: 0.125 < 0.2
        result = calc.calculate(3)
        assert result.below_threshold is True
        assert result.chain_must_terminate is True

    def test_above_threshold_flag(self):
        config = TrustScoreConfig(decay_rate=0.15, min_trust_threshold=0.10)
        calc = TrustScoreCalculator(config)
        result = calc.calculate(1)  # 0.85 > 0.10
        assert result.below_threshold is False

    def test_max_hops_exceeded_flag(self):
        config = TrustScoreConfig(max_hop_count=3)
        calc = TrustScoreCalculator(config)
        result = calc.calculate(4)
        assert result.max_hops_exceeded is True
        assert result.chain_must_terminate is True

    def test_at_max_hops_not_exceeded(self):
        config = TrustScoreConfig(max_hop_count=5)
        calc = TrustScoreCalculator(config)
        result = calc.calculate(5)
        assert result.max_hops_exceeded is False

    def test_chain_must_terminate_when_both_flags(self):
        config = TrustScoreConfig(decay_rate=0.9, min_trust_threshold=0.5, max_hop_count=2)
        calc = TrustScoreCalculator(config)
        result = calc.calculate(3)
        assert result.chain_must_terminate is True


class TestTrustScoreFromContext:
    def test_from_root_context(self):
        ctx = DelegationContext.for_root("root")
        result = trust_score_calculator.from_context(ctx)
        assert result.score == 1.0
        assert result.hop_count == 0

    def test_from_child_context(self):
        ctx = DelegationContext.for_root("root").create_child("child")
        result = trust_score_calculator.from_context(ctx)
        assert result.hop_count == 1
        assert abs(result.score - 0.85) < 1e-9

    def test_from_deep_chain(self):
        ctx = DelegationContext.for_root("root")
        for i in range(4):
            ctx = ctx.create_child(f"agent-{i}")
        result = trust_score_calculator.from_context(ctx)
        assert result.hop_count == 4
        expected = 0.85 ** 4
        assert abs(result.score - expected) < 1e-9


class TestHopsUntilTermination:
    def test_default_config_terminates_within_max_hops(self):
        n = trust_score_calculator.hops_until_termination()
        assert 1 <= n <= trust_score_calculator.config.max_hop_count + 1

    def test_higher_decay_terminates_sooner(self):
        low_decay = TrustScoreCalculator(TrustScoreConfig(decay_rate=0.15)).hops_until_termination()
        high_decay = TrustScoreCalculator(TrustScoreConfig(decay_rate=0.50)).hops_until_termination()
        assert high_decay <= low_decay

    def test_15_percent_decay_does_not_over_terminate_legitimate_chains(self):
        # Sprint S-E06 validation: default 15% decay must not terminate a
        # 5-hop LangGraph workflow (trust score at hop 5 = 0.85^5 ≈ 0.444).
        calc = TrustScoreCalculator(TrustScoreConfig(decay_rate=0.15, min_trust_threshold=0.10))
        for hop in range(1, 6):
            result = calc.calculate(hop)
            assert not result.chain_must_terminate, (
                f"Default decay prematurely terminates at hop {hop} "
                f"(score={result.score:.4f}, threshold=0.10)"
            )


# ===========================================================================
# EffectivePermissionCalculator
# ===========================================================================


class TestPermissionIntersection:
    def test_full_overlap(self):
        result = permission_calculator.compute(
            root_permissions=["read", "write"],
            requested_permissions=["read", "write"],
        )
        assert result.effective == frozenset({"read", "write"})
        assert result.escalated == frozenset()
        assert result.escalation_detected is False

    def test_no_overlap(self):
        result = permission_calculator.compute(
            root_permissions=["read"],
            requested_permissions=["write", "execute"],
        )
        assert result.effective == frozenset()
        assert result.escalated == frozenset({"write", "execute"})
        assert result.escalation_detected is True

    def test_partial_overlap(self):
        result = permission_calculator.compute(
            root_permissions=["read", "write"],
            requested_permissions=["read", "execute"],
        )
        assert result.effective == frozenset({"read"})
        assert result.escalated == frozenset({"execute"})
        assert result.escalation_detected is True

    def test_requested_subset_of_root(self):
        result = permission_calculator.compute(
            root_permissions=["read", "write", "execute"],
            requested_permissions=["read"],
        )
        assert result.effective == frozenset({"read"})
        assert result.escalated == frozenset()
        assert result.escalation_detected is False

    def test_empty_root_permissions(self):
        result = permission_calculator.compute(
            root_permissions=[],
            requested_permissions=["read", "write"],
        )
        assert result.effective == frozenset()
        assert result.escalated == frozenset({"read", "write"})
        assert result.escalation_detected is True

    def test_empty_requested_permissions(self):
        result = permission_calculator.compute(
            root_permissions=["read", "write"],
            requested_permissions=[],
        )
        assert result.effective == frozenset()
        assert result.escalated == frozenset()
        assert result.escalation_detected is False

    def test_both_empty(self):
        result = permission_calculator.compute(
            root_permissions=[],
            requested_permissions=[],
        )
        assert result.effective == frozenset()
        assert result.escalation_detected is False

    def test_accepts_frozenset_input(self):
        result = permission_calculator.compute(
            root_permissions=frozenset({"read"}),
            requested_permissions=frozenset({"read", "write"}),
        )
        assert result.escalation_detected is True
        assert result.escalated == frozenset({"write"})

    def test_accepts_set_input(self):
        result = permission_calculator.compute(
            root_permissions={"read"},
            requested_permissions={"read", "write"},
        )
        assert result.escalation_detected is True


class TestCheckEscalation:
    def test_no_escalation(self):
        assert permission_calculator.check_escalation(["read"], ["read"]) is False

    def test_escalation_detected(self):
        assert permission_calculator.check_escalation(["read"], ["read", "admin"]) is True

    def test_requested_is_subset(self):
        assert permission_calculator.check_escalation(["read", "write"], ["read"]) is False

    def test_completely_disjoint(self):
        assert permission_calculator.check_escalation(["read"], ["write"]) is True

    def test_empty_requested_no_escalation(self):
        assert permission_calculator.check_escalation(["read"], []) is False

    def test_empty_root_any_request_is_escalation(self):
        assert permission_calculator.check_escalation([], ["read"]) is True

    def test_both_empty_no_escalation(self):
        assert permission_calculator.check_escalation([], []) is False


class TestEffectiveOnly:
    def test_returns_intersection(self):
        result = permission_calculator.effective_only(
            root_permissions=["a", "b", "c"],
            requested_permissions=["b", "c", "d"],
        )
        assert result == frozenset({"b", "c"})

    def test_empty_result_when_disjoint(self):
        result = permission_calculator.effective_only(["x"], ["y"])
        assert result == frozenset()


# ===========================================================================
# TRUST_VIOLATION event
# ===========================================================================


class TestTrustViolationEvent:
    def test_permission_escalation_event_structure(self, caplog):
        with caplog.at_level(logging.ERROR):
            event = emit_trust_violation_event(
                reason=TrustViolationReason.PERMISSION_ESCALATION,
                detail="Agent claimed execute_shell beyond root permissions",
                principal_chain=["root", "child-1"],
                hop_count=1,
                trust_score=0.85,
                root_principal="root",
                agent_id="child-1",
                session_id="sess-001",
                request_id="req-001",
                tool_name="shell.exec",
                escalated_permissions=["execute_shell"],
            )

        assert event["class_name"] == "TRUST_VIOLATION"
        assert event["decision"] == "DENY"
        assert event["trust_enforcement_fail_closed"] is True
        assert event["finding_info"]["reason"] == "PERMISSION_ESCALATION"
        assert event["finding_info"]["hop_count"] == 1
        assert event["finding_info"]["trust_score"] == 0.85
        assert "execute_shell" in event["finding_info"]["escalated_permissions"]
        assert event["actor"]["principal_chain"] == ["root", "child-1"]
        assert any("TRUST_VIOLATION" in r.message for r in caplog.records)

    def test_trust_below_threshold_event(self):
        event = emit_trust_violation_event(
            reason=TrustViolationReason.TRUST_BELOW_THRESHOLD,
            detail="Trust score 0.05 below threshold 0.10",
            principal_chain=["root", "a", "b", "c", "d"],
            hop_count=4,
            trust_score=0.05,
        )
        assert event["finding_info"]["reason"] == "TRUST_BELOW_THRESHOLD"
        assert event["finding_info"]["trust_score"] == 0.05

    def test_max_hop_count_exceeded_event(self):
        chain = ["root"] + [f"agent-{i}" for i in range(11)]
        event = emit_trust_violation_event(
            reason=TrustViolationReason.MAX_HOP_COUNT_EXCEEDED,
            detail="Hop count 11 exceeds maximum 10",
            principal_chain=chain,
            hop_count=11,
            trust_score=0.15,
        )
        assert event["finding_info"]["reason"] == "MAX_HOP_COUNT_EXCEEDED"
        assert event["finding_info"]["hop_count"] == 11

    def test_invalid_delegation_chain_event(self):
        event = emit_trust_violation_event(
            reason=TrustViolationReason.INVALID_DELEGATION_CHAIN,
            detail="Empty principal chain",
            principal_chain=[],
            hop_count=0,
            trust_score=1.0,
        )
        assert event["finding_info"]["reason"] == "INVALID_DELEGATION_CHAIN"

    def test_ocsf_required_fields_present(self):
        event = emit_trust_violation_event(
            reason=TrustViolationReason.PERMISSION_ESCALATION,
            detail="test",
            principal_chain=["root"],
            hop_count=0,
            trust_score=1.0,
        )
        for required in (
            "class_uid", "class_name", "category_uid", "severity_id",
            "time", "metadata", "actor", "finding_info", "decision",
        ):
            assert required in event, f"Missing OCSF field: {required}"

    def test_severity_is_critical(self):
        event = emit_trust_violation_event(
            reason=TrustViolationReason.PERMISSION_ESCALATION,
            detail="test",
            principal_chain=["root"],
            hop_count=0,
            trust_score=1.0,
        )
        assert event["severity"] == "CRITICAL"
        assert event["severity_id"] == 5

    def test_escalated_permissions_defaults_to_empty_list(self):
        event = emit_trust_violation_event(
            reason=TrustViolationReason.TRUST_BELOW_THRESHOLD,
            detail="test",
            principal_chain=["root"],
            hop_count=0,
            trust_score=0.05,
        )
        assert event["finding_info"]["escalated_permissions"] == []

    def test_all_reason_codes_are_valid_enum_members(self):
        for reason in TrustViolationReason:
            event = emit_trust_violation_event(
                reason=reason,
                detail="test",
                principal_chain=["root"],
                hop_count=0,
                trust_score=1.0,
            )
            assert event["finding_info"]["reason"] == reason.value


# ===========================================================================
# AuthorizationRequest — delegation_context integration (E06-T04)
# ===========================================================================


class TestRequestBuilderDelegationContext:
    def _make_builder(self):
        from app.pdp.request_builder import AuthorizationRequestBuilder
        return AuthorizationRequestBuilder()

    def test_delegation_context_sets_chain(self):
        builder = self._make_builder()
        ctx = DelegationContext.for_root("root").create_child("child-1")
        req = builder.build("shell.exec", {}, delegation_context=ctx)
        assert req.principal_chain == ["root", "child-1"]

    def test_delegation_context_computes_trust_score(self):
        builder = self._make_builder()
        ctx = DelegationContext.for_root("root").create_child("child-1")
        req = builder.build("tool", {}, delegation_context=ctx)
        expected = 0.85 ** 1
        assert abs(req.trust_score - expected) < 1e-9

    def test_delegation_context_sets_hop_count(self):
        builder = self._make_builder()
        ctx = (
            DelegationContext.for_root("root")
            .create_child("c1")
            .create_child("c2")
        )
        req = builder.build("tool", {}, delegation_context=ctx)
        assert req.delegation_hop_count == 2

    def test_delegation_context_overrides_explicit_trust_score(self):
        builder = self._make_builder()
        ctx = DelegationContext.for_root("root").create_child("c1")
        # Explicit trust_score=1.0 should be ignored in favour of computed value
        req = builder.build("tool", {}, trust_score=1.0, delegation_context=ctx)
        expected = 0.85 ** 1
        assert abs(req.trust_score - expected) < 1e-9

    def test_delegation_context_overrides_explicit_chain(self):
        builder = self._make_builder()
        ctx = DelegationContext.for_root("root").create_child("real-child")
        req = builder.build(
            "tool", {},
            principal_chain=["wrong", "chain"],
            delegation_context=ctx,
        )
        assert req.principal_chain == ["root", "real-child"]

    def test_root_context_has_full_trust(self):
        builder = self._make_builder()
        ctx = DelegationContext.for_root("root")
        req = builder.build("tool", {}, delegation_context=ctx)
        assert req.trust_score == 1.0
        assert req.delegation_hop_count == 0

    def test_without_delegation_context_hop_count_derived_from_chain(self):
        builder = self._make_builder()
        req = builder.build("tool", {}, principal_chain=["root", "c1", "c2"])
        assert req.delegation_hop_count == 2

    def test_single_agent_chain_hop_count_is_zero(self):
        builder = self._make_builder()
        req = builder.build("tool", {}, agent_id="solo-agent")
        assert req.delegation_hop_count == 0

    def test_delegation_hop_count_in_opa_input(self):
        builder = self._make_builder()
        ctx = DelegationContext.for_root("root").create_child("c1")
        req = builder.build("tool", {}, delegation_context=ctx)
        opa_input = req.to_opa_input()
        assert "delegation_hop_count" in opa_input
        assert opa_input["delegation_hop_count"] == 1


# ===========================================================================
# Integration: full delegation chain → OPA input round-trip
# ===========================================================================


class TestEndToEndDelegationChain:
    def test_three_hop_chain_opa_input(self):
        from app.pdp.request_builder import AuthorizationRequestBuilder
        builder = AuthorizationRequestBuilder()

        ctx = (
            DelegationContext.for_root("human-operator", permissions=["read", "write"])
            .create_child("orchestrator")
            .create_child("sub-agent")
        )

        req = builder.build(
            tool_name="read_file",
            tool_args={"path": "/etc/config.yaml"},
            session_id="sess-e2e",
            delegation_context=ctx,
        )

        opa_input = req.to_opa_input()

        assert opa_input["principal_chain"] == ["human-operator", "orchestrator", "sub-agent"]
        assert opa_input["delegation_hop_count"] == 2
        expected_trust = 0.85 ** 2
        assert abs(opa_input["trust_score"] - expected_trust) < 1e-9
        assert opa_input["tool_name"] == "read_file"
        assert opa_input["session_id"] == "sess-e2e"

    def test_permission_intersection_respects_root_limit(self):
        ctx = DelegationContext.for_root("root", permissions=["read", "write"])
        result = permission_calculator.compute(
            root_permissions=ctx.root_permissions,
            requested_permissions={"read", "write", "admin"},
        )
        assert result.effective == frozenset({"read", "write"})
        assert result.escalated == frozenset({"admin"})
        assert result.escalation_detected is True

    def test_trust_score_monotonically_decreasing_through_chain(self):
        ctx = DelegationContext.for_root("root")
        prev_score = 1.0
        for i in range(8):
            ctx = ctx.create_child(f"agent-{i}")
            score = trust_score_calculator.from_context(ctx).score
            assert score < prev_score, f"Score did not decrease at hop {i + 1}"
            prev_score = score
