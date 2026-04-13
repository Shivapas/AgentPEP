"""Tests for Sprint 33 foundation — DEFER & MODIFY decision types.

Verifies that new decision enum values, response fields, and exceptions
work correctly and are backward-compatible with existing decisions.
"""

from uuid import uuid4

import pytest

from app.models.policy import Decision, PolicyDecisionResponse


class TestDecisionEnum:
    """Verify DEFER and MODIFY are valid Decision values."""

    def test_defer_value(self) -> None:
        assert Decision.DEFER == "DEFER"
        assert Decision.DEFER.value == "DEFER"

    def test_modify_value(self) -> None:
        assert Decision.MODIFY == "MODIFY"
        assert Decision.MODIFY.value == "MODIFY"

    def test_all_decisions_present(self) -> None:
        expected = {"ALLOW", "DENY", "ESCALATE", "DRY_RUN", "TIMEOUT", "DEFER", "MODIFY"}
        actual = {d.value for d in Decision}
        assert actual == expected

    def test_decision_from_string(self) -> None:
        assert Decision("DEFER") == Decision.DEFER
        assert Decision("MODIFY") == Decision.MODIFY


class TestPolicyDecisionResponseNewFields:
    """Verify modified_args and defer_timeout_s fields."""

    def test_modify_decision_with_modified_args(self) -> None:
        resp = PolicyDecisionResponse(
            request_id=uuid4(),
            decision=Decision.MODIFY,
            modified_args={"path": "/safe/dir", "mode": "read"},
            reason="Arguments rewritten for safety",
        )
        assert resp.decision == Decision.MODIFY
        assert resp.modified_args == {"path": "/safe/dir", "mode": "read"}

    def test_defer_decision_with_timeout(self) -> None:
        resp = PolicyDecisionResponse(
            request_id=uuid4(),
            decision=Decision.DEFER,
            defer_timeout_s=30,
            reason="Awaiting human approval",
        )
        assert resp.decision == Decision.DEFER
        assert resp.defer_timeout_s == 30

    def test_default_defer_timeout(self) -> None:
        resp = PolicyDecisionResponse(
            request_id=uuid4(),
            decision=Decision.DEFER,
        )
        assert resp.defer_timeout_s == 60

    def test_modified_args_default_none(self) -> None:
        resp = PolicyDecisionResponse(
            request_id=uuid4(),
            decision=Decision.ALLOW,
        )
        assert resp.modified_args is None

    def test_serialization_roundtrip(self) -> None:
        resp = PolicyDecisionResponse(
            request_id=uuid4(),
            decision=Decision.MODIFY,
            modified_args={"key": "value"},
            defer_timeout_s=45,
            risk_score=0.3,
        )
        data = resp.model_dump(mode="json")
        assert data["decision"] == "MODIFY"
        assert data["modified_args"] == {"key": "value"}
        assert data["defer_timeout_s"] == 45

        # Round-trip
        restored = PolicyDecisionResponse.model_validate(data)
        assert restored.decision == Decision.MODIFY
        assert restored.modified_args == {"key": "value"}
        assert restored.defer_timeout_s == 45


class TestBackwardCompatibility:
    """Ensure existing decision types still work unchanged."""

    @pytest.mark.parametrize(
        "decision",
        [Decision.ALLOW, Decision.DENY, Decision.ESCALATE, Decision.DRY_RUN, Decision.TIMEOUT],
    )
    def test_existing_decisions_unchanged(self, decision: Decision) -> None:
        resp = PolicyDecisionResponse(
            request_id=uuid4(),
            decision=decision,
            reason="test",
        )
        assert resp.decision == decision
        assert resp.modified_args is None
        assert resp.defer_timeout_s == 60  # default, harmless for non-DEFER

    def test_allow_with_execution_token(self) -> None:
        resp = PolicyDecisionResponse(
            request_id=uuid4(),
            decision=Decision.ALLOW,
            execution_token="tok|123|abc|agent|tool|sess|1|hmac|sig",
            receipt="agentpep-receipt-v1|default|hmac-sha256|hash|sig",
        )
        assert resp.execution_token is not None
        assert resp.receipt is not None
        assert resp.modified_args is None
