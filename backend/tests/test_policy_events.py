"""Unit tests for agentpep/policy/events.py.

Sprint S-E03 — E03-T08a
Covers:
  - emit_security_violation_event returns correct OCSF structure
  - All SecurityViolationReason variants produce valid events
  - Required OCSF fields are present
  - decision is always DENY
  - policy_loader_fail_closed is always True
  - Contextual fields (source_url, bundle_version, session_id, agent_id) propagated
"""

from __future__ import annotations

import logging

import pytest

from app.policy.events import SecurityViolationReason, emit_security_violation_event


# ---------------------------------------------------------------------------
# OCSF structural tests
# ---------------------------------------------------------------------------


class TestSecurityViolationEventStructure:
    REQUIRED_OCSF_FIELDS = (
        "class_uid",
        "class_name",
        "category_uid",
        "category_name",
        "activity_id",
        "activity_name",
        "severity_id",
        "severity",
        "type_uid",
        "time",
        "metadata",
        "actor",
        "resources",
        "finding_info",
        "decision",
    )

    def _emit(self, reason=SecurityViolationReason.INVALID_SIGNATURE, **kwargs):
        return emit_security_violation_event(reason=reason, detail="test detail", **kwargs)

    def test_required_fields_present(self):
        event = self._emit()
        for field in self.REQUIRED_OCSF_FIELDS:
            assert field in event, f"Missing OCSF field: {field}"

    def test_class_name_is_security_violation(self):
        assert self._emit()["class_name"] == "SECURITY_VIOLATION"

    def test_decision_is_always_deny(self):
        for reason in SecurityViolationReason:
            event = self._emit(reason=reason)
            assert event["decision"] == "DENY", f"Expected DENY for {reason}"

    def test_fail_closed_flag_is_true(self):
        event = self._emit()
        assert event["policy_loader_fail_closed"] is True

    def test_severity_is_critical(self):
        event = self._emit()
        assert event["severity"] == "CRITICAL"
        assert event["severity_id"] == 5

    def test_metadata_contains_product(self):
        event = self._emit()
        assert event["metadata"]["product"]["name"] == "AgentPEP"
        assert event["metadata"]["product"]["vendor_name"] == "TrustFabric"

    def test_metadata_event_code(self):
        event = self._emit()
        assert event["metadata"]["event_code"] == "SECURITY_VIOLATION"

    def test_time_is_positive_integer(self):
        event = self._emit()
        assert isinstance(event["time"], int)
        assert event["time"] > 0


# ---------------------------------------------------------------------------
# Reason variants
# ---------------------------------------------------------------------------


class TestSecurityViolationReasons:
    def test_invalid_signature(self):
        event = emit_security_violation_event(
            reason=SecurityViolationReason.INVALID_SIGNATURE,
            detail="Signature mismatch",
        )
        assert event["finding_info"]["reason"] == "INVALID_SIGNATURE"

    def test_untrusted_source(self):
        event = emit_security_violation_event(
            reason=SecurityViolationReason.UNTRUSTED_SOURCE,
            detail="URL not allowlisted",
            source_url="file:///etc/passwd",
        )
        assert event["finding_info"]["reason"] == "UNTRUSTED_SOURCE"
        assert event["finding_info"]["source_url"] == "file:///etc/passwd"
        assert event["resources"][0]["name"] == "file:///etc/passwd"

    def test_env_var_override_attempt(self):
        event = emit_security_violation_event(
            reason=SecurityViolationReason.ENV_VAR_OVERRIDE_ATTEMPT,
            detail="AGENTPEP_POLICY_URL set",
        )
        assert event["finding_info"]["reason"] == "ENV_VAR_OVERRIDE_ATTEMPT"

    def test_signature_verification_error(self):
        event = emit_security_violation_event(
            reason=SecurityViolationReason.SIGNATURE_VERIFICATION_ERROR,
            detail="Unexpected error during verify",
        )
        assert event["finding_info"]["reason"] == "SIGNATURE_VERIFICATION_ERROR"

    def test_bundle_fetch_from_untrusted_host(self):
        event = emit_security_violation_event(
            reason=SecurityViolationReason.BUNDLE_FETCH_FROM_UNTRUSTED_HOST,
            detail="Redirected to external host",
        )
        assert event["finding_info"]["reason"] == "BUNDLE_FETCH_FROM_UNTRUSTED_HOST"


# ---------------------------------------------------------------------------
# Contextual field propagation
# ---------------------------------------------------------------------------


class TestContextualFields:
    def test_source_url_propagated(self):
        event = emit_security_violation_event(
            reason=SecurityViolationReason.INVALID_SIGNATURE,
            detail="sig bad",
            source_url="https://registry.trustfabric.internal/bundle.tar.gz",
        )
        assert event["finding_info"]["source_url"] == (
            "https://registry.trustfabric.internal/bundle.tar.gz"
        )

    def test_bundle_version_propagated(self):
        event = emit_security_violation_event(
            reason=SecurityViolationReason.INVALID_SIGNATURE,
            detail="sig bad",
            bundle_version="1.4.2",
        )
        assert event["finding_info"]["bundle_version"] == "1.4.2"
        assert event["resources"][0]["version"] == "1.4.2"

    def test_session_and_agent_propagated(self):
        event = emit_security_violation_event(
            reason=SecurityViolationReason.INVALID_SIGNATURE,
            detail="sig bad",
            session_id="sess-abc",
            agent_id="agent-xyz",
        )
        assert event["actor"]["session_id"] == "sess-abc"
        assert event["actor"]["agent_id"] == "agent-xyz"

    def test_request_id_propagated(self):
        event = emit_security_violation_event(
            reason=SecurityViolationReason.INVALID_SIGNATURE,
            detail="sig bad",
            request_id="req-001",
        )
        assert event["finding_info"]["uid"] == "req-001"

    def test_detail_propagated(self):
        event = emit_security_violation_event(
            reason=SecurityViolationReason.INVALID_SIGNATURE,
            detail="very specific reason text",
        )
        assert "very specific reason text" in event["finding_info"]["detail"]


# ---------------------------------------------------------------------------
# Logging side-effect
# ---------------------------------------------------------------------------


class TestSecurityViolationLogging:
    def test_event_logged_at_error_level(self, caplog):
        with caplog.at_level(logging.ERROR):
            emit_security_violation_event(
                reason=SecurityViolationReason.INVALID_SIGNATURE,
                detail="bad sig",
            )
        assert any("SECURITY_VIOLATION" in r.message for r in caplog.records)

    def test_returns_event_dict(self):
        result = emit_security_violation_event(
            reason=SecurityViolationReason.UNTRUSTED_SOURCE,
            detail="bad url",
        )
        assert isinstance(result, dict)
