"""Tests for Sprint 32 — APEP-253: Configurable audit verbosity.

Verifies MINIMAL, STANDARD, and FULL verbosity filtering behaviour
and integration with the global settings.
"""

import copy

import pytest

from app.backends.audit_verbosity import AuditVerbosity, filter_record


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sample_record() -> dict:
    """Full audit decision record with all fields populated."""
    return {
        "decision_id": "d-001",
        "decision": "ALLOW",
        "timestamp": "2026-04-13T00:00:00Z",
        "sequence_number": 1,
        "record_hash": "abc123",
        "previous_hash": "genesis",
        "agent_id": "agent-1",
        "agent_role": "developer",
        "session_id": "sess-1",
        "tool_name": "file.read",
        "matched_rule_id": "rule-1",
        "risk_score": 0.2,
        "escalation_id": None,
        "tool_args_hash": "sha256-abc",
        "taint_flags": ["UNTRUSTED"],
        "delegation_chain": ["agent-0", "agent-1"],
        "latency_ms": 12,
    }


# ---------------------------------------------------------------------------
# APEP-253: Audit Verbosity Filtering
# ---------------------------------------------------------------------------


class TestAuditVerbosity:
    """Verify verbosity filter produces correct field subsets."""

    def test_minimal_filters_to_outcome_only(self):
        record = _sample_record()
        result = filter_record(record, AuditVerbosity.MINIMAL)

        expected_keys = {
            "decision_id",
            "decision",
            "timestamp",
            "sequence_number",
            "record_hash",
            "previous_hash",
        }
        assert set(result.keys()) == expected_keys
        assert result["decision"] == "ALLOW"
        assert result["decision_id"] == "d-001"

    def test_standard_includes_identity_and_scope(self):
        record = _sample_record()
        result = filter_record(record, AuditVerbosity.STANDARD)

        # Must include minimal fields
        assert "decision_id" in result
        assert "decision" in result
        assert "record_hash" in result

        # Must include identity + scope fields
        assert result["agent_id"] == "agent-1"
        assert result["session_id"] == "sess-1"
        assert result["tool_name"] == "file.read"
        assert result["risk_score"] == 0.2
        assert result["matched_rule_id"] == "rule-1"

        # Must NOT include FULL-only fields
        assert "tool_args_hash" not in result
        assert "taint_flags" not in result
        assert "delegation_chain" not in result
        assert "latency_ms" not in result

    def test_full_passes_all_fields(self):
        record = _sample_record()
        result = filter_record(record, AuditVerbosity.FULL)

        assert set(result.keys()) == set(record.keys())
        for key in record:
            assert result[key] == record[key]

    def test_full_preserves_unknown_extra_fields(self):
        record = _sample_record()
        record["custom_metadata"] = {"tenant": "acme"}
        result = filter_record(record, AuditVerbosity.FULL)

        assert result["custom_metadata"] == {"tenant": "acme"}

    def test_filter_returns_copy(self):
        """filter_record must not mutate the original record."""
        record = _sample_record()
        original = copy.deepcopy(record)
        result = filter_record(record, AuditVerbosity.MINIMAL)

        # Mutating the result must not affect the original
        result["decision_id"] = "MUTATED"
        assert record == original

    def test_filter_returns_copy_at_full(self):
        record = _sample_record()
        result = filter_record(record, AuditVerbosity.FULL)
        result["decision_id"] = "MUTATED"
        assert record["decision_id"] == "d-001"

    def test_verbosity_enum_values(self):
        assert AuditVerbosity.MINIMAL == "MINIMAL"
        assert AuditVerbosity.STANDARD == "STANDARD"
        assert AuditVerbosity.FULL == "FULL"


class TestAuditBackendVerbosityHelper:
    """Verify the filter_by_verbosity helper on the AuditBackend ABC."""

    def _make_concrete_backend(self):
        """Create a minimal concrete AuditBackend for testing."""
        from app.backends.audit import AuditBackend, IntegrityResult

        class StubBackend(AuditBackend):
            async def write_decision(self, record):
                return True

            async def query(self, filter, *, limit=100, offset=0):
                return []

            async def verify_integrity(self, *, start_sequence=1, end_sequence=None):
                return IntegrityResult(valid=True)

        return StubBackend()

    def test_filter_by_verbosity_uses_explicit_level(self):
        backend = self._make_concrete_backend()
        record = _sample_record()
        result = backend.filter_by_verbosity(record, AuditVerbosity.MINIMAL)
        assert "tool_args_hash" not in result
        assert "decision" in result

    def test_filter_by_verbosity_uses_settings_default(self, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "audit_verbosity", "STANDARD")
        backend = self._make_concrete_backend()
        record = _sample_record()
        result = backend.filter_by_verbosity(record)
        assert "agent_id" in result
        assert "tool_args_hash" not in result

    def test_filter_by_verbosity_full_from_settings(self, monkeypatch):
        from app.core.config import settings

        monkeypatch.setattr(settings, "audit_verbosity", "FULL")
        backend = self._make_concrete_backend()
        record = _sample_record()
        result = backend.filter_by_verbosity(record)
        assert set(result.keys()) == set(record.keys())
