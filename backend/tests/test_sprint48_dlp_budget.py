"""Unit tests for Sprint 48 — MCP Session DLP Budget (APEP-385).

Tests the MCPSessionDLPBudgetTracker for:
  - Budget creation with configurable limits
  - Finding recording and threshold checks
  - Byte tracking for inbound/outbound data
  - Budget exceeded detection
  - Session cleanup
"""

import pytest

from app.models.mcp_security import MCPDLPFinding
from app.services.mcp_session_dlp_budget import (
    MCPSessionDLPBudgetTracker,
    mcp_session_dlp_budget_tracker,
)


@pytest.fixture
def tracker():
    return MCPSessionDLPBudgetTracker()


def _make_finding(severity: str = "MEDIUM", rule_id: str = "DLP-001") -> MCPDLPFinding:
    return MCPDLPFinding(
        rule_id=rule_id,
        severity=severity,
        description="Test finding",
        matched_field="test",
    )


class TestDLPBudgetCreation:
    def test_create_budget(self, tracker):
        budget = tracker.create_budget("sess-001", "agent-001")
        assert budget.session_id == "sess-001"
        assert budget.agent_id == "agent-001"
        assert budget.max_dlp_findings == 10
        assert budget.max_critical_findings == 3
        assert not budget.budget_exceeded

    def test_create_custom_budget(self, tracker):
        budget = tracker.create_budget(
            "sess-002",
            "agent-001",
            max_dlp_findings=5,
            max_critical_findings=1,
            max_outbound_bytes=1000,
            max_inbound_bytes=2000,
        )
        assert budget.max_dlp_findings == 5
        assert budget.max_critical_findings == 1
        assert budget.max_outbound_bytes_scanned == 1000
        assert budget.max_inbound_bytes_scanned == 2000

    def test_get_budget(self, tracker):
        tracker.create_budget("sess-003", "agent-001")
        budget = tracker.get_budget("sess-003")
        assert budget is not None
        assert budget.session_id == "sess-003"

    def test_get_nonexistent_budget(self, tracker):
        budget = tracker.get_budget("nonexistent")
        assert budget is None


class TestFindingRecording:
    def test_record_findings(self, tracker):
        tracker.create_budget("sess-010", "agent-001", max_dlp_findings=5)

        findings = [_make_finding("MEDIUM"), _make_finding("HIGH")]
        budget = tracker.record_findings("sess-010", findings)
        assert budget is not None
        assert budget.current_dlp_findings == 2
        assert not budget.budget_exceeded

    def test_budget_exceeded_by_findings(self, tracker):
        tracker.create_budget("sess-011", "agent-001", max_dlp_findings=3)

        findings = [_make_finding() for _ in range(3)]
        budget = tracker.record_findings("sess-011", findings)
        assert budget is not None
        assert budget.budget_exceeded
        assert "finding count" in budget.exceeded_reason.lower()

    def test_budget_exceeded_by_critical(self, tracker):
        tracker.create_budget("sess-012", "agent-001", max_critical_findings=2)

        findings = [_make_finding("CRITICAL"), _make_finding("CRITICAL")]
        budget = tracker.record_findings("sess-012", findings)
        assert budget is not None
        assert budget.budget_exceeded
        assert "CRITICAL" in budget.exceeded_reason

    def test_record_findings_nonexistent_session(self, tracker):
        result = tracker.record_findings("nonexistent", [_make_finding()])
        assert result is None

    def test_incremental_findings(self, tracker):
        tracker.create_budget("sess-013", "agent-001", max_dlp_findings=5)

        tracker.record_findings("sess-013", [_make_finding()])
        tracker.record_findings("sess-013", [_make_finding(), _make_finding()])

        budget = tracker.get_budget("sess-013")
        assert budget is not None
        assert budget.current_dlp_findings == 3


class TestByteTracking:
    def test_record_outbound_bytes(self, tracker):
        tracker.create_budget("sess-020", "agent-001", max_outbound_bytes=1000)

        budget = tracker.record_bytes_scanned("sess-020", outbound_bytes=500)
        assert budget is not None
        assert budget.outbound_bytes_scanned == 500
        assert not budget.budget_exceeded

    def test_outbound_budget_exceeded(self, tracker):
        tracker.create_budget("sess-021", "agent-001", max_outbound_bytes=1000)

        budget = tracker.record_bytes_scanned("sess-021", outbound_bytes=1000)
        assert budget is not None
        assert budget.budget_exceeded
        assert "outbound" in budget.exceeded_reason.lower()

    def test_inbound_budget_exceeded(self, tracker):
        tracker.create_budget("sess-022", "agent-001", max_inbound_bytes=500)

        budget = tracker.record_bytes_scanned("sess-022", inbound_bytes=500)
        assert budget is not None
        assert budget.budget_exceeded

    def test_combined_bytes(self, tracker):
        tracker.create_budget(
            "sess-023", "agent-001",
            max_outbound_bytes=10000,
            max_inbound_bytes=10000,
        )
        tracker.record_bytes_scanned("sess-023", outbound_bytes=300, inbound_bytes=200)
        budget = tracker.get_budget("sess-023")
        assert budget is not None
        assert budget.outbound_bytes_scanned == 300
        assert budget.inbound_bytes_scanned == 200


class TestExceededCheck:
    def test_is_exceeded_false(self, tracker):
        tracker.create_budget("sess-030", "agent-001")
        assert not tracker.is_exceeded("sess-030")

    def test_is_exceeded_true(self, tracker):
        tracker.create_budget("sess-031", "agent-001", max_dlp_findings=1)
        tracker.record_findings("sess-031", [_make_finding()])
        assert tracker.is_exceeded("sess-031")

    def test_is_exceeded_nonexistent(self, tracker):
        assert not tracker.is_exceeded("nonexistent")

    def test_exceeded_stays_exceeded(self, tracker):
        """Once exceeded, budget stays exceeded."""
        tracker.create_budget("sess-032", "agent-001", max_dlp_findings=1)
        tracker.record_findings("sess-032", [_make_finding()])
        assert tracker.is_exceeded("sess-032")

        # Even if no more findings are added
        budget = tracker.get_budget("sess-032")
        assert budget is not None
        assert budget.budget_exceeded


class TestSessionCleanup:
    def test_remove_budget(self, tracker):
        tracker.create_budget("sess-040", "agent-001")
        tracker.remove_budget("sess-040")
        assert tracker.get_budget("sess-040") is None
        assert not tracker.is_exceeded("sess-040")

    def test_remove_nonexistent(self, tracker):
        # Should not raise
        tracker.remove_budget("nonexistent")


class TestModuleSingleton:
    def test_singleton_exists(self):
        assert mcp_session_dlp_budget_tracker is not None
