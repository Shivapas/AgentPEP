"""Sprint 22 — Compliance Reports & SIEM Integration tests (APEP-172..179).

Validates:
- DPDPA report generation against regulatory checklist
- GDPR Art. 25 Privacy by Design report template
- CERT-In BOM agent activity report
- Splunk HEC forwarder event batching and envelope
- Elasticsearch writer bulk payload formation
- Report scheduler schedule management
- Compliance API endpoints
"""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from app.db.mongodb import AUDIT_DECISIONS, SECURITY_ALERTS, TAINT_AUDIT_EVENTS
from app.main import app
from app.models.compliance import ReportSchedule, ReportStatus, ReportType, ScheduleFrequency
from app.services.compliance.certin_report import generate_certin_bom_report
from app.services.compliance.dpdpa_report import generate_dpdpa_report
from app.services.compliance.elastic_writer import ElasticsearchConfig, ElasticsearchWriter
from app.services.compliance.gdpr_report import generate_gdpr_art25_report
from app.services.compliance.report_scheduler import (
    create_schedule,
    delete_schedule,
    generate_report,
    get_report,
    list_reports,
    list_schedules,
)
from app.services.compliance.splunk_forwarder import SplunkHECConfig, SplunkHECForwarder

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = datetime.now(UTC)
PERIOD_START = NOW - timedelta(days=7)
PERIOD_END = NOW


def _decision_doc(
    decision: str = "ALLOW",
    agent_id: str = "agent-1",
    tool_name: str = "read_file",
    risk_score: float = 0.3,
    taint_flags: list[str] | None = None,
    agent_role: str = "reader",
) -> dict:
    return {
        "decision_id": str(uuid4()),
        "session_id": "sess-1",
        "agent_id": agent_id,
        "agent_role": agent_role,
        "tool_name": tool_name,
        "tool_args_hash": "abc123",
        "taint_flags": taint_flags or [],
        "risk_score": risk_score,
        "delegation_chain": [],
        "matched_rule_id": str(uuid4()),
        "decision": decision,
        "latency_ms": 5,
        "timestamp": NOW - timedelta(hours=1),
        "reason": "policy match" if decision != "DENY" else "risk threshold exceeded",
    }


def _taint_event_doc(event_type: str = "TAINT_ASSIGNED") -> dict:
    return {
        "event_id": str(uuid4()),
        "event_type": event_type,
        "session_id": "sess-1",
        "node_id": str(uuid4()),
        "agent_id": "agent-1",
        "taint_level": "UNTRUSTED",
        "source": "WEB",
        "propagated_from": [],
        "timestamp": NOW - timedelta(hours=1),
    }


def _security_alert_doc(
    severity: str = "HIGH",
    alert_type: str = "PRIVILEGE_ESCALATION",
) -> dict:
    return {
        "alert_id": str(uuid4()),
        "alert_type": alert_type,
        "session_id": "sess-1",
        "agent_id": "agent-1",
        "tool_name": "delete_file",
        "detail": "Agent attempted privilege escalation",
        "severity": severity,
        "delegation_chain": [],
        "timestamp": NOW - timedelta(hours=1),
    }


async def _seed_data(db) -> None:
    """Insert sample audit decisions, taint events, and security alerts."""
    decisions = db[AUDIT_DECISIONS]
    await decisions.insert_many(
        [
            _decision_doc("ALLOW", "agent-1", "read_file", 0.2, ["UNTRUSTED"]),
            _decision_doc("ALLOW", "agent-2", "write_file", 0.4),
            _decision_doc("DENY", "agent-1", "delete_file", 0.9),
            _decision_doc("DENY", "agent-3", "exec_command", 0.95),
            _decision_doc("ESCALATE", "agent-2", "send_email", 0.7),
        ]
    )

    taint_events = db[TAINT_AUDIT_EVENTS]
    await taint_events.insert_many(
        [
            _taint_event_doc("TAINT_ASSIGNED"),
            _taint_event_doc("TAINT_QUARANTINED"),
            _taint_event_doc("CROSS_AGENT_PROPAGATED"),
            _taint_event_doc("TAINT_DOWNGRADED"),
        ]
    )

    alerts = db[SECURITY_ALERTS]
    await alerts.insert_many(
        [
            _security_alert_doc("CRITICAL", "PRIVILEGE_ESCALATION"),
            _security_alert_doc("HIGH", "CHAIN_DEPTH_EXCEEDED"),
            _security_alert_doc("MEDIUM", "UNAUTHORIZED_DELEGATION"),
        ]
    )


# ---------------------------------------------------------------------------
# APEP-172: DPDPA Report
# ---------------------------------------------------------------------------


class TestDPDPAReport:
    """Validate DPDPA compliance report against regulatory checklist."""

    async def test_dpdpa_report_structure(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_dpdpa_report(PERIOD_START, PERIOD_END)

        assert report.report_type == ReportType.DPDPA
        assert report.status == ReportStatus.COMPLETED
        assert "data_processing_summary" in report.content
        assert "taint_event_summary" in report.content
        assert "deny_log" in report.content

    async def test_dpdpa_data_processing_counts(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_dpdpa_report(PERIOD_START, PERIOD_END)
        summary = report.content["data_processing_summary"]

        assert summary["total_decisions"] == 5
        assert summary["allow_count"] == 2
        assert summary["deny_count"] == 2
        assert summary["escalate_count"] == 1
        assert summary["unique_agents"] == 3

    async def test_dpdpa_taint_summary(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_dpdpa_report(PERIOD_START, PERIOD_END)
        taint = report.content["taint_event_summary"]

        assert taint["total_taint_events"] == 4
        assert taint["quarantine_events"] == 1
        assert taint["cross_agent_propagations"] == 1
        assert taint["sanitisation_events"] == 1

    async def test_dpdpa_deny_log_entries(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_dpdpa_report(PERIOD_START, PERIOD_END)
        deny_log = report.content["deny_log"]

        assert len(deny_log) == 2
        for entry in deny_log:
            assert "decision_id" in entry
            assert "agent_id" in entry
            assert "tool_name" in entry
            assert "risk_score" in entry

    async def test_dpdpa_empty_period(self, mock_mongodb):
        """Report for period with no data should still complete."""
        far_past = NOW - timedelta(days=365)
        report = await generate_dpdpa_report(far_past, far_past + timedelta(days=1))
        assert report.status == ReportStatus.COMPLETED
        assert report.content["data_processing_summary"]["total_decisions"] == 0


# ---------------------------------------------------------------------------
# APEP-173: GDPR Art. 25 Report
# ---------------------------------------------------------------------------


class TestGDPRArt25Report:
    """Validate GDPR Art. 25 Privacy by Design report template."""

    async def test_gdpr_report_structure(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_gdpr_art25_report(PERIOD_START, PERIOD_END)

        assert report.report_type == ReportType.GDPR_ART25
        assert report.status == ReportStatus.COMPLETED
        assert "privacy_by_design_controls" in report.content
        assert "data_minimisation" in report.content
        assert "access_control_summary" in report.content

    async def test_gdpr_pbd_controls_present(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_gdpr_art25_report(PERIOD_START, PERIOD_END)
        controls = report.content["privacy_by_design_controls"]

        # All 8 PbD controls should be listed
        assert len(controls) == 8
        control_ids = {c["control_id"] for c in controls}
        expected = {f"PbD-0{i}" for i in range(1, 9)}
        assert control_ids == expected

    async def test_gdpr_data_minimisation_metrics(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_gdpr_art25_report(PERIOD_START, PERIOD_END)
        minimisation = report.content["data_minimisation"]

        assert minimisation["total_tool_calls"] == 5
        assert minimisation["denied_for_excessive_data"] == 2  # 2 DENY decisions

    async def test_gdpr_access_control_summary(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_gdpr_art25_report(PERIOD_START, PERIOD_END)
        acs = report.content["access_control_summary"]

        assert acs["total_decisions_in_period"] == 5
        assert "role_distribution" in acs


# ---------------------------------------------------------------------------
# APEP-174: CERT-In BOM Report
# ---------------------------------------------------------------------------


class TestCERTInBOMReport:
    """Validate CERT-In BOM-aligned agent activity report."""

    async def test_certin_report_structure(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_certin_bom_report(PERIOD_START, PERIOD_END)

        assert report.report_type == ReportType.CERT_IN_BOM
        assert report.status == ReportStatus.COMPLETED
        assert "agent_bill_of_materials" in report.content
        assert "security_alert_summary" in report.content
        assert "incident_timeline" in report.content

    async def test_certin_agent_bom_entries(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_certin_bom_report(PERIOD_START, PERIOD_END)
        bom = report.content["agent_bill_of_materials"]

        # 3 unique agents in seed data
        assert len(bom) == 3
        agent_ids = {entry["agent_id"] for entry in bom}
        assert agent_ids == {"agent-1", "agent-2", "agent-3"}

    async def test_certin_security_alert_summary(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_certin_bom_report(PERIOD_START, PERIOD_END)
        alerts = report.content["security_alert_summary"]

        assert alerts["total_alerts"] == 3
        assert alerts["critical_alerts"] == 1
        assert alerts["high_alerts"] == 1
        assert alerts["medium_alerts"] == 1

    async def test_certin_incident_timeline(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_certin_bom_report(PERIOD_START, PERIOD_END)
        timeline = report.content["incident_timeline"]

        assert len(timeline) == 3
        for event in timeline:
            assert "alert_type" in event
            assert "severity" in event
            assert "timestamp" in event


# ---------------------------------------------------------------------------
# APEP-175: Splunk HEC Forwarder
# ---------------------------------------------------------------------------


class TestSplunkHECForwarder:
    """Validate Splunk HEC event envelope and batching logic."""

    def test_hec_event_envelope(self):
        config = SplunkHECConfig(
            hec_url="https://splunk.example.com:8088/services/collector",
            hec_token="test-token",
            index="agentpep",
        )
        forwarder = SplunkHECForwarder(config)
        decision = {"decision": "ALLOW", "agent_id": "a1", "timestamp": 1700000000}
        event = forwarder._build_hec_event(decision)

        assert event["source"] == "agentpep-engine"
        assert event["sourcetype"] == "agentpep:decision"
        assert event["index"] == "agentpep"
        assert event["event"] == decision

    async def test_buffer_batching(self):
        config = SplunkHECConfig(batch_size=3)
        forwarder = SplunkHECForwarder(config)

        await forwarder.send_event({"d": 1})
        await forwarder.send_event({"d": 2})
        assert forwarder.buffer_size == 2

        # Third event triggers flush (but no HEC configured, so buffer clears)
        await forwarder.send_event({"d": 3})
        assert forwarder.buffer_size == 0

    async def test_flush_without_config_clears_buffer(self):
        forwarder = SplunkHECForwarder()  # No HEC URL
        await forwarder.send_event({"d": 1})
        await forwarder.flush()
        assert forwarder.buffer_size == 0


# ---------------------------------------------------------------------------
# APEP-176: Elasticsearch Writer
# ---------------------------------------------------------------------------


class TestElasticsearchWriter:
    """Validate Elasticsearch bulk payload formation and batching."""

    def test_document_preparation(self):
        config = ElasticsearchConfig(index_name="test-index")
        writer = ElasticsearchWriter(config)
        doc = writer._prepare_document(
            {"decision": "DENY", "agent_id": "a1", "timestamp": "2024-01-01T00:00:00Z"}
        )

        assert "@timestamp" in doc
        assert doc["decision"] == "DENY"

    async def test_buffer_batching(self):
        config = ElasticsearchConfig(batch_size=2)
        writer = ElasticsearchWriter(config)

        await writer.index_event({"d": 1})
        assert writer.buffer_size == 1

        # Second event triggers flush (no ES configured, clears buffer)
        await writer.index_event({"d": 2})
        assert writer.buffer_size == 0

    async def test_flush_without_config_clears_buffer(self):
        writer = ElasticsearchWriter()  # No ES URL
        await writer.index_event({"d": 1})
        await writer.flush()
        assert writer.buffer_size == 0


# ---------------------------------------------------------------------------
# APEP-177: Report Scheduler
# ---------------------------------------------------------------------------


class TestReportScheduler:
    """Validate schedule CRUD and report generation dispatch."""

    async def test_create_and_list_schedule(self, mock_mongodb):
        schedule = ReportSchedule(
            report_type=ReportType.DPDPA,
            frequency=ScheduleFrequency.WEEKLY,
            email_recipients=["admin@example.com"],
        )
        created = await create_schedule(schedule)
        assert created.next_run_at is not None

        schedules = await list_schedules()
        assert len(schedules) == 1
        assert schedules[0].report_type == ReportType.DPDPA

    async def test_delete_schedule(self, mock_mongodb):
        schedule = ReportSchedule(
            report_type=ReportType.GDPR_ART25,
            frequency=ScheduleFrequency.MONTHLY,
        )
        created = await create_schedule(schedule)

        deleted = await delete_schedule(created.schedule_id)
        assert deleted is True

        schedules = await list_schedules()
        assert len(schedules) == 0

    async def test_generate_and_retrieve_report(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        report = await generate_report(ReportType.DPDPA, PERIOD_START, PERIOD_END)

        assert report.status == ReportStatus.COMPLETED

        # Retrieve by ID
        fetched = await get_report(report.report_id)
        assert fetched is not None
        assert fetched.report_id == report.report_id

    async def test_list_reports_with_filter(self, mock_mongodb):
        await _seed_data(mock_mongodb)
        await generate_report(ReportType.DPDPA, PERIOD_START, PERIOD_END)
        await generate_report(ReportType.GDPR_ART25, PERIOD_START, PERIOD_END)

        all_reports, total = await list_reports()
        assert total == 2

        dpdpa_only, dpdpa_total = await list_reports(report_type=ReportType.DPDPA)
        assert dpdpa_total == 1
        assert dpdpa_only[0].report_type == ReportType.DPDPA


# ---------------------------------------------------------------------------
# APEP-178 & 179: API Endpoint Integration Tests
# ---------------------------------------------------------------------------


class TestComplianceAPI:
    """Integration tests for the compliance report API endpoints."""

    @pytest.fixture
    def client(self):
        from tests.conftest import _get_auth_headers

        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://test", headers=_get_auth_headers())

    async def test_generate_report_endpoint(self, mock_mongodb, client):
        await _seed_data(mock_mongodb)
        resp = await client.post(
            "/v1/compliance/reports",
            json={
                "report_type": "DPDPA",
                "period_start": PERIOD_START.isoformat(),
                "period_end": PERIOD_END.isoformat(),
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["report_type"] == "DPDPA"
        assert data["status"] == "COMPLETED"

    async def test_list_reports_endpoint(self, mock_mongodb, client):
        await _seed_data(mock_mongodb)
        # Generate a report first
        await client.post(
            "/v1/compliance/reports",
            json={
                "report_type": "GDPR_ART25",
                "period_start": PERIOD_START.isoformat(),
                "period_end": PERIOD_END.isoformat(),
            },
        )
        resp = await client.get("/v1/compliance/reports")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    async def test_download_report_endpoint(self, mock_mongodb, client):
        await _seed_data(mock_mongodb)
        gen_resp = await client.post(
            "/v1/compliance/reports",
            json={
                "report_type": "CERT_IN_BOM",
                "period_start": PERIOD_START.isoformat(),
                "period_end": PERIOD_END.isoformat(),
            },
        )
        report_id = gen_resp.json()["report_id"]

        dl_resp = await client.get(f"/v1/compliance/reports/{report_id}/download")
        assert dl_resp.status_code == 200
        assert "attachment" in dl_resp.headers.get("content-disposition", "")
        # Verify it's valid JSON
        content = json.loads(dl_resp.text)
        assert content["report_type"] == "CERT_IN_BOM"

    async def test_report_not_found(self, mock_mongodb, client):
        fake_id = str(uuid4())
        resp = await client.get(f"/v1/compliance/reports/{fake_id}")
        assert resp.status_code == 404

    async def test_create_schedule_endpoint(self, mock_mongodb, client):
        resp = await client.post(
            "/v1/compliance/schedules",
            json={
                "report_type": "DPDPA",
                "frequency": "WEEKLY",
                "email_recipients": ["admin@example.com"],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["frequency"] == "WEEKLY"
        assert data["next_run_at"] is not None

    async def test_list_and_delete_schedule_endpoint(self, mock_mongodb, client):
        create_resp = await client.post(
            "/v1/compliance/schedules",
            json={
                "report_type": "GDPR_ART25",
                "frequency": "MONTHLY",
                "email_recipients": [],
            },
        )
        schedule_id = create_resp.json()["schedule_id"]

        list_resp = await client.get("/v1/compliance/schedules")
        assert list_resp.status_code == 200
        assert len(list_resp.json()) >= 1

        del_resp = await client.delete(f"/v1/compliance/schedules/{schedule_id}")
        assert del_resp.status_code == 204


# ---------------------------------------------------------------------------
# APEP-179: Regulatory Checklist Validation
# ---------------------------------------------------------------------------


class TestRegulatoryChecklist:
    """Cross-cutting validation that reports meet regulatory requirements."""

    async def test_dpdpa_contains_all_required_sections(self, mock_mongodb):
        """DPDPA report must include processing summary, taint audit, and deny log."""
        await _seed_data(mock_mongodb)
        report = await generate_dpdpa_report(PERIOD_START, PERIOD_END)

        required_sections = ["data_processing_summary", "taint_event_summary", "deny_log"]
        for section in required_sections:
            assert section in report.content, f"Missing required DPDPA section: {section}"

    async def test_gdpr_art25_has_all_pbd_controls(self, mock_mongodb):
        """GDPR Art. 25 report must enumerate all 8 Privacy by Design controls."""
        await _seed_data(mock_mongodb)
        report = await generate_gdpr_art25_report(PERIOD_START, PERIOD_END)

        controls = report.content["privacy_by_design_controls"]
        assert len(controls) >= 8, "GDPR report must have at least 8 PbD controls"

        required_names = {
            "Purpose Limitation",
            "Data Minimisation",
            "Access Control",
            "Audit Trail",
            "Risk Assessment",
            "Delegation Control",
            "Injection Protection",
            "Fail-Safe Defaults",
        }
        actual_names = {c["control_name"] for c in controls}
        assert required_names.issubset(actual_names), (
            f"Missing PbD controls: {required_names - actual_names}"
        )

    async def test_certin_bom_has_all_required_sections(self, mock_mongodb):
        """CERT-In BOM report must include agent BOM, alerts, and timeline."""
        await _seed_data(mock_mongodb)
        report = await generate_certin_bom_report(PERIOD_START, PERIOD_END)

        required = ["agent_bill_of_materials", "security_alert_summary", "incident_timeline"]
        for section in required:
            assert section in report.content, f"Missing CERT-In section: {section}"

    async def test_all_reports_have_period_and_timestamp(self, mock_mongodb):
        """Every report must record its generation time and period."""
        await _seed_data(mock_mongodb)

        for gen_fn in [generate_dpdpa_report, generate_gdpr_art25_report, generate_certin_bom_report]:
            report = await gen_fn(PERIOD_START, PERIOD_END)
            assert report.generated_at is not None, f"{report.report_type} missing generated_at"
            assert report.period_start == PERIOD_START
            assert report.period_end == PERIOD_END

    async def test_deny_log_entries_have_required_fields(self, mock_mongodb):
        """Each DENY log entry must have decision_id, timestamp, agent, tool, risk."""
        await _seed_data(mock_mongodb)
        report = await generate_dpdpa_report(PERIOD_START, PERIOD_END)
        required_fields = {"decision_id", "timestamp", "agent_id", "tool_name", "risk_score"}

        for entry in report.content["deny_log"]:
            missing = required_fields - set(entry.keys())
            assert not missing, f"DENY log entry missing fields: {missing}"
