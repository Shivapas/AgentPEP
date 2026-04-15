"""Sprint 56 — Unit tests for CIS scan results to compliance exports (APEP-448.c).

Tests cover:
  - JSON export with CIS_SECURITY template
  - CSV export with correct headers
  - Template listing
  - Query filtering by session, severity, scanner
  - Summary generation (by_severity, by_scanner, by_verdict)
  - Unknown template handling
"""

from __future__ import annotations

import pytest

from app.services.cis_compliance_export import (
    CISComplianceExporter,
    CISExportQuery,
    CIS_COMPLIANCE_TEMPLATES,
)


@pytest.fixture
def exporter():
    return CISComplianceExporter()


@pytest.fixture
async def seeded_db(mock_mongodb):
    """Seed MongoDB with CIS findings for export tests."""
    db = mock_mongodb
    collection = db["cis_findings"]
    await collection.insert_many([
        {
            "finding_id": "f-1",
            "timestamp": "2026-04-15T10:00:00Z",
            "session_id": "sess-exp-1",
            "scanner": "InjectionSignatureLibrary",
            "severity": "CRITICAL",
            "rule_id": "INJ-001",
            "description": "Prompt override detected",
            "file_path": "/repo/CLAUDE.md",
            "scan_mode": "STRICT",
            "verdict": "MALICIOUS",
            "taint_assigned": "QUARANTINE",
        },
        {
            "finding_id": "f-2",
            "timestamp": "2026-04-15T10:01:00Z",
            "session_id": "sess-exp-1",
            "scanner": "ONNXSemanticClassifier",
            "severity": "HIGH",
            "rule_id": "ONNX-SEMANTIC",
            "description": "Semantic injection detected",
            "file_path": None,
            "scan_mode": "STANDARD",
            "verdict": "SUSPICIOUS",
            "taint_assigned": "UNTRUSTED",
        },
        {
            "finding_id": "f-3",
            "timestamp": "2026-04-15T10:02:00Z",
            "session_id": "sess-exp-2",
            "scanner": "InjectionSignatureLibrary",
            "severity": "MEDIUM",
            "rule_id": "INJ-042",
            "description": "Social engineering pattern",
            "file_path": "/repo/README.md",
            "scan_mode": "LENIENT",
            "verdict": "CLEAN",
            "taint_assigned": None,
        },
    ])
    return db


class TestJSONExport:
    """APEP-448.b: JSON compliance export."""

    @pytest.mark.asyncio
    async def test_export_json_cis_security(self, exporter, seeded_db):
        result = await exporter.export_json(
            CISExportQuery(template="CIS_SECURITY")
        )
        assert result.title == "CIS (Content Ingestion Security) Scan Report"
        assert result.returned_records == 3
        assert result.total_matching_records == 3
        assert len(result.records) == 3

    @pytest.mark.asyncio
    async def test_export_json_with_session_filter(self, exporter, seeded_db):
        result = await exporter.export_json(
            CISExportQuery(template="CIS_SECURITY", session_id="sess-exp-1")
        )
        assert result.returned_records == 2

    @pytest.mark.asyncio
    async def test_export_json_with_severity_filter(self, exporter, seeded_db):
        result = await exporter.export_json(
            CISExportQuery(template="CIS_SECURITY", severity="CRITICAL")
        )
        assert result.returned_records == 1

    @pytest.mark.asyncio
    async def test_export_json_dpdpa_template(self, exporter, seeded_db):
        result = await exporter.export_json(
            CISExportQuery(template="CIS_DPDPA")
        )
        assert "DPDPA" in result.title
        assert result.returned_records == 3

    @pytest.mark.asyncio
    async def test_export_json_gdpr_template(self, exporter, seeded_db):
        result = await exporter.export_json(
            CISExportQuery(template="CIS_GDPR")
        )
        assert "GDPR" in result.title

    @pytest.mark.asyncio
    async def test_export_json_unknown_template(self, exporter, seeded_db):
        result = await exporter.export_json(
            CISExportQuery(template="UNKNOWN_TEMPLATE")
        )
        assert "Error" in result.title


class TestCSVExport:
    """APEP-448.b: CSV compliance export."""

    @pytest.mark.asyncio
    async def test_export_csv(self, exporter, seeded_db):
        csv_data = await exporter.export_csv(
            CISExportQuery(template="CIS_SECURITY")
        )
        lines = csv_data.strip().split("\n")
        assert len(lines) == 4  # header + 3 records
        assert "Finding ID" in lines[0]
        assert "Severity" in lines[0]

    @pytest.mark.asyncio
    async def test_export_csv_with_filter(self, exporter, seeded_db):
        csv_data = await exporter.export_csv(
            CISExportQuery(template="CIS_SECURITY", severity="CRITICAL")
        )
        lines = csv_data.strip().split("\n")
        assert len(lines) == 2  # header + 1 record

    @pytest.mark.asyncio
    async def test_export_csv_unknown_template(self, exporter, seeded_db):
        csv_data = await exporter.export_csv(
            CISExportQuery(template="BOGUS")
        )
        assert "error" in csv_data.lower()


class TestSummary:
    """APEP-448.b: Summary generation."""

    @pytest.mark.asyncio
    async def test_summary_in_json_export(self, exporter, seeded_db):
        result = await exporter.export_json(
            CISExportQuery(template="CIS_SECURITY")
        )
        summary = result.summary
        assert "by_severity" in summary
        assert summary["by_severity"]["CRITICAL"] == 1
        assert summary["by_severity"]["HIGH"] == 1
        assert summary["by_severity"]["MEDIUM"] == 1
        assert "by_scanner" in summary
        assert "by_verdict" in summary


class TestTemplates:
    """APEP-448.a: Template listing."""

    def test_list_templates(self, exporter):
        templates = exporter.list_templates()
        assert len(templates) == 3
        names = [t["template"] for t in templates]
        assert "CIS_SECURITY" in names
        assert "CIS_DPDPA" in names
        assert "CIS_GDPR" in names

    def test_templates_have_required_fields(self):
        for name, tmpl in CIS_COMPLIANCE_TEMPLATES.items():
            assert "title" in tmpl
            assert "description" in tmpl
            assert "fields" in tmpl
            assert "headers" in tmpl
            assert len(tmpl["fields"]) > 0
