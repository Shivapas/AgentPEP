"""CIS scan results to compliance exports — Sprint 56 (APEP-448).

Exports CIS scan findings into compliance-ready formats (CSV, JSON, PDF)
aligned with DPDPA, GDPR, and CERT-In templates.  Extends the existing
compliance_export module with CIS-specific templates and data mappings.

Usage::

    from app.services.cis_compliance_export import cis_compliance_exporter

    # Export CIS findings as JSON
    report = await cis_compliance_exporter.export_json(
        template="CIS_SECURITY",
        session_id="sess-123",
    )

    # Export as CSV
    csv_data = await cis_compliance_exporter.export_csv(
        template="CIS_SECURITY",
        limit=500,
    )
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CIS-specific compliance templates
# ---------------------------------------------------------------------------

CIS_COMPLIANCE_TEMPLATES: dict[str, dict[str, Any]] = {
    "CIS_SECURITY": {
        "title": "CIS (Content Ingestion Security) Scan Report",
        "description": (
            "Content Ingestion Security findings from multi-tier scanning "
            "(Tier 0: regex, Tier 1: ONNX semantic classifier)."
        ),
        "fields": [
            "finding_id", "timestamp", "session_id", "scanner", "severity",
            "rule_id", "description", "file_path", "scan_mode",
            "verdict", "taint_assigned",
        ],
        "headers": {
            "finding_id": "Finding ID",
            "timestamp": "Timestamp (UTC)",
            "session_id": "Session ID",
            "scanner": "Scanner Tier",
            "severity": "Severity",
            "rule_id": "Rule / Pattern ID",
            "description": "Finding Description",
            "file_path": "File Path",
            "scan_mode": "Scan Mode",
            "verdict": "Verdict",
            "taint_assigned": "Taint Assignment",
        },
    },
    "CIS_DPDPA": {
        "title": "CIS Findings — DPDPA Compliance Report",
        "description": (
            "Content Ingestion Security findings mapped to DPDPA data "
            "protection compliance requirements."
        ),
        "fields": [
            "finding_id", "timestamp", "session_id", "agent_id",
            "scanner", "severity", "rule_id", "description",
            "file_path", "scan_mode", "verdict", "taint_assigned",
            "matched_text",
        ],
        "headers": {
            "finding_id": "Finding ID",
            "timestamp": "Event Timestamp (UTC)",
            "session_id": "Processing Session",
            "agent_id": "Data Fiduciary Agent",
            "scanner": "Security Scanner",
            "severity": "Risk Severity",
            "rule_id": "Detection Rule",
            "description": "Security Finding",
            "file_path": "Affected Resource",
            "scan_mode": "Scan Stringency",
            "verdict": "Security Verdict",
            "taint_assigned": "Data Taint Classification",
            "matched_text": "Evidence (truncated)",
        },
    },
    "CIS_GDPR": {
        "title": "CIS Findings — GDPR Data Processing Security Report",
        "description": (
            "Content Ingestion Security findings for GDPR Article 32 "
            "security-of-processing compliance."
        ),
        "fields": [
            "finding_id", "timestamp", "session_id", "agent_id",
            "scanner", "severity", "rule_id", "description",
            "file_path", "scan_mode", "verdict", "taint_assigned",
        ],
        "headers": {
            "finding_id": "Processing Security Event ID",
            "timestamp": "Timestamp (UTC)",
            "session_id": "Processing Session",
            "agent_id": "Controller/Processor Agent",
            "scanner": "Security Measure (Scanner)",
            "severity": "DPIA Risk Level",
            "rule_id": "Detection Rule",
            "description": "Security Finding",
            "file_path": "Affected Resource",
            "scan_mode": "Security Posture",
            "verdict": "Assessment Verdict",
            "taint_assigned": "Data Origin Flag",
        },
    },
}


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CISExportQuery(BaseModel):
    """Query parameters for CIS compliance exports."""

    template: str = Field(default="CIS_SECURITY", description="Template name")
    session_id: str | None = Field(default=None, description="Filter by session")
    severity: str | None = Field(default=None, description="Filter by severity")
    scanner: str | None = Field(default=None, description="Filter by scanner")
    verdict: str | None = Field(default=None, description="Filter by verdict")
    limit: int = Field(default=500, ge=1, le=5000)
    offset: int = Field(default=0, ge=0)


class CISExportResponse(BaseModel):
    """JSON export response."""

    title: str
    description: str
    template: str
    generated_at: str
    total_matching_records: int = 0
    returned_records: int = 0
    records: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class CISComplianceExporter:
    """Exports CIS scan findings to compliance-ready formats (APEP-448)."""

    async def _query_findings(self, query: CISExportQuery) -> tuple[list[dict], int]:
        """Query CIS findings from MongoDB."""
        try:
            from app.db import mongodb as db_module

            db = db_module.get_database()
            filt: dict = {}
            if query.session_id:
                filt["session_id"] = query.session_id
            if query.severity:
                filt["severity"] = query.severity
            if query.scanner:
                filt["scanner"] = query.scanner
            if query.verdict:
                filt["verdict"] = query.verdict

            total = await db["cis_findings"].count_documents(filt)
            cursor = (
                db["cis_findings"]
                .find(filt, {"_id": 0})
                .sort("timestamp", -1)
                .skip(query.offset)
                .limit(query.limit)
            )
            docs = [doc async for doc in cursor]
            return docs, total
        except Exception:
            logger.warning("Failed to query CIS findings for export", exc_info=True)
            return [], 0

    def _build_summary(self, records: list[dict]) -> dict[str, Any]:
        """Build a summary of findings by severity and scanner."""
        severity_counts: dict[str, int] = {}
        scanner_counts: dict[str, int] = {}
        verdict_counts: dict[str, int] = {}

        for rec in records:
            sev = rec.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            scn = rec.get("scanner", "UNKNOWN")
            scanner_counts[scn] = scanner_counts.get(scn, 0) + 1
            vrd = rec.get("verdict", "UNKNOWN")
            verdict_counts[vrd] = verdict_counts.get(vrd, 0) + 1

        return {
            "by_severity": severity_counts,
            "by_scanner": scanner_counts,
            "by_verdict": verdict_counts,
        }

    async def export_json(
        self,
        query: CISExportQuery | None = None,
        **kwargs: Any,
    ) -> CISExportResponse:
        """Export CIS findings as a JSON compliance report."""
        if query is None:
            query = CISExportQuery(**kwargs)

        tmpl = CIS_COMPLIANCE_TEMPLATES.get(query.template)
        if not tmpl:
            return CISExportResponse(
                title="Error",
                description=f"Unknown template: {query.template}",
                template=query.template,
                generated_at=datetime.now(UTC).isoformat(),
            )

        records, total = await self._query_findings(query)

        # Map records to template fields
        filtered: list[dict[str, Any]] = []
        for rec in records:
            row: dict[str, Any] = {}
            for field_name in tmpl["fields"]:
                val = rec.get(field_name, "")
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val)
                header = tmpl["headers"].get(field_name, field_name)
                row[header] = val
            filtered.append(row)

        return CISExportResponse(
            title=tmpl["title"],
            description=tmpl["description"],
            template=query.template,
            generated_at=datetime.now(UTC).isoformat(),
            total_matching_records=total,
            returned_records=len(filtered),
            records=filtered,
            summary=self._build_summary(records),
        )

    async def export_csv(
        self,
        query: CISExportQuery | None = None,
        **kwargs: Any,
    ) -> str:
        """Export CIS findings as a CSV string."""
        if query is None:
            query = CISExportQuery(**kwargs)

        tmpl = CIS_COMPLIANCE_TEMPLATES.get(query.template)
        if not tmpl:
            return f"error: Unknown template: {query.template}"

        records, _ = await self._query_findings(query)
        headers = [tmpl["headers"].get(f, f) for f in tmpl["fields"]]

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)

        for rec in records:
            row: list[str] = []
            for field_name in tmpl["fields"]:
                val = rec.get(field_name, "")
                if isinstance(val, list):
                    val = "; ".join(str(v) for v in val)
                row.append(str(val))
            writer.writerow(row)

        return output.getvalue()

    async def export_pdf(
        self,
        query: CISExportQuery | None = None,
        **kwargs: Any,
    ) -> bytes:
        """Export CIS findings as a PDF report."""
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        if query is None:
            query = CISExportQuery(**kwargs)

        tmpl = CIS_COMPLIANCE_TEMPLATES.get(query.template)
        if not tmpl:
            raise ValueError(f"Unknown template: {query.template}")

        records, total = await self._query_findings(query)
        summary = self._build_summary(records)

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(A4))
        styles = getSampleStyleSheet()
        elements = []

        # Title and metadata
        elements.append(Paragraph(tmpl["title"], styles["Title"]))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(tmpl["description"], styles["Normal"]))
        elements.append(Spacer(1, 6))
        elements.append(
            Paragraph(
                f"Generated: {datetime.now(UTC).isoformat()} | "
                f"Total findings: {total} | Returned: {len(records)}",
                styles["Normal"],
            )
        )
        elements.append(Spacer(1, 6))

        # Summary
        sev_summary = ", ".join(
            f"{k}: {v}" for k, v in sorted(summary.get("by_severity", {}).items())
        )
        if sev_summary:
            elements.append(
                Paragraph(f"Severity breakdown: {sev_summary}", styles["Normal"])
            )
        elements.append(Spacer(1, 18))

        # Table
        display_fields = tmpl["fields"][:8]
        headers = [tmpl["headers"].get(f, f) for f in display_fields]
        table_data = [headers]

        for rec in records:
            row: list[str] = []
            for field_name in display_fields:
                val = rec.get(field_name, "")
                if isinstance(val, list):
                    val = "; ".join(str(v) for v in val)
                s = str(val)
                if len(s) > 40:
                    s = s[:37] + "..."
                row.append(s)
            table_data.append(row)

        if len(table_data) > 1:
            table = Table(table_data, repeatRows=1)
            table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d3748")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, 0), 8),
                    ("FONTSIZE", (0, 1), (-1, -1), 7),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                        colors.white, colors.HexColor("#f7fafc"),
                    ]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )
            elements.append(table)
        else:
            elements.append(
                Paragraph("No CIS findings matching the query.", styles["Normal"])
            )

        doc.build(elements)
        return buffer.getvalue()

    def list_templates(self) -> list[dict[str, str]]:
        """List available CIS compliance export templates."""
        return [
            {
                "template": key,
                "title": val["title"],
                "description": val["description"],
            }
            for key, val in CIS_COMPLIANCE_TEMPLATES.items()
        ]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

cis_compliance_exporter = CISComplianceExporter()
