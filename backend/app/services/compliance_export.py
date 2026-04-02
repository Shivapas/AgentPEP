"""Compliance export — CSV, JSON, and PDF for DPDPA, GDPR, CERT-In templates.

Sprint 10:
  APEP-086: CSV and JSON compliance export
  APEP-087: PDF audit report generation (reportlab)
"""

import csv
import io
import json
import logging
from datetime import datetime

from app.db import mongodb as db_module
from app.models.policy import AuditQueryRequest

logger = logging.getLogger(__name__)

# Template field mappings for each compliance framework
COMPLIANCE_TEMPLATES: dict[str, dict] = {
    "DPDPA": {
        "title": "DPDPA (Digital Personal Data Protection Act) Audit Report",
        "description": "Audit trail of AI agent tool authorisation decisions per DPDPA compliance.",
        "fields": [
            "decision_id", "timestamp", "agent_id", "agent_role", "tool_name",
            "decision", "risk_score", "taint_flags", "delegation_chain",
            "matched_rule_id", "latency_ms", "record_hash",
        ],
        "headers": {
            "decision_id": "Decision ID",
            "timestamp": "Timestamp (UTC)",
            "agent_id": "Data Fiduciary Agent",
            "agent_role": "Agent Role",
            "tool_name": "Processing Activity (Tool)",
            "decision": "Authorisation Decision",
            "risk_score": "Risk Score",
            "taint_flags": "Data Taint Flags",
            "delegation_chain": "Delegation Chain",
            "matched_rule_id": "Policy Rule Applied",
            "latency_ms": "Evaluation Latency (ms)",
            "record_hash": "Integrity Hash",
        },
    },
    "GDPR": {
        "title": "GDPR (General Data Protection Regulation) Audit Report",
        "description": "Record of AI agent processing decisions for GDPR Article 30 compliance.",
        "fields": [
            "decision_id", "timestamp", "agent_id", "agent_role", "tool_name",
            "tool_args_hash", "decision", "risk_score", "taint_flags",
            "delegation_chain", "matched_rule_id", "latency_ms", "record_hash",
        ],
        "headers": {
            "decision_id": "Processing Activity ID",
            "timestamp": "Timestamp (UTC)",
            "agent_id": "Controller/Processor Agent",
            "agent_role": "Agent Role",
            "tool_name": "Processing Operation (Tool)",
            "tool_args_hash": "Arguments Hash (Data Minimisation)",
            "decision": "Lawfulness Decision",
            "risk_score": "DPIA Risk Score",
            "taint_flags": "Data Origin Flags",
            "delegation_chain": "Sub-Processor Chain",
            "matched_rule_id": "Legal Basis Rule",
            "latency_ms": "Evaluation Latency (ms)",
            "record_hash": "Integrity Hash",
        },
    },
    "CERT_IN": {
        "title": "CERT-In Incident Audit Report",
        "description": "AI agent authorisation audit trail for CERT-In reporting requirements.",
        "fields": [
            "decision_id", "timestamp", "agent_id", "tool_name", "decision",
            "risk_score", "taint_flags", "delegation_chain",
            "sequence_number", "previous_hash", "record_hash",
        ],
        "headers": {
            "decision_id": "Event ID",
            "timestamp": "Event Timestamp (UTC)",
            "agent_id": "Agent Identifier",
            "tool_name": "Tool/Action",
            "decision": "Authorisation Outcome",
            "risk_score": "Risk Assessment",
            "taint_flags": "Taint Indicators",
            "delegation_chain": "Delegation Trail",
            "sequence_number": "Sequence Number",
            "previous_hash": "Previous Record Hash",
            "record_hash": "Record Hash",
        },
    },
}


def _build_query_filter(params: AuditQueryRequest) -> dict:
    """Build a MongoDB query filter from audit query parameters."""
    query: dict = {}
    if params.agent_id:
        query["agent_id"] = params.agent_id
    if params.tool_name:
        query["tool_name"] = params.tool_name
    if params.decision:
        query["decision"] = params.decision
    if params.risk_score_min is not None or params.risk_score_max is not None:
        risk_q: dict = {}
        if params.risk_score_min is not None:
            risk_q["$gte"] = params.risk_score_min
        if params.risk_score_max is not None:
            risk_q["$lte"] = params.risk_score_max
        query["risk_score"] = risk_q
    if params.start_time or params.end_time:
        time_q: dict = {}
        if params.start_time:
            time_q["$gte"] = params.start_time.isoformat()
        if params.end_time:
            time_q["$lte"] = params.end_time.isoformat()
        query["timestamp"] = time_q
    return query


async def query_audit_records(params: AuditQueryRequest) -> list[dict]:
    """Query audit decision records with filters."""
    db = db_module.get_database()
    query = _build_query_filter(params)
    cursor = (
        db[db_module.AUDIT_DECISIONS]
        .find(query, {"_id": 0})
        .sort("timestamp", -1)
        .skip(params.offset)
        .limit(params.limit)
    )
    return [doc async for doc in cursor]


async def count_audit_records(params: AuditQueryRequest) -> int:
    """Count audit records matching the query filter."""
    db = db_module.get_database()
    query = _build_query_filter(params)
    return await db[db_module.AUDIT_DECISIONS].count_documents(query)


async def export_json(template: str, params: AuditQueryRequest) -> dict:
    """Export audit records as a JSON compliance report."""
    tmpl = COMPLIANCE_TEMPLATES.get(template)
    if not tmpl:
        return {"error": f"Unknown template: {template}"}

    records = await query_audit_records(params)
    total = await count_audit_records(params)

    # Filter fields per template
    filtered = []
    for rec in records:
        row = {}
        for field in tmpl["fields"]:
            val = rec.get(field, "")
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            row[tmpl["headers"].get(field, field)] = val
        filtered.append(row)

    return {
        "title": tmpl["title"],
        "description": tmpl["description"],
        "template": template,
        "generated_at": datetime.utcnow().isoformat(),
        "total_matching_records": total,
        "returned_records": len(filtered),
        "records": filtered,
    }


async def export_csv(template: str, params: AuditQueryRequest) -> str:
    """Export audit records as a CSV string for compliance."""
    tmpl = COMPLIANCE_TEMPLATES.get(template)
    if not tmpl:
        return f"error: Unknown template: {template}"

    records = await query_audit_records(params)
    headers = [tmpl["headers"].get(f, f) for f in tmpl["fields"]]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)

    for rec in records:
        row = []
        for field in tmpl["fields"]:
            val = rec.get(field, "")
            if isinstance(val, list):
                val = "; ".join(str(v) for v in val)
            row.append(str(val))
        writer.writerow(row)

    return output.getvalue()


async def export_pdf(template: str, params: AuditQueryRequest) -> bytes:
    """Generate a PDF audit report using reportlab (APEP-087).

    Returns raw PDF bytes.
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    tmpl = COMPLIANCE_TEMPLATES.get(template)
    if not tmpl:
        raise ValueError(f"Unknown template: {template}")

    records = await query_audit_records(params)
    total = await count_audit_records(params)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(A4))
    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph(tmpl["title"], styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(tmpl["description"], styles["Normal"]))
    elements.append(Spacer(1, 6))
    elements.append(
        Paragraph(
            f"Generated: {datetime.utcnow().isoformat()} | "
            f"Total records: {total} | Returned: {len(records)}",
            styles["Normal"],
        )
    )
    elements.append(Spacer(1, 18))

    # Build table
    # Use a subset of fields for readability
    display_fields = tmpl["fields"][:8]  # Cap columns for PDF readability
    headers = [tmpl["headers"].get(f, f) for f in display_fields]
    table_data = [headers]

    for rec in records:
        row = []
        for field in display_fields:
            val = rec.get(field, "")
            if isinstance(val, list):
                val = "; ".join(str(v) for v in val)
            # Truncate long values for PDF
            s = str(val)
            if len(s) > 40:
                s = s[:37] + "..."
            row.append(s)
        table_data.append(row)

    if len(table_data) > 1:
        table = Table(table_data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2d3748")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, 0), 8),
                    ("FONTSIZE", (0, 1), (-1, -1), 7),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        elements.append(table)
    else:
        elements.append(Paragraph("No records found matching the query.", styles["Normal"]))

    doc.build(elements)
    return buffer.getvalue()
