"""Audit API — query, compliance export, PDF reports, and integrity verification.

Sprint 10:
  APEP-085: Audit query API with filters
  APEP-086: Compliance export (CSV / JSON)
  APEP-087: PDF audit report generation
  APEP-088: Audit integrity verification
"""

from datetime import datetime

from fastapi import APIRouter, Query
from fastapi.responses import Response

from app.models.policy import AuditIntegrityResult, AuditQueryRequest, ComplianceExportRequest
from app.services.audit_integrity import verify_audit_chain
from app.services.compliance_export import (
    count_audit_records,
    export_csv,
    export_json,
    export_pdf,
    query_audit_records,
)

router = APIRouter(prefix="/v1/audit", tags=["audit"])


# --- APEP-085: Audit Query API ---


@router.get("/decisions")
async def get_audit_decisions(
    agent_id: str | None = None,
    tool_name: str | None = None,
    decision: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    risk_score_min: float | None = Query(default=None, ge=0.0, le=1.0),
    risk_score_max: float | None = Query(default=None, ge=0.0, le=1.0),
    limit: int = Query(default=100, ge=1, le=10000),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """Query audit decisions with optional filters."""
    params = AuditQueryRequest(
        agent_id=agent_id,
        tool_name=tool_name,
        decision=decision,
        start_time=start_time,
        end_time=end_time,
        risk_score_min=risk_score_min,
        risk_score_max=risk_score_max,
        limit=limit,
        offset=offset,
    )
    records = await query_audit_records(params)
    total = await count_audit_records(params)
    return {
        "total": total,
        "returned": len(records),
        "offset": offset,
        "limit": limit,
        "records": records,
    }


# --- APEP-086: Compliance Export ---


@router.post("/export/json")
async def export_compliance_json(request: ComplianceExportRequest) -> dict:
    """Export audit records as JSON in a compliance template format."""
    params = AuditQueryRequest(
        agent_id=request.agent_id,
        tool_name=request.tool_name,
        decision=request.decision,
        start_time=request.start_time,
        end_time=request.end_time,
        risk_score_min=request.risk_score_min,
        risk_score_max=request.risk_score_max,
    )
    return await export_json(request.template, params)


@router.post("/export/csv")
async def export_compliance_csv(request: ComplianceExportRequest) -> Response:
    """Export audit records as CSV in a compliance template format."""
    params = AuditQueryRequest(
        agent_id=request.agent_id,
        tool_name=request.tool_name,
        decision=request.decision,
        start_time=request.start_time,
        end_time=request.end_time,
        risk_score_min=request.risk_score_min,
        risk_score_max=request.risk_score_max,
    )
    csv_data = await export_csv(request.template, params)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=audit_{request.template}.csv"},
    )


# --- APEP-087: PDF Audit Report ---


@router.post("/export/pdf")
async def export_compliance_pdf(request: ComplianceExportRequest) -> Response:
    """Generate a PDF audit report for compliance."""
    params = AuditQueryRequest(
        agent_id=request.agent_id,
        tool_name=request.tool_name,
        decision=request.decision,
        start_time=request.start_time,
        end_time=request.end_time,
        risk_score_min=request.risk_score_min,
        risk_score_max=request.risk_score_max,
    )
    pdf_bytes = await export_pdf(request.template, params)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=audit_{request.template}.pdf"},
    )


# --- APEP-088: Audit Integrity Verification ---


@router.get("/verify", response_model=AuditIntegrityResult)
async def verify_integrity(
    start_sequence: int = Query(default=1, ge=1),
    end_sequence: int | None = None,
) -> AuditIntegrityResult:
    """Verify the audit hash chain integrity."""
    return await verify_audit_chain(
        start_sequence=start_sequence,
        end_sequence=end_sequence,
    )
