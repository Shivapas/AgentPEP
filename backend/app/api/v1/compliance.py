"""Compliance Reports API — generate, list, preview, and download reports (Sprint 22)."""

import json
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from app.models.compliance import (
    ComplianceReport,
    CreateScheduleRequest,
    GenerateReportRequest,
    ReportListResponse,
    ReportSchedule,
    ReportType,
)
from app.services.compliance.report_scheduler import (
    create_schedule,
    delete_schedule,
    generate_report,
    get_report,
    list_reports,
    list_schedules,
)

router = APIRouter(prefix="/v1/compliance", tags=["compliance"])


# --- Report Generation ---


@router.post("/reports", response_model=ComplianceReport)
async def create_report(req: GenerateReportRequest) -> ComplianceReport:
    """Generate a compliance report for the specified type and period."""
    report = await generate_report(req.report_type, req.period_start, req.period_end)
    return report


@router.get("/reports", response_model=ReportListResponse)
async def get_reports(
    report_type: ReportType | None = None,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
) -> ReportListResponse:
    """List generated compliance reports with optional type filter."""
    reports, total = await list_reports(report_type=report_type, skip=skip, limit=limit)
    return ReportListResponse(reports=reports, total=total)


@router.get("/reports/{report_id}", response_model=ComplianceReport)
async def get_report_detail(report_id: UUID) -> ComplianceReport:
    """Get a single compliance report by ID."""
    report = await get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/reports/{report_id}/download")
async def download_report(report_id: UUID) -> Response:
    """Download a compliance report as JSON file."""
    report = await get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    content = json.dumps(report.model_dump(mode="json"), indent=2, default=str)
    start = report.period_start.strftime("%Y%m%d")
    end = report.period_end.strftime("%Y%m%d")
    filename = f"{report.report_type.value}_{start}_{end}.json"
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# --- Schedule Management ---


@router.post("/schedules", response_model=ReportSchedule)
async def create_report_schedule(req: CreateScheduleRequest) -> ReportSchedule:
    """Create a recurring report schedule."""
    schedule = ReportSchedule(
        report_type=req.report_type,
        frequency=req.frequency,
        email_recipients=req.email_recipients,
    )
    return await create_schedule(schedule)


@router.get("/schedules", response_model=list[ReportSchedule])
async def get_schedules() -> list[ReportSchedule]:
    """List all report schedules."""
    return await list_schedules()


@router.delete("/schedules/{schedule_id}", status_code=204)
async def remove_schedule(schedule_id: UUID) -> None:
    """Delete a report schedule."""
    deleted = await delete_schedule(schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found")
