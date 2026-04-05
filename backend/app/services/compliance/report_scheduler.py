"""APEP-177: Compliance report scheduler.

Manages scheduled report generation (weekly/monthly) with email delivery.
Uses asyncio background tasks to run on a configurable interval, generating
reports and optionally emailing them to configured recipients.
"""

import asyncio
import logging
import smtplib
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from uuid import UUID

from app.db.mongodb import get_database
from app.models.compliance import (
    ComplianceReport,
    ReportSchedule,
    ReportStatus,
    ReportType,
    ScheduleFrequency,
)
from app.services.compliance.certin_report import generate_certin_bom_report
from app.services.compliance.dpdpa_report import generate_dpdpa_report
from app.services.compliance.gdpr_report import generate_gdpr_art25_report

logger = logging.getLogger(__name__)

COMPLIANCE_REPORTS = "compliance_reports"
REPORT_SCHEDULES = "report_schedules"


async def _save_report(report: ComplianceReport) -> None:
    """Persist a generated report to MongoDB."""
    db = get_database()
    coll = db[COMPLIANCE_REPORTS]
    await coll.insert_one(report.model_dump(mode="json"))


async def generate_report(
    report_type: ReportType,
    period_start: datetime,
    period_end: datetime,
) -> ComplianceReport:
    """Generate a compliance report by type and persist it."""
    generators = {
        ReportType.DPDPA: generate_dpdpa_report,
        ReportType.GDPR_ART25: generate_gdpr_art25_report,
        ReportType.CERT_IN_BOM: generate_certin_bom_report,
    }
    generator = generators[report_type]
    report = await generator(period_start, period_end)
    await _save_report(report)
    return report


async def list_reports(
    report_type: ReportType | None = None,
    skip: int = 0,
    limit: int = 20,
) -> tuple[list[ComplianceReport], int]:
    """List generated reports with optional type filter."""
    db = get_database()
    coll = db[COMPLIANCE_REPORTS]
    query: dict = {}
    if report_type:
        query["report_type"] = report_type.value
    total = await coll.count_documents(query)
    cursor = coll.find(query).sort("created_at", -1).skip(skip).limit(limit)
    reports: list[ComplianceReport] = []
    async for doc in cursor:
        doc.pop("_id", None)
        reports.append(ComplianceReport(**doc))
    return reports, total


async def get_report(report_id: UUID) -> ComplianceReport | None:
    """Fetch a single report by ID."""
    db = get_database()
    coll = db[COMPLIANCE_REPORTS]
    doc = await coll.find_one({"report_id": str(report_id)})
    if doc:
        doc.pop("_id", None)
        return ComplianceReport(**doc)
    return None


# --- Schedule Management ---


async def create_schedule(schedule: ReportSchedule) -> ReportSchedule:
    """Create a new report schedule."""
    schedule.next_run_at = _compute_next_run(schedule.frequency)
    db = get_database()
    coll = db[REPORT_SCHEDULES]
    await coll.insert_one(schedule.model_dump(mode="json"))
    return schedule


async def list_schedules() -> list[ReportSchedule]:
    """List all report schedules."""
    db = get_database()
    coll = db[REPORT_SCHEDULES]
    schedules: list[ReportSchedule] = []
    async for doc in coll.find():
        doc.pop("_id", None)
        schedules.append(ReportSchedule(**doc))
    return schedules


async def delete_schedule(schedule_id: UUID) -> bool:
    """Delete a schedule by ID."""
    db = get_database()
    coll = db[REPORT_SCHEDULES]
    result = await coll.delete_one({"schedule_id": str(schedule_id)})
    return result.deleted_count > 0


def _compute_next_run(frequency: ScheduleFrequency) -> datetime:
    """Compute the next run time from now."""
    now = datetime.now(UTC)
    if frequency == ScheduleFrequency.WEEKLY:
        return now + timedelta(weeks=1)
    return now + timedelta(days=30)


def _compute_period(frequency: ScheduleFrequency) -> tuple[datetime, datetime]:
    """Compute the reporting period ending now."""
    end = datetime.now(UTC)
    if frequency == ScheduleFrequency.WEEKLY:
        start = end - timedelta(weeks=1)
    else:
        start = end - timedelta(days=30)
    return start, end


def _send_email(recipients: list[str], report: ComplianceReport) -> None:
    """Send report notification via SMTP (best-effort, non-blocking)."""
    try:
        msg = EmailMessage()
        msg["Subject"] = f"AgentPEP Compliance Report: {report.title}"
        msg["From"] = "agentpep-noreply@localhost"
        msg["To"] = ", ".join(recipients)
        msg.set_content(
            f"Report: {report.title}\n"
            f"Type: {report.report_type.value}\n"
            f"Status: {report.status.value}\n"
            f"Period: {report.period_start} to {report.period_end}\n"
            f"Generated: {report.generated_at}\n\n"
            f"View full report in the AgentPEP Policy Console."
        )
        # Best-effort local SMTP — production deployments configure a relay
        with smtplib.SMTP("localhost", 25, timeout=5) as smtp:
            smtp.send_message(msg)
        logger.info("Email sent to %s for report %s", recipients, report.report_id)
    except Exception:
        logger.debug("Email delivery skipped (SMTP not available)")


async def run_due_schedules() -> list[ComplianceReport]:
    """Check and execute any schedules that are due. Returns generated reports."""
    db = get_database()
    coll = db[REPORT_SCHEDULES]
    now = datetime.now(UTC)

    due_schedules = coll.find({
        "enabled": True,
        "next_run_at": {"$lte": now},
    })

    generated: list[ComplianceReport] = []
    async for doc in due_schedules:
        doc.pop("_id", None)
        schedule = ReportSchedule(**doc)
        period_start, period_end = _compute_period(schedule.frequency)

        report = await generate_report(schedule.report_type, period_start, period_end)
        generated.append(report)

        # Email if configured and report succeeded
        if schedule.email_recipients and report.status == ReportStatus.COMPLETED:
            _send_email(schedule.email_recipients, report)

        # Update schedule
        await coll.update_one(
            {"schedule_id": str(schedule.schedule_id)},
            {
                "$set": {
                    "last_run_at": now.isoformat(),
                    "next_run_at": _compute_next_run(schedule.frequency).isoformat(),
                    "updated_at": now.isoformat(),
                }
            },
        )

    return generated


class ReportSchedulerLoop:
    """Background loop that periodically checks for due report schedules."""

    def __init__(self, check_interval_s: float = 300.0) -> None:
        self._check_interval = check_interval_s
        self._task: asyncio.Task | None = None  # type: ignore[type-arg]

    async def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())
            logger.info("Report scheduler loop started (interval=%ss)", self._check_interval)

    async def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            logger.info("Report scheduler loop stopped")

    async def _loop(self) -> None:
        while True:
            try:
                reports = await run_due_schedules()
                if reports:
                    logger.info("Scheduler generated %d reports", len(reports))
            except Exception:
                logger.exception("Report scheduler error")
            await asyncio.sleep(self._check_interval)


# Module-level singleton
report_scheduler = ReportSchedulerLoop()
