"""Pydantic models for compliance reports and SIEM integration (Sprint 22)."""

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ReportType(StrEnum):
    DPDPA = "DPDPA"
    GDPR_ART25 = "GDPR_ART25"
    CERT_IN_BOM = "CERT_IN_BOM"


class ReportStatus(StrEnum):
    PENDING = "PENDING"
    GENERATING = "GENERATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScheduleFrequency(StrEnum):
    WEEKLY = "WEEKLY"
    MONTHLY = "MONTHLY"


# --- DPDPA Report Sections (APEP-172) ---


class DPDPADataProcessingSummary(BaseModel):
    """Summary of data processing decisions under India's DPDPA."""

    total_decisions: int = 0
    allow_count: int = 0
    deny_count: int = 0
    escalate_count: int = 0
    unique_agents: int = 0
    unique_tools: int = 0
    period_start: datetime | None = None
    period_end: datetime | None = None


class DPDPATaintSummary(BaseModel):
    """Summary of taint tracking events for DPDPA compliance."""

    total_taint_events: int = 0
    quarantine_events: int = 0
    cross_agent_propagations: int = 0
    sanitisation_events: int = 0


class DPDPADenyLog(BaseModel):
    """Individual DENY decision entry for DPDPA report."""

    decision_id: str
    timestamp: datetime
    agent_id: str
    tool_name: str
    risk_score: float
    reason: str = ""


# --- GDPR Art. 25 Report Sections (APEP-173) ---


class GDPRPrivacyByDesignControl(BaseModel):
    """A single Privacy by Design control assessment."""

    control_id: str
    control_name: str
    description: str
    implemented: bool = False
    evidence: str = ""


class GDPRDataMinimisationSummary(BaseModel):
    """Data minimisation metrics for GDPR Art. 25."""

    total_tool_calls: int = 0
    calls_with_taint_check: int = 0
    taint_check_percentage: float = 0.0
    denied_for_excessive_data: int = 0


# --- CERT-In BOM Report Sections (APEP-174) ---


class CERTInAgentEntry(BaseModel):
    """Bill of Materials entry for a single agent."""

    agent_id: str
    agent_name: str
    roles: list[str] = Field(default_factory=list)
    tools_accessed: list[str] = Field(default_factory=list)
    total_decisions: int = 0
    deny_count: int = 0
    risk_score_avg: float = 0.0
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class CERTInSecurityAlertSummary(BaseModel):
    """Security alert summary for CERT-In report."""

    total_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    alert_types: dict[str, int] = Field(default_factory=dict)


# --- Compliance Report (unified envelope) ---


class ComplianceReport(BaseModel):
    """Generated compliance report stored in MongoDB."""

    report_id: UUID = Field(default_factory=uuid4)
    report_type: ReportType
    title: str
    status: ReportStatus = ReportStatus.PENDING
    period_start: datetime
    period_end: datetime
    generated_at: datetime | None = None
    generated_by: str = "system"
    content: dict = Field(default_factory=dict, description="Report-specific JSON content")
    error_message: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# --- Report Schedule (APEP-177) ---


class ReportSchedule(BaseModel):
    """Schedule configuration for recurring compliance report generation."""

    schedule_id: UUID = Field(default_factory=uuid4)
    report_type: ReportType
    frequency: ScheduleFrequency
    email_recipients: list[str] = Field(default_factory=list)
    enabled: bool = True
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# --- API Schemas ---


class GenerateReportRequest(BaseModel):
    """Request to generate a compliance report."""

    report_type: ReportType
    period_start: datetime
    period_end: datetime


class ReportListResponse(BaseModel):
    """Paginated list of compliance reports."""

    reports: list[ComplianceReport] = Field(default_factory=list)
    total: int = 0


class CreateScheduleRequest(BaseModel):
    """Request to create a report schedule."""

    report_type: ReportType
    frequency: ScheduleFrequency
    email_recipients: list[str] = Field(default_factory=list)
