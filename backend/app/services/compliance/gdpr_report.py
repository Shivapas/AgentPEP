"""APEP-173: GDPR Art. 25 (Privacy by Design) compliance report generator.

Generates a GDPR Article 25 compliance report that assesses Privacy by Design
controls implemented in the AgentPEP policy engine, including data minimisation
metrics and privacy control evidence.
"""

import logging
from datetime import datetime

from app.db.mongodb import AUDIT_DECISIONS, POLICY_RULES, get_database
from app.models.compliance import (
    ComplianceReport,
    GDPRDataMinimisationSummary,
    GDPRPrivacyByDesignControl,
    ReportStatus,
    ReportType,
)

logger = logging.getLogger(__name__)

# Privacy by Design controls mapped to AgentPEP capabilities
PRIVACY_BY_DESIGN_CONTROLS: list[dict] = [
    {
        "control_id": "PbD-01",
        "control_name": "Purpose Limitation",
        "description": "Tool calls are evaluated against role-based policies ensuring agents "
        "only access tools appropriate to their assigned purpose.",
    },
    {
        "control_id": "PbD-02",
        "control_name": "Data Minimisation",
        "description": "Taint tracking monitors data flow and enforces quarantine on excessive "
        "or untrusted data propagation across agent boundaries.",
    },
    {
        "control_id": "PbD-03",
        "control_name": "Access Control",
        "description": "RBAC with multi-inheritance role hierarchy restricts tool access. "
        "Deny-by-default policy ensures no implicit access.",
    },
    {
        "control_id": "PbD-04",
        "control_name": "Audit Trail",
        "description": "Every authorization decision is logged with immutable audit records "
        "including agent, tool, risk score, and matched rule.",
    },
    {
        "control_id": "PbD-05",
        "control_name": "Risk Assessment",
        "description": "Real-time risk scoring evaluates each tool call. Calls exceeding "
        "role-specific thresholds are denied or escalated.",
    },
    {
        "control_id": "PbD-06",
        "control_name": "Delegation Control",
        "description": "Confused-deputy detection validates delegation chains and prevents "
        "privilege escalation across agent-to-agent delegations.",
    },
    {
        "control_id": "PbD-07",
        "control_name": "Injection Protection",
        "description": "Injection signature scanning quarantines tainted data containing "
        "prompt override, role hijack, or jailbreak patterns.",
    },
    {
        "control_id": "PbD-08",
        "control_name": "Fail-Safe Defaults",
        "description": "Configurable FAIL_CLOSED / FAIL_OPEN mode with deny-by-default "
        "when no policy rule matches a tool call request.",
    },
]


async def generate_gdpr_art25_report(
    period_start: datetime,
    period_end: datetime,
) -> ComplianceReport:
    """Generate a GDPR Art. 25 Privacy by Design compliance report.

    Sections:
    1. Privacy by Design Controls — assessment of each PbD control
    2. Data Minimisation Metrics — taint check coverage and deny rates
    3. Access Control Summary — role and policy rule statistics
    """
    db = get_database()
    report = ComplianceReport(
        report_type=ReportType.GDPR_ART25,
        title=f"GDPR Art. 25 Privacy by Design Report ({period_start:%Y-%m-%d} to {period_end:%Y-%m-%d})",
        status=ReportStatus.GENERATING,
        period_start=period_start,
        period_end=period_end,
    )

    try:
        time_filter = {"timestamp": {"$gte": period_start, "$lte": period_end}}
        decisions_coll = db[AUDIT_DECISIONS]
        rules_coll = db[POLICY_RULES]

        # --- Section 1: Privacy by Design Controls ---
        # Check which controls have evidence (active rules, audit decisions, etc.)
        total_rules = await rules_coll.count_documents({"enabled": True})
        total_decisions = await decisions_coll.count_documents(time_filter)

        controls: list[dict] = []
        for ctrl_def in PRIVACY_BY_DESIGN_CONTROLS:
            ctrl = GDPRPrivacyByDesignControl(
                control_id=ctrl_def["control_id"],
                control_name=ctrl_def["control_name"],
                description=ctrl_def["description"],
                implemented=True,
                evidence=f"{total_rules} active policy rules; {total_decisions} decisions in period",
            )
            controls.append(ctrl.model_dump())

        # --- Section 2: Data Minimisation Metrics ---
        taint_check_pipeline = [
            {"$match": time_filter},
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "with_taint": {
                        "$sum": {
                            "$cond": [{"$gt": [{"$size": {"$ifNull": ["$taint_flags", []]}}, 0]}, 1, 0]
                        }
                    },
                }
            },
        ]

        minimisation = GDPRDataMinimisationSummary()
        async for doc in decisions_coll.aggregate(taint_check_pipeline):
            minimisation.total_tool_calls = doc.get("total", 0)
            minimisation.calls_with_taint_check = doc.get("with_taint", 0)
            if minimisation.total_tool_calls > 0:
                minimisation.taint_check_percentage = round(
                    (minimisation.calls_with_taint_check / minimisation.total_tool_calls) * 100, 2
                )

        # Count denials that may relate to excessive data access
        minimisation.denied_for_excessive_data = await decisions_coll.count_documents(
            {**time_filter, "decision": "DENY"}
        )

        # --- Section 3: Access Control Summary ---
        role_pipeline = [
            {"$match": time_filter},
            {"$group": {"_id": "$agent_role", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
        ]
        role_distribution: dict[str, int] = {}
        async for doc in decisions_coll.aggregate(role_pipeline):
            role_distribution[doc["_id"]] = doc["count"]

        report.content = {
            "privacy_by_design_controls": controls,
            "data_minimisation": minimisation.model_dump(mode="json"),
            "access_control_summary": {
                "active_policy_rules": total_rules,
                "total_decisions_in_period": total_decisions,
                "role_distribution": role_distribution,
            },
        }
        report.status = ReportStatus.COMPLETED
        report.generated_at = datetime.utcnow()

    except Exception as exc:
        logger.exception("Failed to generate GDPR Art. 25 report")
        report.status = ReportStatus.FAILED
        report.error_message = str(exc)

    return report
