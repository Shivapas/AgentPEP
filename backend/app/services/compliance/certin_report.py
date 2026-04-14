"""APEP-174: CERT-In BOM-aligned agent activity report generator.

Generates a Bill of Materials (BOM) report aligned with CERT-In (Indian Computer
Emergency Response Team) requirements, cataloguing all agent activity, tools
accessed, security alerts, and risk posture for the reporting period.
"""

import logging
from datetime import UTC, datetime

from app.db.mongodb import (
    AGENT_PROFILES,
    AUDIT_DECISIONS,
    CHECKPOINT_ESCALATION_HISTORY,
    SECURITY_ALERTS,
    get_database,
)
from app.models.compliance import (
    CERTInAgentEntry,
    CERTInCheckpointSummary,
    CERTInSecurityAlertSummary,
    ComplianceReport,
    ReportStatus,
    ReportType,
)

logger = logging.getLogger(__name__)


async def generate_certin_bom_report(
    period_start: datetime,
    period_end: datetime,
) -> ComplianceReport:
    """Generate a CERT-In BOM-aligned agent activity report.

    Sections:
    1. Agent Bill of Materials — every agent with roles, tools, decisions, risk
    2. Security Alert Summary — counts by severity and type
    3. Incident Timeline — chronological security alerts
    """
    db = get_database()
    report = ComplianceReport(
        report_type=ReportType.CERT_IN_BOM,
        title=(
            f"CERT-In BOM Agent Activity Report"
            f" ({period_start:%Y-%m-%d} to {period_end:%Y-%m-%d})"
        ),
        status=ReportStatus.GENERATING,
        period_start=period_start,
        period_end=period_end,
    )

    try:
        time_filter = {"timestamp": {"$gte": period_start, "$lte": period_end}}
        decisions_coll = db[AUDIT_DECISIONS]
        profiles_coll = db[AGENT_PROFILES]
        alerts_coll = db[SECURITY_ALERTS]

        # --- Section 1: Agent Bill of Materials ---
        agent_pipeline = [
            {"$match": time_filter},
            {
                "$group": {
                    "_id": "$agent_id",
                    "total_decisions": {"$sum": 1},
                    "deny_count": {
                        "$sum": {"$cond": [{"$eq": ["$decision", "DENY"]}, 1, 0]}
                    },
                    "avg_risk": {"$avg": "$risk_score"},
                    "tools": {"$addToSet": "$tool_name"},
                    "first_seen": {"$min": "$timestamp"},
                    "last_seen": {"$max": "$timestamp"},
                }
            },
            {"$sort": {"total_decisions": -1}},
        ]

        agent_entries: list[dict] = []
        async for doc in decisions_coll.aggregate(agent_pipeline):
            agent_id = doc["_id"]
            # Look up agent profile for name and roles
            profile = await profiles_coll.find_one({"agent_id": agent_id})
            entry = CERTInAgentEntry(
                agent_id=agent_id,
                agent_name=profile.get("name", agent_id) if profile else agent_id,
                roles=profile.get("roles", []) if profile else [],
                tools_accessed=doc.get("tools", []),
                total_decisions=doc.get("total_decisions", 0),
                deny_count=doc.get("deny_count", 0),
                risk_score_avg=round(doc.get("avg_risk", 0.0), 4),
                first_seen=doc.get("first_seen"),
                last_seen=doc.get("last_seen"),
            )
            agent_entries.append(entry.model_dump(mode="json"))

        # --- Section 2: Security Alert Summary ---
        alert_pipeline = [
            {"$match": time_filter},
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "critical": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "CRITICAL"]}, 1, 0]}
                    },
                    "high": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "HIGH"]}, 1, 0]}
                    },
                    "medium": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "MEDIUM"]}, 1, 0]}
                    },
                    "low": {
                        "$sum": {"$cond": [{"$eq": ["$severity", "LOW"]}, 1, 0]}
                    },
                }
            },
        ]

        alert_summary = CERTInSecurityAlertSummary()
        async for doc in alerts_coll.aggregate(alert_pipeline):
            alert_summary.total_alerts = doc.get("total", 0)
            alert_summary.critical_alerts = doc.get("critical", 0)
            alert_summary.high_alerts = doc.get("high", 0)
            alert_summary.medium_alerts = doc.get("medium", 0)
            alert_summary.low_alerts = doc.get("low", 0)

        # Alert type distribution
        type_pipeline = [
            {"$match": time_filter},
            {"$group": {"_id": "$alert_type", "count": {"$sum": 1}}},
        ]
        alert_types: dict[str, int] = {}
        async for doc in alerts_coll.aggregate(type_pipeline):
            alert_types[doc["_id"]] = doc["count"]
        alert_summary.alert_types = alert_types

        # --- Section 3: Incident Timeline ---
        timeline_cursor = alerts_coll.find(time_filter).sort("timestamp", 1)
        incident_timeline: list[dict] = []
        async for doc in timeline_cursor:
            incident_timeline.append(
                {
                    "alert_id": str(doc.get("alert_id", "")),
                    "alert_type": doc.get("alert_type", ""),
                    "severity": doc.get("severity", ""),
                    "agent_id": doc.get("agent_id", ""),
                    "tool_name": doc.get("tool_name", ""),
                    "detail": doc.get("detail", ""),
                    "timestamp": doc.get("timestamp", "").isoformat()
                    if isinstance(doc.get("timestamp"), datetime)
                    else str(doc.get("timestamp", "")),
                }
            )

        # --- Section 4 (Sprint 41 — APEP-330): Checkpoint Escalation Summary ---
        checkpoint_coll = db[CHECKPOINT_ESCALATION_HISTORY]
        cp_pipeline = [
            {"$match": {"created_at": {"$gte": period_start, "$lte": period_end}}},
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "patterns": {"$addToSet": "$matched_pattern"},
                    "agents": {"$addToSet": "$agent_id"},
                    "intents": {"$addToSet": "$human_intent"},
                }
            },
        ]

        checkpoint_summary = CERTInCheckpointSummary()
        async for doc in checkpoint_coll.aggregate(cp_pipeline):
            checkpoint_summary.total_checkpoint_escalations = doc.get("total", 0)
            checkpoint_summary.checkpoint_patterns = doc.get("patterns", [])
            checkpoint_summary.agents_with_checkpoints = doc.get("agents", [])
            raw_intents = doc.get("intents", [])
            checkpoint_summary.human_intents = [
                i for i in raw_intents if i
            ]

        report.content = {
            "agent_bill_of_materials": agent_entries,
            "security_alert_summary": alert_summary.model_dump(mode="json"),
            "incident_timeline": incident_timeline,
            "checkpoint_escalation_summary": checkpoint_summary.model_dump(
                mode="json"
            ),
        }
        report.status = ReportStatus.COMPLETED
        report.generated_at = datetime.now(UTC)

    except Exception as exc:
        logger.exception("Failed to generate CERT-In BOM report")
        report.status = ReportStatus.FAILED
        report.error_message = str(exc)

    return report
