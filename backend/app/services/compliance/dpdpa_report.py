"""APEP-172: DPDPA compliance report generator.

Generates a Digital Personal Data Protection Act (India) compliance report
covering data processing decisions, taint events, and DENY logs for a
specified time period.
"""

import logging
from datetime import UTC, datetime

from app.db.mongodb import (
    AUDIT_DECISIONS,
    CHECKPOINT_ESCALATION_HISTORY,
    TAINT_AUDIT_EVENTS,
    get_database,
)
from app.models.compliance import (
    ComplianceReport,
    DPDPACheckpointSummary,
    DPDPADataProcessingSummary,
    DPDPADenyLog,
    DPDPATaintSummary,
    ReportStatus,
    ReportType,
)

logger = logging.getLogger(__name__)


async def generate_dpdpa_report(
    period_start: datetime,
    period_end: datetime,
) -> ComplianceReport:
    """Generate a DPDPA compliance report for the given period.

    Sections:
    1. Data Processing Summary — totals of ALLOW/DENY/ESCALATE decisions
    2. Taint Event Summary — quarantine, cross-agent propagation, sanitisation counts
    3. DENY Log — detailed list of every DENY decision with agent, tool, risk score
    """
    db = get_database()
    report = ComplianceReport(
        report_type=ReportType.DPDPA,
        title=f"DPDPA Compliance Report ({period_start:%Y-%m-%d} to {period_end:%Y-%m-%d})",
        status=ReportStatus.GENERATING,
        period_start=period_start,
        period_end=period_end,
    )

    try:
        # --- Section 1: Data Processing Summary ---
        time_filter = {"timestamp": {"$gte": period_start, "$lte": period_end}}
        decisions_coll = db[AUDIT_DECISIONS]

        pipeline = [
            {"$match": time_filter},
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "allow": {"$sum": {"$cond": [{"$eq": ["$decision", "ALLOW"]}, 1, 0]}},
                    "deny": {"$sum": {"$cond": [{"$eq": ["$decision", "DENY"]}, 1, 0]}},
                    "escalate": {
                        "$sum": {"$cond": [{"$eq": ["$decision", "ESCALATE"]}, 1, 0]}
                    },
                    "agents": {"$addToSet": "$agent_id"},
                    "tools": {"$addToSet": "$tool_name"},
                }
            },
        ]

        summary_data = DPDPADataProcessingSummary(
            period_start=period_start,
            period_end=period_end,
        )

        async for doc in decisions_coll.aggregate(pipeline):
            summary_data.total_decisions = doc.get("total", 0)
            summary_data.allow_count = doc.get("allow", 0)
            summary_data.deny_count = doc.get("deny", 0)
            summary_data.escalate_count = doc.get("escalate", 0)
            summary_data.unique_agents = len(doc.get("agents", []))
            summary_data.unique_tools = len(doc.get("tools", []))

        # --- Section 2: Taint Event Summary ---
        taint_coll = db[TAINT_AUDIT_EVENTS]
        taint_filter = {"timestamp": {"$gte": period_start, "$lte": period_end}}

        taint_pipeline = [
            {"$match": taint_filter},
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "quarantine": {
                        "$sum": {
                            "$cond": [{"$eq": ["$event_type", "TAINT_QUARANTINED"]}, 1, 0]
                        }
                    },
                    "cross_agent": {
                        "$sum": {
                            "$cond": [
                                {"$eq": ["$event_type", "CROSS_AGENT_PROPAGATED"]},
                                1,
                                0,
                            ]
                        }
                    },
                    "sanitised": {
                        "$sum": {
                            "$cond": [{"$eq": ["$event_type", "TAINT_DOWNGRADED"]}, 1, 0]
                        }
                    },
                }
            },
        ]

        taint_summary = DPDPATaintSummary()
        async for doc in taint_coll.aggregate(taint_pipeline):
            taint_summary.total_taint_events = doc.get("total", 0)
            taint_summary.quarantine_events = doc.get("quarantine", 0)
            taint_summary.cross_agent_propagations = doc.get("cross_agent", 0)
            taint_summary.sanitisation_events = doc.get("sanitised", 0)

        # --- Section 3: DENY Log ---
        deny_cursor = decisions_coll.find(
            {**time_filter, "decision": "DENY"},
        ).sort("timestamp", -1)

        deny_log: list[dict] = []
        async for doc in deny_cursor:
            entry = DPDPADenyLog(
                decision_id=str(doc.get("decision_id", "")),
                timestamp=doc["timestamp"],
                agent_id=doc.get("agent_id", ""),
                tool_name=doc.get("tool_name", ""),
                risk_score=doc.get("risk_score", 0.0),
                reason=doc.get("reason", ""),
            )
            deny_log.append(entry.model_dump(mode="json"))

        # --- Section 4 (Sprint 41 — APEP-330): Checkpoint Escalation Summary ---
        checkpoint_coll = db[CHECKPOINT_ESCALATION_HISTORY]
        checkpoint_pipeline = [
            {"$match": {"created_at": {"$gte": period_start, "$lte": period_end}}},
            {
                "$group": {
                    "_id": None,
                    "total": {"$sum": 1},
                    "patterns": {"$addToSet": "$matched_pattern"},
                    "agents": {"$addToSet": "$agent_id"},
                }
            },
        ]

        checkpoint_summary = DPDPACheckpointSummary()
        async for doc in checkpoint_coll.aggregate(checkpoint_pipeline):
            checkpoint_summary.total_checkpoint_escalations = doc.get("total", 0)
            checkpoint_summary.unique_patterns = len(doc.get("patterns", []))
            checkpoint_summary.unique_agents = len(doc.get("agents", []))

        # Count approved/denied/pending from escalation tickets with checkpoint_match_reason
        from app.db.mongodb import ESCALATION_TICKETS

        esc_coll = db[ESCALATION_TICKETS]
        esc_checkpoint_pipeline = [
            {
                "$match": {
                    "created_at": {"$gte": period_start, "$lte": period_end},
                    "checkpoint_match_reason": {"$ne": None},
                }
            },
            {
                "$group": {
                    "_id": None,
                    "approved": {
                        "$sum": {"$cond": [{"$eq": ["$state", "APPROVED"]}, 1, 0]}
                    },
                    "denied": {
                        "$sum": {"$cond": [{"$eq": ["$state", "DENIED"]}, 1, 0]}
                    },
                    "pending": {
                        "$sum": {"$cond": [{"$eq": ["$state", "PENDING"]}, 1, 0]}
                    },
                }
            },
        ]
        async for doc in esc_coll.aggregate(esc_checkpoint_pipeline):
            checkpoint_summary.approved_checkpoints = doc.get("approved", 0)
            checkpoint_summary.denied_checkpoints = doc.get("denied", 0)
            checkpoint_summary.pending_checkpoints = doc.get("pending", 0)

        report.content = {
            "data_processing_summary": summary_data.model_dump(mode="json"),
            "taint_event_summary": taint_summary.model_dump(mode="json"),
            "deny_log": deny_log,
            "checkpoint_escalation_summary": checkpoint_summary.model_dump(
                mode="json"
            ),
        }
        report.status = ReportStatus.COMPLETED
        report.generated_at = datetime.now(UTC)

    except Exception as exc:
        logger.exception("Failed to generate DPDPA report")
        report.status = ReportStatus.FAILED
        report.error_message = str(exc)

    return report
