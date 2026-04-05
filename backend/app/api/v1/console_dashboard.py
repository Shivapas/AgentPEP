"""Console dashboard endpoints for KPI data (APEP-110)."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends

from app.api.v1.console_auth import get_current_user
from app.db import mongodb as db_module

router = APIRouter(prefix="/v1/console", tags=["console-dashboard"])


@router.get("/dashboard/kpis")
async def get_dashboard_kpis(user: dict = Depends(get_current_user)):
    """Return KPI metrics for the dashboard homepage."""
    db = db_module.get_database()
    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # Decisions in the last hour
    decisions_last_hour = await db["audit_decisions"].count_documents(
        {"timestamp": {"$gte": one_hour_ago}}
    )

    # Total decisions today
    decisions_today = await db["audit_decisions"].count_documents(
        {"timestamp": {"$gte": today_start}}
    )

    # DENY rate today
    denies_today = await db["audit_decisions"].count_documents(
        {"timestamp": {"$gte": today_start}, "decision": "DENY"}
    )
    deny_rate = (denies_today / decisions_today * 100) if decisions_today > 0 else 0.0

    # Pending escalations (ESCALATE decisions without resolution)
    pending_escalations = await db["audit_decisions"].count_documents(
        {"decision": "ESCALATE"}
    )

    # Active agents (distinct agent_ids in last 24h)
    one_day_ago = now - timedelta(days=1)
    active_agent_ids = await db["audit_decisions"].distinct(
        "agent_id", {"timestamp": {"$gte": one_day_ago}}
    )
    active_agents = len(active_agent_ids)

    # Total policy rules
    total_rules = await db["policy_rules"].count_documents({"enabled": True})

    # Security alerts in last 24h
    alerts_24h = await db["security_alerts"].count_documents(
        {"timestamp": {"$gte": one_day_ago}}
    )

    return {
        "decisions_per_hour": decisions_last_hour,
        "decisions_today": decisions_today,
        "deny_rate": round(deny_rate, 1),
        "pending_escalations": pending_escalations,
        "active_agents": active_agents,
        "total_rules": total_rules,
        "security_alerts_24h": alerts_24h,
    }
