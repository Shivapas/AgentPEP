"""Console API — endpoints for the Policy Console UI and beta friction fixes (APEP-215).

Provides:
- GET /v1/stats — Dashboard statistics
- GET /v1/audit — Queryable audit log
- GET /v1/rules — List policy rules
- GET /v1/agents — List agent profiles
- POST /v1/ux-survey — Submit UX survey responses
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.db.mongodb import (
    AGENT_PROFILES,
    AUDIT_DECISIONS,
    POLICY_RULES,
    get_database,
)

router = APIRouter(prefix="/v1", tags=["console"])

UX_SURVEYS = "ux_surveys"


# --- Stats endpoint (APEP-215 friction #3) ---


class DashboardStats(BaseModel):
    policy_rules: int = 0
    decisions_today: int = 0
    active_agents: int = 0
    deny_rate: float = 0.0
    avg_latency_ms: int = 0
    escalations_pending: int = 0


@router.get("/stats", response_model=DashboardStats)
async def get_stats() -> DashboardStats:
    """Get dashboard statistics for the Policy Console."""
    db = get_database()

    # Count policy rules
    rule_count = await db[POLICY_RULES].count_documents({"enabled": True})

    # Count today's decisions
    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    today_filter = {"timestamp": {"$gte": today_start}}
    decisions_today = await db[AUDIT_DECISIONS].count_documents(today_filter)

    # Count active agents
    active_agents = await db[AGENT_PROFILES].count_documents({"enabled": True})

    # Calculate deny rate
    deny_count = await db[AUDIT_DECISIONS].count_documents(
        {**today_filter, "decision": "DENY"}
    )
    deny_rate = deny_count / max(decisions_today, 1)

    # Average latency
    try:
        pipeline = [
            {"$match": today_filter},
            {"$group": {"_id": None, "avg_latency": {"$avg": "$latency_ms"}}},
        ]
        cursor = db[AUDIT_DECISIONS].aggregate(pipeline)
        avg_result = await cursor.to_list(length=1)
        avg_latency = int(avg_result[0]["avg_latency"]) if avg_result else 0
    except Exception:
        avg_latency = 0

    # Escalations pending
    escalations = await db[AUDIT_DECISIONS].count_documents(
        {**today_filter, "decision": "ESCALATE"}
    )

    return DashboardStats(
        policy_rules=rule_count,
        decisions_today=decisions_today,
        active_agents=active_agents,
        deny_rate=round(deny_rate, 3),
        avg_latency_ms=avg_latency,
        escalations_pending=escalations,
    )


# --- Audit log query endpoint (APEP-215 friction #8) ---


class AuditListResponse(BaseModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0


@router.get("/audit", response_model=AuditListResponse)
async def list_audit(
    decision: str | None = Query(default=None, description="Filter by decision type"),
    agent_id: str | None = Query(default=None, description="Filter by agent ID"),
    tool_name: str | None = Query(default=None, description="Filter by tool name"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AuditListResponse:
    """Query the audit decision log with optional filtering."""
    db = get_database()
    query: dict[str, Any] = {}

    if decision:
        query["decision"] = decision
    if agent_id:
        query["agent_id"] = agent_id
    if tool_name:
        import re
        query["tool_name"] = {"$regex": re.escape(tool_name), "$options": "i"}

    total = await db[AUDIT_DECISIONS].count_documents(query)
    cursor = (
        db[AUDIT_DECISIONS]
        .find(query, {"_id": 0})
        .sort("timestamp", -1)
        .skip(offset)
        .limit(limit)
    )
    items = await cursor.to_list(length=limit)

    return AuditListResponse(items=items, total=total)


# --- Policy rules list endpoint ---


class RulesListResponse(BaseModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0


@router.get("/rules", response_model=RulesListResponse)
async def list_rules(
    limit: int = Query(default=100, ge=1, le=500),
) -> RulesListResponse:
    """List all policy rules sorted by priority."""
    db = get_database()
    total = await db[POLICY_RULES].count_documents({})
    cursor = db[POLICY_RULES].find({}, {"_id": 0}).sort("priority", 1).limit(limit)
    items = await cursor.to_list(length=limit)
    return RulesListResponse(items=items, total=total)


# --- Agent profiles list endpoint ---


class AgentsListResponse(BaseModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0


@router.get("/console/agents", response_model=AgentsListResponse)
async def list_agents(
    limit: int = Query(default=100, ge=1, le=500),
) -> AgentsListResponse:
    """List all agent profiles."""
    db = get_database()
    total = await db[AGENT_PROFILES].count_documents({})
    cursor = db[AGENT_PROFILES].find({}, {"_id": 0}).sort("agent_id", 1).limit(limit)
    items = await cursor.to_list(length=limit)
    return AgentsListResponse(items=items, total=total)


# --- UX Survey endpoint (APEP-214) ---


class UXSurveyRequest(BaseModel):
    responses: list[int] = Field(..., min_length=10, max_length=10)
    score: float
    additional_feedback: str = ""
    timestamp: str = ""


@router.post("/ux-survey", status_code=201)
async def submit_ux_survey(request: UXSurveyRequest) -> dict[str, str]:
    """Submit a UX survey (SUS) response."""
    db = get_database()
    await db[UX_SURVEYS].insert_one(
        {
            "responses": request.responses,
            "score": request.score,
            "additional_feedback": request.additional_feedback,
            "timestamp": request.timestamp or datetime.now(timezone.utc).isoformat(),
        }
    )
    return {"status": "recorded"}
