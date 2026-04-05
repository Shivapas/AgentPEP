"""Sprint 16 — Risk Dashboard API endpoints (APEP-128 to APEP-134).

Provides aggregated data for the Policy Console Risk Dashboard:
- Risk heatmap (agent × tool matrix)
- Decision trend over time
- Top blocked tools
- Risk score distribution
- Anomaly detection (DENY rate > 2σ)
"""

import logging
import math
from datetime import datetime, timedelta, timezone, UTC
from enum import Enum
from typing import Any

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from app.api.v1.console_auth import get_current_user
from app.db.mongodb import API_KEYS, AUDIT_DECISIONS, get_database

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/dashboard", tags=["dashboard"])


# --- Time Window ---


class TimeWindow(str, Enum):
    ONE_HOUR = "1h"
    SIX_HOURS = "6h"
    TWENTY_FOUR_HOURS = "24h"
    SEVEN_DAYS = "7d"
    THIRTY_DAYS = "30d"


WINDOW_DELTAS: dict[TimeWindow, timedelta] = {
    TimeWindow.ONE_HOUR: timedelta(hours=1),
    TimeWindow.SIX_HOURS: timedelta(hours=6),
    TimeWindow.TWENTY_FOUR_HOURS: timedelta(hours=24),
    TimeWindow.SEVEN_DAYS: timedelta(days=7),
    TimeWindow.THIRTY_DAYS: timedelta(days=30),
}

# Number of time buckets for the trend chart per window
WINDOW_BUCKETS: dict[TimeWindow, int] = {
    TimeWindow.ONE_HOUR: 12,       # 5-min buckets
    TimeWindow.SIX_HOURS: 24,      # 15-min buckets
    TimeWindow.TWENTY_FOUR_HOURS: 24,  # 1-hr buckets
    TimeWindow.SEVEN_DAYS: 28,     # 6-hr buckets
    TimeWindow.THIRTY_DAYS: 30,    # 1-day buckets
}


def _window_start(window: TimeWindow) -> datetime:
    # Use naive UTC datetime for MongoDB compatibility (mongomock
    # aggregation pipelines cannot mix aware/naive datetimes).
    return datetime.now(UTC).replace(tzinfo=None) - WINDOW_DELTAS[window]


# --- Response Models ---


class HeatmapCell(BaseModel):
    agent_id: str
    tool_name: str
    avg_risk_score: float
    count: int


class TrendBucket(BaseModel):
    timestamp: str
    allow: int = 0
    deny: int = 0
    escalate: int = 0


class BlockedTool(BaseModel):
    tool_name: str
    deny_count: int
    escalate_count: int
    top_agents: list[str] = Field(default_factory=list)


class HistogramBin(BaseModel):
    bin_start: float
    bin_end: float
    count: int


class AnomalyAgent(BaseModel):
    agent_id: str
    deny_rate: float
    mean_deny_rate: float
    std_deny_rate: float
    sigma_distance: float
    total_decisions: int
    deny_count: int


class DashboardSummary(BaseModel):
    heatmap: list[HeatmapCell]
    trend: list[TrendBucket]
    top_blocked: list[BlockedTool]
    histogram: list[HistogramBin]
    anomalies: list[AnomalyAgent]
    window: str
    generated_at: str


# --- Aggregation Helpers ---


async def _build_heatmap(since: datetime) -> list[HeatmapCell]:
    """APEP-128: agent × tool matrix coloured by average risk score."""
    db = get_database()
    pipeline: list[dict[str, Any]] = [
        {"$match": {"timestamp": {"$gte": since}}},
        {
            "$group": {
                "_id": {"agent_id": "$agent_id", "tool_name": "$tool_name"},
                "avg_risk_score": {"$avg": "$risk_score"},
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"count": -1}},
        {"$limit": 500},
    ]
    cells: list[HeatmapCell] = []
    async for doc in db[AUDIT_DECISIONS].aggregate(pipeline):
        cells.append(
            HeatmapCell(
                agent_id=doc["_id"]["agent_id"],
                tool_name=doc["_id"]["tool_name"],
                avg_risk_score=round(doc["avg_risk_score"], 4),
                count=doc["count"],
            )
        )
    return cells


async def _build_trend(since: datetime, window: TimeWindow) -> list[TrendBucket]:
    """APEP-129: ALLOW/DENY/ESCALATE rates over time buckets."""
    db = get_database()
    num_buckets = WINDOW_BUCKETS[window]
    total_seconds = WINDOW_DELTAS[window].total_seconds()
    bucket_seconds = total_seconds / num_buckets

    pipeline: list[dict[str, Any]] = [
        {"$match": {"timestamp": {"$gte": since}}},
        {
            "$addFields": {
                "bucket": {
                    "$floor": {
                        "$divide": [
                            {"$subtract": ["$timestamp", since]},
                            bucket_seconds * 1000,  # milliseconds
                        ]
                    }
                }
            }
        },
        {
            "$group": {
                "_id": {"bucket": "$bucket", "decision": "$decision"},
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"_id.bucket": 1}},
    ]

    raw: dict[int, dict[str, int]] = {}
    async for doc in db[AUDIT_DECISIONS].aggregate(pipeline):
        b = int(doc["_id"]["bucket"])
        decision = doc["_id"]["decision"]
        if b not in raw:
            raw[b] = {}
        raw[b][decision] = doc["count"]

    buckets: list[TrendBucket] = []
    for i in range(num_buckets):
        ts = since + timedelta(seconds=bucket_seconds * i)
        data = raw.get(i, {})
        buckets.append(
            TrendBucket(
                timestamp=ts.isoformat() + "Z",
                allow=data.get("ALLOW", 0),
                deny=data.get("DENY", 0),
                escalate=data.get("ESCALATE", 0),
            )
        )
    return buckets


async def _build_top_blocked(since: datetime, limit: int = 10) -> list[BlockedTool]:
    """APEP-130: tools ranked by DENY count."""
    db = get_database()
    pipeline: list[dict[str, Any]] = [
        {"$match": {"timestamp": {"$gte": since}, "decision": {"$in": ["DENY", "ESCALATE"]}}},
        {
            "$group": {
                "_id": "$tool_name",
                "deny_count": {
                    "$sum": {"$cond": [{"$eq": ["$decision", "DENY"]}, 1, 0]}
                },
                "escalate_count": {
                    "$sum": {"$cond": [{"$eq": ["$decision", "ESCALATE"]}, 1, 0]}
                },
                "agents": {"$addToSet": "$agent_id"},
            }
        },
        {"$sort": {"deny_count": -1}},
        {"$limit": limit},
    ]
    results: list[BlockedTool] = []
    async for doc in db[AUDIT_DECISIONS].aggregate(pipeline):
        results.append(
            BlockedTool(
                tool_name=doc["_id"],
                deny_count=doc["deny_count"],
                escalate_count=doc["escalate_count"],
                top_agents=doc["agents"][:5],
            )
        )
    return results


async def _build_histogram(since: datetime, num_bins: int = 10) -> list[HistogramBin]:
    """APEP-131: risk score distribution histogram."""
    db = get_database()
    bin_width = 1.0 / num_bins
    pipeline: list[dict[str, Any]] = [
        {"$match": {"timestamp": {"$gte": since}}},
        {
            "$addFields": {
                "bin": {
                    "$min": [
                        {"$floor": {"$divide": ["$risk_score", bin_width]}},
                        num_bins - 1,
                    ]
                }
            }
        },
        {"$group": {"_id": "$bin", "count": {"$sum": 1}}},
        {"$sort": {"_id": 1}},
    ]
    raw: dict[int, int] = {}
    async for doc in db[AUDIT_DECISIONS].aggregate(pipeline):
        raw[int(doc["_id"])] = doc["count"]

    bins: list[HistogramBin] = []
    for i in range(num_bins):
        bins.append(
            HistogramBin(
                bin_start=round(i * bin_width, 2),
                bin_end=round((i + 1) * bin_width, 2),
                count=raw.get(i, 0),
            )
        )
    return bins


async def _detect_anomalies(since: datetime) -> list[AnomalyAgent]:
    """APEP-134: flag agents with DENY rate > 2σ from baseline."""
    db = get_database()
    pipeline: list[dict[str, Any]] = [
        {"$match": {"timestamp": {"$gte": since}}},
        {
            "$group": {
                "_id": "$agent_id",
                "total": {"$sum": 1},
                "deny_count": {
                    "$sum": {"$cond": [{"$eq": ["$decision", "DENY"]}, 1, 0]}
                },
            }
        },
    ]
    agents: list[dict[str, Any]] = []
    async for doc in db[AUDIT_DECISIONS].aggregate(pipeline):
        total = doc["total"]
        deny = doc["deny_count"]
        rate = deny / total if total > 0 else 0.0
        agents.append(
            {"agent_id": doc["_id"], "total": total, "deny": deny, "rate": rate}
        )

    if len(agents) < 2:
        return []

    rates = [a["rate"] for a in agents]
    mean_rate = sum(rates) / len(rates)
    variance = sum((r - mean_rate) ** 2 for r in rates) / len(rates)
    std_rate = math.sqrt(variance) if variance > 0 else 0.0

    if std_rate == 0:
        return []

    anomalies: list[AnomalyAgent] = []
    for a in agents:
        sigma_dist = (a["rate"] - mean_rate) / std_rate
        if sigma_dist > 2.0:
            anomalies.append(
                AnomalyAgent(
                    agent_id=a["agent_id"],
                    deny_rate=round(a["rate"], 4),
                    mean_deny_rate=round(mean_rate, 4),
                    std_deny_rate=round(std_rate, 4),
                    sigma_distance=round(sigma_dist, 2),
                    total_decisions=a["total"],
                    deny_count=a["deny"],
                )
            )
    return sorted(anomalies, key=lambda x: x.sigma_distance, reverse=True)


# --- REST Endpoints ---


@router.get("/summary", response_model=DashboardSummary)
async def get_dashboard_summary(
    window: TimeWindow = Query(default=TimeWindow.TWENTY_FOUR_HOURS),
    _user: dict = Depends(get_current_user),
) -> DashboardSummary:
    """Return full dashboard summary for the given time window."""
    since = _window_start(window)
    heatmap, trend, top_blocked, histogram, anomalies = (
        await _build_heatmap(since),
        await _build_trend(since, window),
        await _build_top_blocked(since),
        await _build_histogram(since),
        await _detect_anomalies(since),
    )
    return DashboardSummary(
        heatmap=heatmap,
        trend=trend,
        top_blocked=top_blocked,
        histogram=histogram,
        anomalies=anomalies,
        window=window.value,
        generated_at=datetime.now(UTC).isoformat() + "Z",
    )


@router.get("/heatmap", response_model=list[HeatmapCell])
async def get_heatmap(
    window: TimeWindow = Query(default=TimeWindow.TWENTY_FOUR_HOURS),
    _user: dict = Depends(get_current_user),
) -> list[HeatmapCell]:
    """APEP-128: Risk heatmap data."""
    return await _build_heatmap(_window_start(window))


@router.get("/trend", response_model=list[TrendBucket])
async def get_trend(
    window: TimeWindow = Query(default=TimeWindow.TWENTY_FOUR_HOURS),
    _user: dict = Depends(get_current_user),
) -> list[TrendBucket]:
    """APEP-129: Decision trend buckets."""
    return await _build_trend(_window_start(window), window)


@router.get("/top-blocked", response_model=list[BlockedTool])
async def get_top_blocked(
    window: TimeWindow = Query(default=TimeWindow.TWENTY_FOUR_HOURS),
    limit: int = Query(default=10, ge=1, le=50),
    _user: dict = Depends(get_current_user),
) -> list[BlockedTool]:
    """APEP-130: Top blocked tools."""
    return await _build_top_blocked(_window_start(window), limit)


@router.get("/histogram", response_model=list[HistogramBin])
async def get_histogram(
    window: TimeWindow = Query(default=TimeWindow.TWENTY_FOUR_HOURS),
    _user: dict = Depends(get_current_user),
) -> list[HistogramBin]:
    """APEP-131: Risk score distribution."""
    return await _build_histogram(_window_start(window))


@router.get("/anomalies", response_model=list[AnomalyAgent])
async def get_anomalies(
    window: TimeWindow = Query(default=TimeWindow.TWENTY_FOUR_HOURS),
    _user: dict = Depends(get_current_user),
) -> list[AnomalyAgent]:
    """APEP-134: Anomalous agents."""
    return await _detect_anomalies(_window_start(window))


# --- WebSocket (APEP-133) ---

_ws_connections: set[WebSocket] = set()


@router.websocket("/ws")
async def dashboard_ws(websocket: WebSocket) -> None:
    """APEP-133: WebSocket for real-time dashboard updates.

    Clients connect and receive periodic dashboard summary pushes,
    or can send a JSON message with {"window": "1h"} to change their window.
    """
    # Authenticate before accepting the connection
    token = websocket.query_params.get("token")
    api_key = websocket.query_params.get("api_key")
    if api_key:
        db = get_database()
        key_record = await db[API_KEYS].find_one({"key": api_key, "enabled": True})
        if not key_record:
            await websocket.close(code=4003, reason="Invalid API key")
            return
    elif token:
        from app.services.jwt_auth import decode_token

        payload = decode_token(token)
        if payload is None or payload.get("type") != "access":
            await websocket.close(code=4001, reason="Invalid or expired token")
            return
    else:
        await websocket.close(
            code=4001,
            reason="Authentication required: provide token or api_key query param",
        )
        return

    await websocket.accept()
    _ws_connections.add(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            window_str = data.get("window", "24h")
            try:
                window = TimeWindow(window_str)
            except ValueError:
                window = TimeWindow.TWENTY_FOUR_HOURS
            since = _window_start(window)
            summary = DashboardSummary(
                heatmap=await _build_heatmap(since),
                trend=await _build_trend(since, window),
                top_blocked=await _build_top_blocked(since),
                histogram=await _build_histogram(since),
                anomalies=await _detect_anomalies(since),
                window=window.value,
                generated_at=datetime.now(UTC).isoformat() + "Z",
            )
            await websocket.send_json(summary.model_dump())
    except WebSocketDisconnect:
        pass
    finally:
        _ws_connections.discard(websocket)


async def broadcast_dashboard_update(window: TimeWindow = TimeWindow.TWENTY_FOUR_HOURS) -> None:
    """Broadcast dashboard update to all connected WebSocket clients."""
    if not _ws_connections:
        return
    since = _window_start(window)
    summary = DashboardSummary(
        heatmap=await _build_heatmap(since),
        trend=await _build_trend(since, window),
        top_blocked=await _build_top_blocked(since),
        histogram=await _build_histogram(since),
        anomalies=await _detect_anomalies(since),
        window=window.value,
        generated_at=datetime.now(UTC).isoformat() + "Z",
    )
    data = summary.model_dump()
    dead: set[WebSocket] = set()
    for ws in list(_ws_connections):
        try:
            await ws.send_json(data)
        except Exception:
            dead.add(ws)
    _ws_connections.difference_update(dead)
