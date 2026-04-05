"""Sprint 16 — Tests for Risk Dashboard API endpoints (APEP-128 to APEP-135)."""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.db.mongodb import AUDIT_DECISIONS, get_database
from app.main import app


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


async def _insert_decisions(decisions: list[dict]) -> None:
    """Insert audit decision documents into MongoDB."""
    db = get_database()
    if decisions:
        await db[AUDIT_DECISIONS].insert_many(decisions)


def _make_decision(
    agent_id: str = "agent-1",
    tool_name: str = "tool-a",
    decision: str = "ALLOW",
    risk_score: float = 0.3,
    minutes_ago: int = 30,
) -> dict:
    return {
        "decision_id": str(uuid4()),
        "session_id": "sess-1",
        "agent_id": agent_id,
        "agent_role": "worker",
        "tool_name": tool_name,
        "tool_args_hash": "abc123",
        "taint_flags": [],
        "risk_score": risk_score,
        "delegation_chain": [],
        "matched_rule_id": None,
        "decision": decision,
        "escalation_id": None,
        "latency_ms": 5,
        "timestamp": datetime.utcnow() - timedelta(minutes=minutes_ago),
    }


# --- Dashboard Summary ---


@pytest.mark.asyncio
async def test_dashboard_summary_empty(client: AsyncClient) -> None:
    """Dashboard returns valid structure even with no data."""
    resp = await client.get("/v1/dashboard/summary?window=1h")
    assert resp.status_code == 200
    body = resp.json()
    assert body["window"] == "1h"
    assert body["heatmap"] == []
    assert body["trend"] is not None
    assert body["top_blocked"] == []
    assert body["histogram"] is not None
    assert body["anomalies"] == []


@pytest.mark.asyncio
async def test_dashboard_summary_with_data(client: AsyncClient) -> None:
    """Dashboard aggregates decision data correctly."""
    await _insert_decisions(
        [
            _make_decision("agent-1", "tool-a", "ALLOW", 0.2, 10),
            _make_decision("agent-1", "tool-a", "DENY", 0.8, 15),
            _make_decision("agent-2", "tool-b", "ALLOW", 0.1, 20),
            _make_decision("agent-2", "tool-b", "ESCALATE", 0.7, 25),
        ]
    )
    resp = await client.get("/v1/dashboard/summary?window=1h")
    assert resp.status_code == 200
    body = resp.json()

    # Heatmap should have entries
    assert len(body["heatmap"]) > 0

    # Top blocked should include tool-a (DENY) and tool-b (ESCALATE)
    blocked_tools = {t["tool_name"] for t in body["top_blocked"]}
    assert "tool-a" in blocked_tools or "tool-b" in blocked_tools

    # Histogram should have 10 bins
    assert len(body["histogram"]) == 10


# --- Heatmap (APEP-128) ---


@pytest.mark.asyncio
async def test_heatmap_endpoint(client: AsyncClient) -> None:
    await _insert_decisions(
        [
            _make_decision("agent-1", "tool-x", "ALLOW", 0.5, 10),
            _make_decision("agent-1", "tool-x", "ALLOW", 0.7, 15),
        ]
    )
    resp = await client.get("/v1/dashboard/heatmap?window=1h")
    assert resp.status_code == 200
    cells = resp.json()
    assert len(cells) == 1
    assert cells[0]["agent_id"] == "agent-1"
    assert cells[0]["tool_name"] == "tool-x"
    # Average of 0.5 and 0.7
    assert abs(cells[0]["avg_risk_score"] - 0.6) < 0.01
    assert cells[0]["count"] == 2


# --- Trend (APEP-129) ---


@pytest.mark.asyncio
async def test_trend_endpoint(client: AsyncClient) -> None:
    await _insert_decisions(
        [
            _make_decision("agent-1", "tool-a", "ALLOW", 0.2, 5),
            _make_decision("agent-1", "tool-a", "DENY", 0.8, 10),
        ]
    )
    resp = await client.get("/v1/dashboard/trend?window=1h")
    assert resp.status_code == 200
    buckets = resp.json()
    # Should have 12 buckets for 1h window
    assert len(buckets) == 12


# --- Top Blocked (APEP-130) ---


@pytest.mark.asyncio
async def test_top_blocked_endpoint(client: AsyncClient) -> None:
    await _insert_decisions(
        [
            _make_decision("agent-1", "dangerous-tool", "DENY", 0.9, 5),
            _make_decision("agent-1", "dangerous-tool", "DENY", 0.85, 10),
            _make_decision("agent-2", "dangerous-tool", "DENY", 0.95, 15),
            _make_decision("agent-1", "safe-tool", "ALLOW", 0.1, 20),
        ]
    )
    resp = await client.get("/v1/dashboard/top-blocked?window=1h")
    assert resp.status_code == 200
    blocked = resp.json()
    assert len(blocked) == 1  # only dangerous-tool had DENYs
    assert blocked[0]["tool_name"] == "dangerous-tool"
    assert blocked[0]["deny_count"] == 3
    assert set(blocked[0]["top_agents"]) == {"agent-1", "agent-2"}


# --- Histogram (APEP-131) ---


@pytest.mark.asyncio
async def test_histogram_endpoint(client: AsyncClient) -> None:
    await _insert_decisions(
        [
            _make_decision("a", "t", "ALLOW", 0.05, 5),
            _make_decision("a", "t", "ALLOW", 0.15, 10),
            _make_decision("a", "t", "ALLOW", 0.95, 15),
        ]
    )
    resp = await client.get("/v1/dashboard/histogram?window=1h")
    assert resp.status_code == 200
    bins = resp.json()
    assert len(bins) == 10
    # First bin (0.0-0.1) should have 1 decision
    assert bins[0]["count"] == 1
    # Second bin (0.1-0.2) should have 1 decision
    assert bins[1]["count"] == 1
    # Last bin (0.9-1.0) should have 1 decision
    assert bins[9]["count"] == 1


# --- Anomaly Detection (APEP-134) ---


@pytest.mark.asyncio
async def test_anomaly_detection(client: AsyncClient) -> None:
    """Agent with high DENY rate vs others should be flagged (>2σ)."""
    decisions = []
    # 9 normal agents with ~5% deny rate each
    for agent_num in range(9):
        agent_name = f"agent-normal-{agent_num}"
        for i in range(19):
            decisions.append(_make_decision(agent_name, "t", "ALLOW", 0.1, i + 1))
        decisions.append(_make_decision(agent_name, "t", "DENY", 0.8, 20))

    # 1 bad agent with 90% deny rate — should be > 2σ from the rest
    for i in range(2):
        decisions.append(_make_decision("agent-bad", "t", "ALLOW", 0.1, i + 1))
    for i in range(18):
        decisions.append(_make_decision("agent-bad", "t", "DENY", 0.9, i + 3))

    await _insert_decisions(decisions)

    resp = await client.get("/v1/dashboard/anomalies?window=1h")
    assert resp.status_code == 200
    anomalies = resp.json()
    assert len(anomalies) >= 1
    assert anomalies[0]["agent_id"] == "agent-bad"
    assert anomalies[0]["sigma_distance"] > 2.0


@pytest.mark.asyncio
async def test_anomaly_no_anomalies_when_similar(client: AsyncClient) -> None:
    """No anomalies when all agents have similar DENY rates."""
    decisions = []
    for agent in ["a1", "a2", "a3"]:
        for i in range(10):
            decisions.append(_make_decision(agent, "t", "ALLOW", 0.2, i + 1))
        decisions.append(_make_decision(agent, "t", "DENY", 0.8, 11))

    await _insert_decisions(decisions)

    resp = await client.get("/v1/dashboard/anomalies?window=1h")
    assert resp.status_code == 200
    anomalies = resp.json()
    assert len(anomalies) == 0


# --- Time Window (APEP-132) ---


@pytest.mark.asyncio
async def test_invalid_window_rejected(client: AsyncClient) -> None:
    resp = await client.get("/v1/dashboard/summary?window=99h")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_all_windows_accepted(client: AsyncClient) -> None:
    for w in ["1h", "6h", "24h", "7d", "30d"]:
        resp = await client.get(f"/v1/dashboard/summary?window={w}")
        assert resp.status_code == 200
