"""Unit tests for ConflictResolutionEngine (Sprint 36 — APEP-289)."""

import pytest

from app.db import mongodb as db_module
from app.models.policy import Decision, PolicyRule
from app.models.sprint36 import ConflictResolutionStrategy, ConflictSeverity
from app.services.conflict_resolution import ConflictResolutionEngine


async def _seed_rules(db, rules: list[dict]) -> None:
    """Insert test policy rules into the mock database."""
    collection = db[db_module.POLICY_RULES]
    for rule_data in rules:
        rule = PolicyRule(**rule_data)
        await collection.insert_one(rule.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_no_conflicts(mock_mongodb):
    """No conflicts when all rules have the same action."""
    await _seed_rules(mock_mongodb, [
        {"name": "rule-1", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "ALLOW", "priority": 10},
        {"name": "rule-2", "agent_role": ["admin"], "tool_pattern": "db.*", "action": "ALLOW", "priority": 20},
    ])

    engine = ConflictResolutionEngine()
    report = await engine.scan_and_report()
    assert report.total_conflicts == 0
    assert report.total_rules_scanned == 2


@pytest.mark.asyncio
async def test_action_conflict_detected(mock_mongodb):
    """Rules with overlapping scope but different actions should conflict."""
    await _seed_rules(mock_mongodb, [
        {"name": "allow-files", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "ALLOW", "priority": 10},
        {"name": "deny-files", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "DENY", "priority": 20},
    ])

    engine = ConflictResolutionEngine()
    report = await engine.scan_and_report()
    assert report.total_conflicts == 1
    assert report.conflicts[0].severity == ConflictSeverity.CRITICAL


@pytest.mark.asyncio
async def test_priority_tie_detection(mock_mongodb):
    """Rules with same priority and overlapping scope should be HIGH severity."""
    await _seed_rules(mock_mongodb, [
        {"name": "rule-a", "agent_role": ["reader"], "tool_pattern": "file.*", "action": "ALLOW", "priority": 10},
        {"name": "rule-b", "agent_role": ["reader"], "tool_pattern": "file.*", "action": "ESCALATE", "priority": 10},
    ])

    engine = ConflictResolutionEngine()
    report = await engine.scan_and_report()
    assert report.total_conflicts == 1
    assert report.conflicts[0].overlap_type == "priority_tie"
    assert report.conflicts[0].severity == ConflictSeverity.HIGH


@pytest.mark.asyncio
async def test_no_overlap_different_roles(mock_mongodb):
    """No conflict when roles don't overlap."""
    await _seed_rules(mock_mongodb, [
        {"name": "admin-allow", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "ALLOW", "priority": 10},
        {"name": "reader-deny", "agent_role": ["reader"], "tool_pattern": "file.*", "action": "DENY", "priority": 10},
    ])

    engine = ConflictResolutionEngine()
    report = await engine.scan_and_report()
    assert report.total_conflicts == 0


@pytest.mark.asyncio
async def test_wildcard_role_overlap(mock_mongodb):
    """Wildcard role should overlap with any specific role."""
    await _seed_rules(mock_mongodb, [
        {"name": "all-allow", "agent_role": ["*"], "tool_pattern": "file.*", "action": "ALLOW", "priority": 10},
        {"name": "admin-deny", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "DENY", "priority": 20},
    ])

    engine = ConflictResolutionEngine()
    report = await engine.scan_and_report()
    assert report.total_conflicts == 1


@pytest.mark.asyncio
async def test_priority_wins_resolution(mock_mongodb):
    """PRIORITY_WINS strategy should auto-resolve conflicts."""
    await _seed_rules(mock_mongodb, [
        {"name": "high-prio", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "ALLOW", "priority": 10},
        {"name": "low-prio", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "DENY", "priority": 20},
    ])

    engine = ConflictResolutionEngine()
    report = await engine.scan_and_report(
        strategy=ConflictResolutionStrategy.PRIORITY_WINS
    )
    assert report.total_conflicts == 1
    assert report.conflicts[0].resolved is True


@pytest.mark.asyncio
async def test_manual_review_strategy(mock_mongodb):
    """MANUAL_REVIEW strategy should leave conflicts unresolved."""
    await _seed_rules(mock_mongodb, [
        {"name": "rule-x", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "ALLOW", "priority": 10},
        {"name": "rule-y", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "DENY", "priority": 20},
    ])

    engine = ConflictResolutionEngine()
    report = await engine.scan_and_report(
        strategy=ConflictResolutionStrategy.MANUAL_REVIEW
    )
    assert report.total_conflicts == 1
    assert report.conflicts[0].resolved is False


@pytest.mark.asyncio
async def test_resolve_conflict_by_id(mock_mongodb):
    """Manual conflict resolution by ID."""
    await _seed_rules(mock_mongodb, [
        {"name": "rule-1", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "ALLOW", "priority": 10},
        {"name": "rule-2", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "DENY", "priority": 20},
    ])

    engine = ConflictResolutionEngine()
    report = await engine.scan_and_report(
        strategy=ConflictResolutionStrategy.MANUAL_REVIEW
    )

    conflict = report.conflicts[0]
    resolved = await engine.resolve_conflict_by_id(
        conflict.conflict_id, "Accepted: higher priority rule takes precedence"
    )
    assert resolved is not None
    assert resolved.resolved is True


@pytest.mark.asyncio
async def test_get_conflicts_by_severity(mock_mongodb):
    """Query conflicts filtered by severity."""
    await _seed_rules(mock_mongodb, [
        {"name": "r1", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "ALLOW", "priority": 10},
        {"name": "r2", "agent_role": ["admin"], "tool_pattern": "file.*", "action": "DENY", "priority": 20},
    ])

    engine = ConflictResolutionEngine()
    await engine.scan_and_report()

    critical = await engine.get_conflicts(severity="CRITICAL")
    assert len(critical) >= 1

    low = await engine.get_conflicts(severity="LOW")
    assert len(low) == 0
