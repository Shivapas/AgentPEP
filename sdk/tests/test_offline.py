"""Tests for local offline policy evaluation (APEP-035, APEP-036)."""

from agentpep.models import PolicyDecision
from agentpep.offline import OfflineEvaluator, OfflineRule


class TestOfflineRule:
    def test_glob_match(self) -> None:
        rule = OfflineRule(tool_pattern="read_*")
        assert rule.matches_tool("read_file")
        assert rule.matches_tool("read_database")
        assert not rule.matches_tool("write_file")

    def test_regex_match(self) -> None:
        rule = OfflineRule(tool_pattern="^(read|list)_.*$")
        assert rule.matches_tool("read_file")
        assert rule.matches_tool("list_users")
        assert not rule.matches_tool("delete_file")

    def test_wildcard_role(self) -> None:
        rule = OfflineRule(tool_pattern="*", agent_roles=["*"])
        assert rule.matches_role("any_role")

    def test_specific_role(self) -> None:
        rule = OfflineRule(tool_pattern="*", agent_roles=["admin", "writer"])
        assert rule.matches_role("admin")
        assert rule.matches_role("writer")
        assert not rule.matches_role("reader")


class TestOfflineEvaluator:
    def test_first_match_wins(self) -> None:
        evaluator = OfflineEvaluator(
            rules=[
                OfflineRule(tool_pattern="delete_*", action=PolicyDecision.DENY, priority=10),
                OfflineRule(tool_pattern="*", action=PolicyDecision.ALLOW, priority=100),
            ]
        )
        resp = evaluator.evaluate(agent_id="a", tool_name="delete_file")
        assert resp.decision == PolicyDecision.DENY

        resp = evaluator.evaluate(agent_id="a", tool_name="read_file")
        assert resp.decision == PolicyDecision.ALLOW

    def test_priority_ordering(self) -> None:
        evaluator = OfflineEvaluator(
            rules=[
                OfflineRule(tool_pattern="*", action=PolicyDecision.ALLOW, priority=100),
                OfflineRule(tool_pattern="*", action=PolicyDecision.DENY, priority=10),
            ]
        )
        # Priority 10 should match first (lower = higher priority)
        resp = evaluator.evaluate(agent_id="a", tool_name="anything")
        assert resp.decision == PolicyDecision.DENY

    def test_deny_by_default(self) -> None:
        evaluator = OfflineEvaluator(rules=[])
        resp = evaluator.evaluate(agent_id="a", tool_name="unknown_tool")
        assert resp.decision == PolicyDecision.DENY

    def test_custom_default_action(self) -> None:
        evaluator = OfflineEvaluator(rules=[], default_action=PolicyDecision.ALLOW)
        resp = evaluator.evaluate(agent_id="a", tool_name="any_tool")
        assert resp.decision == PolicyDecision.ALLOW

    def test_role_filtering(self) -> None:
        evaluator = OfflineEvaluator(
            rules=[
                OfflineRule(
                    tool_pattern="*",
                    action=PolicyDecision.ALLOW,
                    agent_roles=["admin"],
                ),
            ]
        )
        resp = evaluator.evaluate(agent_id="a", tool_name="delete_all", role="admin")
        assert resp.decision == PolicyDecision.ALLOW

        resp = evaluator.evaluate(agent_id="a", tool_name="delete_all", role="reader")
        assert resp.decision == PolicyDecision.DENY  # No match → default deny

    def test_from_dict_list(self) -> None:
        rules = [
            {"tool_pattern": "read_*", "action": "ALLOW", "priority": 10},
            {"tool_pattern": "write_*", "action": "DENY", "priority": 20},
        ]
        evaluator = OfflineEvaluator.from_dict_list(rules)
        assert len(evaluator.rules) == 2

        resp = evaluator.evaluate(agent_id="a", tool_name="read_file")
        assert resp.decision == PolicyDecision.ALLOW

        resp = evaluator.evaluate(agent_id="a", tool_name="write_file")
        assert resp.decision == PolicyDecision.DENY

    def test_escalate_action(self) -> None:
        evaluator = OfflineEvaluator(
            rules=[
                OfflineRule(tool_pattern="dangerous_*", action=PolicyDecision.ESCALATE),
            ]
        )
        resp = evaluator.evaluate(agent_id="a", tool_name="dangerous_op")
        assert resp.decision == PolicyDecision.ESCALATE
