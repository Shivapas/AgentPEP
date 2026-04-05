"""Property-based tests for role resolution and rule matching — APEP-027.

Uses Hypothesis to generate random inputs and verify invariants.
"""

from hypothesis import given, settings
from hypothesis import strategies as st

from app.models.policy import ArgValidator, Decision, PolicyRule
from app.services.rule_matcher import RuleMatcher

# --- Strategies ---

role_name_st = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_-"),
    min_size=1,
    max_size=30,
)

tool_name_st = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N"), whitelist_characters="_"),
    min_size=1,
    max_size=50,
)

decision_st = st.sampled_from([Decision.ALLOW, Decision.DENY, Decision.ESCALATE])


def make_rule(
    agent_role: list[str],
    tool_pattern: str,
    action: Decision,
    priority: int = 100,
) -> PolicyRule:
    return PolicyRule(
        name=f"rule-{priority}",
        agent_role=agent_role,
        tool_pattern=tool_pattern,
        action=action,
        priority=priority,
        enabled=True,
    )


# ---------------------------------------------------------------------------
# Property: wildcard role always matches
# ---------------------------------------------------------------------------


@given(roles=st.lists(role_name_st, min_size=1, max_size=5))
@settings(max_examples=100)
def test_wildcard_role_always_matches(roles):
    """A rule with agent_role=['*'] must match any list of agent roles."""
    assert RuleMatcher.role_matches(roles, ["*"]) is True


# ---------------------------------------------------------------------------
# Property: exact role match is reflexive
# ---------------------------------------------------------------------------


@given(role=role_name_st)
@settings(max_examples=100)
def test_exact_role_match_is_reflexive(role):
    """A role should always match a rule targeting that same role."""
    assert RuleMatcher.role_matches([role], [role]) is True


# ---------------------------------------------------------------------------
# Property: exact tool match is reflexive
# ---------------------------------------------------------------------------


@given(tool=tool_name_st)
@settings(max_examples=100)
def test_exact_tool_match_is_reflexive(tool):
    """A tool name should always match itself as a pattern."""
    assert RuleMatcher.tool_matches(tool, tool) is True


# ---------------------------------------------------------------------------
# Property: glob '*' matches everything
# ---------------------------------------------------------------------------


@given(tool=tool_name_st)
@settings(max_examples=100)
def test_glob_star_matches_all(tool):
    """The glob pattern '*' should match any tool name."""
    assert RuleMatcher.tool_matches(tool, "*") is True


# ---------------------------------------------------------------------------
# Property: no match when roles are disjoint
# ---------------------------------------------------------------------------


@given(
    agent_roles=st.lists(role_name_st, min_size=1, max_size=3),
    rule_roles=st.lists(role_name_st, min_size=1, max_size=3),
)
@settings(max_examples=100)
def test_disjoint_roles_never_match(agent_roles, rule_roles):
    """If no role overlaps and no wildcard, match should be False."""
    # Make them disjoint by prefixing
    prefixed_agent = [f"agent_{r}" for r in agent_roles]
    prefixed_rule = [f"rule_{r}" for r in rule_roles]
    assert RuleMatcher.role_matches(prefixed_agent, prefixed_rule) is False


# ---------------------------------------------------------------------------
# Property: first-match semantics — higher priority wins
# ---------------------------------------------------------------------------


@given(
    tool=tool_name_st,
    action_first=decision_st,
    action_second=decision_st,
)
@settings(max_examples=100)
def test_first_match_higher_priority_wins(tool, action_first, action_second):
    """The first rule (lower priority number) should always win in first-match."""
    matcher = RuleMatcher()
    rules = [
        make_rule(agent_role=["*"], tool_pattern="*", action=action_first, priority=1),
        make_rule(agent_role=["*"], tool_pattern="*", action=action_second, priority=100),
    ]
    result = matcher.match(tool, {}, ["any_role"], rules)
    assert result.matched is True
    assert result.rule is not None
    assert result.rule.action == action_first


# ---------------------------------------------------------------------------
# Property: deny-by-default when no rules
# ---------------------------------------------------------------------------


@given(tool=tool_name_st)
@settings(max_examples=50)
def test_no_rules_means_no_match(tool):
    """With an empty rule list, match should return matched=False."""
    matcher = RuleMatcher()
    result = matcher.match(tool, {}, ["any_role"], [])
    assert result.matched is False


# ---------------------------------------------------------------------------
# Property: disabled rules are never matched
# ---------------------------------------------------------------------------


@given(tool=tool_name_st, action=decision_st)
@settings(max_examples=50)
def test_disabled_rules_never_match(tool, action):
    """A disabled rule should never be matched regardless of patterns."""
    matcher = RuleMatcher()
    rule = make_rule(agent_role=["*"], tool_pattern="*", action=action)
    rule.enabled = False
    result = matcher.match(tool, {}, ["any_role"], [rule])
    assert result.matched is False


# ---------------------------------------------------------------------------
# Property: validate_args — blocklist always blocks
# ---------------------------------------------------------------------------


@given(value=st.text(min_size=1, max_size=20))
@settings(max_examples=50)
def test_blocklist_always_blocks_matching_value(value):
    """Any value in the blocklist should cause validation failure."""
    validators = [ArgValidator(arg_name="x", blocklist=[value])]
    valid, _ = RuleMatcher.validate_args({"x": value}, validators)
    assert valid is False


# ---------------------------------------------------------------------------
# Property: validate_args — allowlist allows only listed values
# ---------------------------------------------------------------------------


@given(
    allowed=st.text(min_size=1, max_size=20),
    other=st.text(min_size=1, max_size=20),
)
@settings(max_examples=50)
def test_allowlist_only_allows_listed(allowed, other):
    """Only values in the allowlist should pass; others should fail."""
    validators = [ArgValidator(arg_name="x", allowlist=[allowed])]
    valid_allowed, _ = RuleMatcher.validate_args({"x": allowed}, validators)
    assert valid_allowed is True

    if other != allowed:
        valid_other, _ = RuleMatcher.validate_args({"x": other}, validators)
        assert valid_other is False
