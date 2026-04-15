"""CaMeL-lite SEQ Rule Engine — Sprint 55 (APEP-436).

Implements 5 CaMeL-lite behavioural sequence rules for coding-agent-specific
attack patterns.  SEQ-001/002 are enforcing (DENY on match); SEQ-003-005
are advisory (WARN or LOG_ONLY).

Gap-tolerant: benign events between matched steps do not evade detection.

Integration: runs alongside the existing ToolCallChainDetector (Phase 10)
as an additional pattern source.
"""

from __future__ import annotations

import logging
import time

from app.models.camel_seq import (
    MarkerSeverity,
    MarkerType,
    SEQDetectionResult,
    SEQRule,
    SEQRuleAction,
    SEQRuleMatch,
    SEQRuleStep,
    SessionMarker,
)
from app.services.session_marker_store import session_marker_manager

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Built-in SEQ rules (5 rules — APEP-436)
# ---------------------------------------------------------------------------

_BUILTIN_SEQ_RULES: list[SEQRule] = [
    # SEQ-001: File read → external exfiltration (ENFORCING)
    SEQRule(
        rule_id="SEQ-001",
        name="File Read to External Exfiltration",
        description=(
            "Detects file or database read followed by HTTP POST or network "
            "send — indicates data exfiltration to an external endpoint. "
            "Enforcing: blocks the exfiltration step."
        ),
        steps=[
            SEQRuleStep(
                marker_type=MarkerType.FILE_READ,
                gap_tolerant=True,
                max_gap=50,
            ),
            SEQRuleStep(
                marker_type=MarkerType.NETWORK_SEND,
                gap_tolerant=True,
                max_gap=50,
            ),
        ],
        severity=MarkerSeverity.ENFORCING,
        action=SEQRuleAction.DENY,
        risk_boost=0.9,
        window_seconds=600,
        enabled=True,
        builtin=True,
    ),
    # SEQ-002: Sensitive read → network send (ENFORCING)
    SEQRule(
        rule_id="SEQ-002",
        name="Sensitive Data Read to External Write",
        description=(
            "Detects secret/credential access followed by any network send "
            "operation — catches credential exfiltration even through indirect "
            "channels. Enforcing: blocks the send step."
        ),
        steps=[
            SEQRuleStep(
                marker_type=MarkerType.SECRET_ACCESS,
                gap_tolerant=True,
                max_gap=50,
            ),
            SEQRuleStep(
                marker_type=MarkerType.NETWORK_SEND,
                gap_tolerant=True,
                max_gap=50,
            ),
        ],
        severity=MarkerSeverity.ENFORCING,
        action=SEQRuleAction.DENY,
        risk_boost=0.95,
        window_seconds=600,
        enabled=True,
        builtin=True,
    ),
    # SEQ-003: Shell exec → network send (ADVISORY)
    SEQRule(
        rule_id="SEQ-003",
        name="Shell Execution to Network Exfiltration",
        description=(
            "Detects shell command execution followed by network send — "
            "may indicate command output exfiltration. Advisory: logs a warning."
        ),
        steps=[
            SEQRuleStep(
                marker_type=MarkerType.SHELL_EXEC,
                gap_tolerant=True,
                max_gap=30,
            ),
            SEQRuleStep(
                marker_type=MarkerType.NETWORK_SEND,
                gap_tolerant=True,
                max_gap=30,
            ),
        ],
        severity=MarkerSeverity.ADVISORY,
        action=SEQRuleAction.WARN,
        risk_boost=0.5,
        window_seconds=300,
        enabled=True,
        builtin=True,
    ),
    # SEQ-004: Package install → config write (ADVISORY)
    SEQRule(
        rule_id="SEQ-004",
        name="Package Install to Config Modification",
        description=(
            "Detects package installation followed by configuration file "
            "modification — may indicate supply chain attack installing a "
            "trojan dependency then modifying config for persistence."
        ),
        steps=[
            SEQRuleStep(
                marker_type=MarkerType.PACKAGE_INSTALL,
                gap_tolerant=True,
                max_gap=20,
            ),
            SEQRuleStep(
                marker_type=MarkerType.CONFIG_WRITE,
                gap_tolerant=True,
                max_gap=20,
            ),
        ],
        severity=MarkerSeverity.ADVISORY,
        action=SEQRuleAction.WARN,
        risk_boost=0.4,
        window_seconds=600,
        enabled=True,
        builtin=True,
    ),
    # SEQ-005: File read → shell exec → config write (ADVISORY)
    SEQRule(
        rule_id="SEQ-005",
        name="Read-Execute-Config Modification Chain",
        description=(
            "Detects file read followed by shell execution and config write — "
            "indicates a multi-stage attack reading source, executing payload, "
            "and persisting via config change."
        ),
        steps=[
            SEQRuleStep(
                marker_type=MarkerType.FILE_READ,
                gap_tolerant=True,
                max_gap=30,
            ),
            SEQRuleStep(
                marker_type=MarkerType.SHELL_EXEC,
                gap_tolerant=True,
                max_gap=30,
            ),
            SEQRuleStep(
                marker_type=MarkerType.CONFIG_WRITE,
                gap_tolerant=True,
                max_gap=30,
            ),
        ],
        severity=MarkerSeverity.ADVISORY,
        action=SEQRuleAction.WARN,
        risk_boost=0.6,
        window_seconds=900,
        enabled=True,
        builtin=True,
    ),
]


# ---------------------------------------------------------------------------
# SEQ Rule Engine
# ---------------------------------------------------------------------------


class CaMeLSEQEngine:
    """CaMeL-lite behavioural sequence rule engine (APEP-436).

    Evaluates all enabled SEQ rules against a session's marker history.
    Gap-tolerant: ignores unrelated markers between matched steps.
    """

    def __init__(self) -> None:
        self._rules: list[SEQRule] = list(_BUILTIN_SEQ_RULES)
        self._custom_rules: dict[str, SEQRule] = {}

    @property
    def all_rules(self) -> list[SEQRule]:
        return [*self._rules, *self._custom_rules.values()]

    def get_enabled_rules(self) -> list[SEQRule]:
        return [r for r in self.all_rules if r.enabled]

    def get_rule(self, rule_id: str) -> SEQRule | None:
        for r in self._rules:
            if r.rule_id == rule_id:
                return r
        return self._custom_rules.get(rule_id)

    def add_custom_rule(self, rule: SEQRule) -> None:
        self._custom_rules[rule.rule_id] = rule

    def evaluate_session(
        self,
        session_id: str,
        agent_id: str = "",
    ) -> SEQDetectionResult:
        """Evaluate all enabled SEQ rules against session markers.

        Returns aggregate detection result with all matches.
        """
        start_us = time.monotonic()

        markers = session_marker_manager.get_all_markers(session_id)
        if not markers:
            return SEQDetectionResult(
                session_id=session_id,
                agent_id=agent_id,
                detail="No session markers present",
            )

        rules = self.get_enabled_rules()
        if not rules:
            return SEQDetectionResult(
                session_id=session_id,
                agent_id=agent_id,
                detail="No SEQ rules enabled",
            )

        matches: list[SEQRuleMatch] = []
        for rule in rules:
            match = self._evaluate_rule(rule, markers)
            if match is not None:
                matches.append(match)

        elapsed_us = int((time.monotonic() - start_us) * 1_000_000)

        if not matches:
            return SEQDetectionResult(
                session_id=session_id,
                agent_id=agent_id,
                detail="No SEQ rules triggered",
                scan_latency_us=elapsed_us,
            )

        max_risk_boost = max(m.risk_boost for m in matches)
        recommended_action = max(
            (m.action for m in matches),
            key=lambda a: _ACTION_PRIORITY.get(a, 0),
        )

        detail_parts = [
            f"{m.rule_id} ({m.rule_name}): {m.severity.value}"
            for m in matches
        ]

        return SEQDetectionResult(
            session_id=session_id,
            agent_id=agent_id,
            matches=matches,
            total_matches=len(matches),
            max_risk_boost=max_risk_boost,
            recommended_action=recommended_action,
            detail=f"SEQ rules triggered: {'; '.join(detail_parts)}",
            scan_latency_us=elapsed_us,
        )

    def _evaluate_rule(
        self,
        rule: SEQRule,
        markers: list[SessionMarker],
    ) -> SEQRuleMatch | None:
        """Evaluate a single SEQ rule against an ordered list of markers.

        Uses gap-tolerant subsequence matching: markers between matched
        steps are ignored as long as the gap count doesn't exceed max_gap.
        """
        if len(markers) < len(rule.steps):
            return None

        now = time.time()
        window_start = now - rule.window_seconds

        # Filter markers within the rule's time window
        windowed = [
            m for m in markers if m.created_at.timestamp() >= window_start
        ]
        if len(windowed) < len(rule.steps):
            return None

        # Gap-tolerant subsequence match
        matched_indices: list[int] = []
        step_idx = 0
        gap_count = 0

        for i, marker in enumerate(windowed):
            if step_idx >= len(rule.steps):
                break

            step = rule.steps[step_idx]

            if marker.marker_type == step.marker_type:
                # Check tool pattern filter if specified
                if step.tool_patterns and not self._matches_tool_patterns(
                    marker.tool_name, step.tool_patterns
                ):
                    gap_count += 1
                    if gap_count > step.max_gap:
                        return None
                    continue

                matched_indices.append(i)
                step_idx += 1
                gap_count = 0
            else:
                if step.gap_tolerant:
                    gap_count += 1
                    if gap_count > step.max_gap:
                        # Too many gaps — reset
                        return None
                else:
                    # Non-gap-tolerant step: sequence broken
                    return None

        if step_idx < len(rule.steps):
            return None

        # Full sequence matched
        matched_markers_list = [windowed[i] for i in matched_indices]
        first_ts = matched_markers_list[0].created_at.timestamp()
        last_ts = matched_markers_list[-1].created_at.timestamp()

        return SEQRuleMatch(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            severity=rule.severity,
            action=rule.action,
            risk_boost=rule.risk_boost,
            matched_markers=[m.marker_id for m in matched_markers_list],
            sequence_duration_s=last_ts - first_ts,
            dry_run=rule.dry_run,
            description=rule.description,
        )

    @staticmethod
    def _matches_tool_patterns(tool_name: str, patterns: list[str]) -> bool:
        """Check if a tool name matches any of the given glob patterns."""
        import fnmatch

        return any(
            fnmatch.fnmatch(tool_name.lower(), p.lower()) for p in patterns
        )


# Action priority for aggregation
_ACTION_PRIORITY: dict[SEQRuleAction, int] = {
    SEQRuleAction.LOG_ONLY: 0,
    SEQRuleAction.WARN: 1,
    SEQRuleAction.ESCALATE: 2,
    SEQRuleAction.DENY: 3,
}

# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

camel_seq_engine = CaMeLSEQEngine()
