"""CaMeL-lite SEQ Rules — Sprint 55 (APEP-436).

5 behavioural sequence rules imported from ToolTrust CaMeL-lite:
  SEQ-001: File read → external HTTP exfil (ENFORCING)
  SEQ-002: File read → DNS/network exfil (ENFORCING)
  SEQ-003: Config read → config write (ADVISORY)
  SEQ-004: Secret access → shell exec (ADVISORY)
  SEQ-005: Env read → config write (CONFIG-WRITE ENFORCEMENT)

These are registered as named chain patterns in the Phase 10
ToolCallChainDetector and also as marker-based rules that operate
on the session-wide typed marker system (APEP-437).

Gap-tolerant: padding with benign events between trigger markers
does NOT evade detection because markers persist across the session.
"""

from __future__ import annotations

import logging

from app.models.camel_seq import (
    MarkerType,
    SEQDetectionResult,
    SEQRuleID,
    SEQRuleMatch,
    SEQRuleMode,
    SessionMarker,
)
from app.models.tool_call_chain import (
    ChainCategory,
    ChainDetectionAction,
    ChainMatchStrategy,
    ChainSeverity,
    ToolCallChainPattern,
    ToolCallChainStep,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CaMeL-lite SEQ rules as ToolCallChainPatterns (APEP-436)
# ---------------------------------------------------------------------------

CAMEL_SEQ_PATTERNS: list[ToolCallChainPattern] = [
    # SEQ-001: File read → external HTTP (ENFORCING)
    ToolCallChainPattern(
        pattern_id="SEQ-001",
        name="CaMeL SEQ-001: File Read to HTTP Exfiltration",
        description=(
            "Detects file/data read followed by external HTTP POST/PUT — "
            "indicates data exfiltration to an external endpoint. "
            "Gap-tolerant: benign events between read and exfil do not evade detection."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="*.read", max_gap=50),
            ToolCallChainStep(tool_pattern="http.post", max_gap=50),
        ],
        category=ChainCategory.DATA_EXFILTRATION,
        severity=ChainSeverity.CRITICAL,
        action=ChainDetectionAction.DENY,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=1800,  # 30-minute window for gap tolerance
        risk_boost=0.95,
        mitre_technique_id="T1041",
        enabled=True,
        builtin=True,
    ),
    # SEQ-002: File read → DNS/network exfiltration (ENFORCING)
    ToolCallChainPattern(
        pattern_id="SEQ-002",
        name="CaMeL SEQ-002: File Read to DNS Exfiltration",
        description=(
            "Detects file/data read followed by DNS lookup or low-level "
            "network send — indicates covert data exfiltration via DNS. "
            "Gap-tolerant."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="*.read", max_gap=50),
            ToolCallChainStep(tool_pattern="dns.*", max_gap=50),
        ],
        category=ChainCategory.DATA_EXFILTRATION,
        severity=ChainSeverity.CRITICAL,
        action=ChainDetectionAction.DENY,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=1800,
        risk_boost=0.95,
        mitre_technique_id="T1048",
        enabled=True,
        builtin=True,
    ),
    # SEQ-003: Config read → config write (ADVISORY)
    ToolCallChainPattern(
        pattern_id="SEQ-003",
        name="CaMeL SEQ-003: Config Read then Config Write",
        description=(
            "Detects configuration read followed by configuration write — "
            "may indicate configuration tampering. Advisory mode: logs only."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="config.read*", max_gap=30),
            ToolCallChainStep(tool_pattern="config.write*", max_gap=30),
        ],
        category=ChainCategory.DEFENSE_EVASION,
        severity=ChainSeverity.MEDIUM,
        action=ChainDetectionAction.ALERT,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=900,
        risk_boost=0.5,
        mitre_technique_id="T1562",
        enabled=True,
        builtin=True,
    ),
    # SEQ-004: Secret access → shell exec (ADVISORY)
    ToolCallChainPattern(
        pattern_id="SEQ-004",
        name="CaMeL SEQ-004: Secret Access then Shell Execution",
        description=(
            "Detects secret/credential access followed by shell execution — "
            "may indicate credential use for lateral movement. Advisory mode."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="secret.*", max_gap=30),
            ToolCallChainStep(tool_pattern="shell.exec", max_gap=30),
        ],
        category=ChainCategory.LATERAL_MOVEMENT,
        severity=ChainSeverity.HIGH,
        action=ChainDetectionAction.ALERT,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=900,
        risk_boost=0.7,
        mitre_technique_id="T1059",
        enabled=True,
        builtin=True,
    ),
    # SEQ-005: Env read → config write (CONFIG-WRITE ENFORCEMENT)
    ToolCallChainPattern(
        pattern_id="SEQ-005",
        name="CaMeL SEQ-005: Environment Read to Config Write",
        description=(
            "Detects environment variable read followed by config write — "
            "may indicate injection of environment secrets into configuration. "
            "Enforcing for config-write operations."
        ),
        steps=[
            ToolCallChainStep(tool_pattern="env.*", max_gap=30),
            ToolCallChainStep(tool_pattern="config.write*", max_gap=30),
        ],
        category=ChainCategory.DEFENSE_EVASION,
        severity=ChainSeverity.HIGH,
        action=ChainDetectionAction.ESCALATE,
        match_strategy=ChainMatchStrategy.SUBSEQUENCE,
        window_seconds=900,
        risk_boost=0.7,
        mitre_technique_id="T1562",
        enabled=True,
        builtin=True,
    ),
]

# Map SEQ rule IDs to enforcement modes
_SEQ_MODES: dict[str, SEQRuleMode] = {
    "SEQ-001": SEQRuleMode.ENFORCING,
    "SEQ-002": SEQRuleMode.ENFORCING,
    "SEQ-003": SEQRuleMode.ADVISORY,
    "SEQ-004": SEQRuleMode.ADVISORY,
    "SEQ-005": SEQRuleMode.ENFORCING,  # config-write enforcement
}

# Map SEQ rules to the marker types they require (in order)
_SEQ_MARKER_REQUIREMENTS: dict[str, list[MarkerType]] = {
    "SEQ-001": [MarkerType.FILE_READ, MarkerType.EXTERNAL_HTTP],
    "SEQ-002": [MarkerType.FILE_READ, MarkerType.DNS_EXFIL],
    "SEQ-003": [MarkerType.CONFIG_READ, MarkerType.CONFIG_WRITE],
    "SEQ-004": [MarkerType.SECRET_ACCESS, MarkerType.SHELL_EXEC],
    "SEQ-005": [MarkerType.ENV_READ, MarkerType.CONFIG_WRITE],
}


def get_seq_patterns() -> list[ToolCallChainPattern]:
    """Return all 5 CaMeL-lite SEQ chain patterns."""
    return list(CAMEL_SEQ_PATTERNS)


def get_seq_mode(rule_id: str) -> SEQRuleMode:
    """Get the enforcement mode for a SEQ rule."""
    return _SEQ_MODES.get(rule_id, SEQRuleMode.ADVISORY)


async def evaluate_seq_markers(
    session_id: str,
    markers: list[SessionMarker],
) -> SEQDetectionResult:
    """Evaluate session markers against all 5 SEQ rules.

    This is the marker-based detection path that complements the
    chain pattern-based detection in the ToolCallChainDetector.
    Markers provide gap-tolerant detection because they persist
    across the session regardless of intervening benign tool calls.

    Args:
        session_id: The session to evaluate.
        markers: Ordered list of session markers.

    Returns:
        SEQDetectionResult with any matched rules.
    """
    if not markers:
        return SEQDetectionResult(
            session_id=session_id,
            detail="No session markers to evaluate",
        )

    # Build a set of marker types present in the session
    present_types: set[MarkerType] = set()
    marker_by_type: dict[MarkerType, list[SessionMarker]] = {}
    for m in markers:
        present_types.add(m.marker_type)
        marker_by_type.setdefault(m.marker_type, []).append(m)

    matches: list[SEQRuleMatch] = []

    for rule_id_str, required_types in _SEQ_MARKER_REQUIREMENTS.items():
        # Check if all required marker types are present
        all_present = all(rt in present_types for rt in required_types)
        if not all_present:
            continue

        # Verify ordering: first marker of type[0] must precede
        # first marker of type[1] (gap-tolerant — any amount of gap OK)
        first_markers = [marker_by_type[rt][0] for rt in required_types]
        ordered = all(
            first_markers[i].created_at <= first_markers[i + 1].created_at
            for i in range(len(first_markers) - 1)
        )
        if not ordered:
            continue

        # Count gap events between the first and last matched markers
        first_ts = first_markers[0].created_at
        last_ts = first_markers[-1].created_at
        gap_count = sum(
            1
            for m in markers
            if first_ts < m.created_at < last_ts
            and m.marker_type not in required_types
        )

        rule_id = SEQRuleID(rule_id_str)
        mode = _SEQ_MODES[rule_id_str]

        matches.append(
            SEQRuleMatch(
                rule_id=rule_id,
                mode=mode,
                markers_matched=[fm.marker_id for fm in first_markers],
                detail=(
                    f"{rule_id_str} triggered: "
                    f"{' → '.join(rt.value for rt in required_types)} "
                    f"(gap={gap_count}, mode={mode.value})"
                ),
                gap_count=gap_count,
                session_id=session_id,
            )
        )

    has_enforcing = any(m.mode == SEQRuleMode.ENFORCING for m in matches)

    if matches:
        detail_parts = [f"{m.rule_id.value}({m.mode.value})" for m in matches]
        detail = f"SEQ rules triggered: {', '.join(detail_parts)}"
    else:
        detail = "No SEQ rules triggered"

    return SEQDetectionResult(
        session_id=session_id,
        matches=matches,
        total_matches=len(matches),
        has_enforcing_match=has_enforcing,
        detail=detail,
    )
