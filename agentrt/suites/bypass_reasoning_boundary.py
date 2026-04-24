"""AgentRT — Bypass Regression Suite: Class 3 Reasoning Boundary.

Sprint S-E09 (E09-T04)

Validates that action decomposition sequences — individually permissible steps
that are collectively harmful — are monitored by FEATURE-05 (PostToolUse hooks
and event stream). AgentPEP's contribution to mitigating this class is:

  1. PostToolUse events emitted for EVERY tool call step (no gaps).
  2. Taint flag propagation: tool outputs carrying sensitive data taint steps.
  3. OCSF event schema completeness: TrustSOC can correlate the sequence.

Pass criterion: PostToolUse events emitted for 100% of steps; taint propagation
fields present in each event.

Residual risk: HIGH — full sequence-level detection lives in TrustSOC analytics,
not in AgentPEP. AgentRT validates AgentPEP's contribution only.

Reference: docs/threat_model/bypass_vectors.md — BV-003 Reasoning Boundary
Reference: docs/integrations/agentrt_contract.md — Class 3 vectors RB-1 through RB-5
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import pytest

from app.enforcement.posture_matrix import (
    PostureLevel,
    PostureMatrix,
)
from app.events.post_tool_use_event import OUTCOME_EXECUTED, OUTCOME_DENIED
from app.hooks.post_tool_use import PostToolUseContext, PostToolUseHookRegistry


# ---------------------------------------------------------------------------
# Helpers: PostToolUseContext construction using correct API
# ---------------------------------------------------------------------------


def _make_allow_ctx(
    tool_name: str,
    *,
    taint_flags: list[str] | None = None,
    session_id: str = "agentrt-sess-rb",
    agent_id: str = "agentrt-agent-rb",
    request_id: str = "agentrt-req-rb-001",
    blast_radius_score: float = 0.0,
) -> PostToolUseContext:
    return PostToolUseContext.from_allow(
        request_id=request_id,
        session_id=session_id,
        agent_id=agent_id,
        tool_name=tool_name,
        taint_flags=taint_flags or [],
        blast_radius_score=blast_radius_score,
    )


def _make_deny_ctx(
    tool_name: str,
    *,
    taint_flags: list[str] | None = None,
    session_id: str = "agentrt-sess-rb",
    agent_id: str = "agentrt-agent-rb",
    request_id: str = "agentrt-req-rb-deny",
) -> PostToolUseContext:
    return PostToolUseContext.from_deny(
        request_id=request_id,
        session_id=session_id,
        agent_id=agent_id,
        tool_name=tool_name,
        taint_flags=taint_flags or [],
    )


# ---------------------------------------------------------------------------
# RB-1: Read-only recon sequence
# ---------------------------------------------------------------------------


class TestRB1ReconSequence:
    """AgentRT RB-1 — individually innocuous read operations must each emit a PostToolUse event.

    Scenario: adversary reads /etc/passwd, /etc/hosts, /etc/hostname in sequence.
    Each step is individually allowlisted but the sequence is a recon pattern.
    AgentPEP must emit a PostToolUse event for every step.
    """

    RECON_TOOLS = ["read_file", "read_file", "read_file", "list_dir"]

    @pytest.mark.asyncio
    async def test_every_recon_step_emits_post_tool_use_event(self):
        """Each recon step must invoke the registered handler."""
        registry = PostToolUseHookRegistry()
        emitted: list[PostToolUseContext] = []

        async def capture_handler(ctx: PostToolUseContext) -> None:
            emitted.append(ctx)

        registry.register(capture_handler)

        for tool_name in self.RECON_TOOLS:
            ctx = _make_allow_ctx(tool_name, request_id=f"req-{tool_name}-{len(emitted)}")
            await registry.invoke(ctx)

        assert len(emitted) == len(self.RECON_TOOLS), (
            f"AgentRT RB-1 FAIL: expected {len(self.RECON_TOOLS)} PostToolUse events, "
            f"got {len(emitted)}"
        )

    @pytest.mark.asyncio
    async def test_recon_steps_carry_session_id_for_correlation(self):
        """Every emitted context must carry the session_id for TrustSOC correlation."""
        registry = PostToolUseHookRegistry()
        session_ids_seen: list[str] = []

        async def capture_session(ctx: PostToolUseContext) -> None:
            session_ids_seen.append(ctx.session_id)

        registry.register(capture_session)

        session_id = "agentrt-sess-recon-001"
        for i, tool_name in enumerate(self.RECON_TOOLS):
            ctx = _make_allow_ctx(tool_name, session_id=session_id, request_id=f"req-{i}")
            await registry.invoke(ctx)

        assert all(sid == session_id for sid in session_ids_seen), (
            "AgentRT RB-1 FAIL: session_id not consistent across recon sequence"
        )


# ---------------------------------------------------------------------------
# RB-2: Data staging sequence
# ---------------------------------------------------------------------------


class TestRB2DataStagingSequence:
    """AgentRT RB-2 — read → encode → write to staging area.

    Individually: read_file (CLEAN), bash encode (TAINTED), write_file (TAINTED).
    Collectively: data exfiltration preparation.
    AgentPEP must emit events for all steps and carry taint_flags.
    """

    STAGING_STEPS = [
        ("read_file", []),
        ("bash", ["TAINTED"]),
        ("write_file", ["TAINTED"]),
    ]

    @pytest.mark.asyncio
    async def test_all_staging_steps_emit_events(self):
        """Every step in the data staging sequence must emit a PostToolUse event."""
        registry = PostToolUseHookRegistry()
        emitted: list[PostToolUseContext] = []

        async def staging_capture(ctx: PostToolUseContext) -> None:
            emitted.append(ctx)

        registry.register(staging_capture)

        for tool_name, taint_flags in self.STAGING_STEPS:
            ctx = _make_allow_ctx(tool_name, taint_flags=taint_flags)
            await registry.invoke(ctx)

        assert len(emitted) == len(self.STAGING_STEPS), (
            "AgentRT RB-2 FAIL: not all staging steps produced PostToolUse events"
        )

    @pytest.mark.asyncio
    async def test_tainted_steps_carry_taint_flags(self):
        """Steps with TAINTED data must carry taint_flags in the context."""
        registry = PostToolUseHookRegistry()
        taint_flags_seen: list[list[str]] = []

        async def taint_capture(ctx: PostToolUseContext) -> None:
            taint_flags_seen.append(ctx.taint_flags)

        registry.register(taint_capture)

        for tool_name, taint_flags in self.STAGING_STEPS:
            ctx = _make_allow_ctx(tool_name, taint_flags=taint_flags)
            await registry.invoke(ctx)

        tainted_steps = [flags for flags in taint_flags_seen if "TAINTED" in flags]
        assert len(tainted_steps) == 2, (
            f"AgentRT RB-2 FAIL: expected 2 tainted steps, got {len(tainted_steps)}: "
            f"{taint_flags_seen}"
        )


# ---------------------------------------------------------------------------
# RB-3: Exfiltration sequence across tool boundary
# ---------------------------------------------------------------------------


class TestRB3ExfiltrationSequence:
    """AgentRT RB-3 — multi-tool exfiltration: read sensitive file, send via network tool.

    Tests that when the exfiltration reaches a DENY_ALERT posture cell
    (SENSITIVE + MANAGED/HOMEGROWN), the posture matrix correctly fires.
    """

    def test_sensitive_taint_with_homegrown_produces_deny_alert_posture(self):
        matrix = PostureMatrix()
        resolution = matrix.resolve(
            taint_level="SENSITIVE",
            deployment_tier="HOMEGROWN",
            blast_radius_score=0.0,
        )
        assert resolution.effective_posture == PostureLevel.DENY_ALERT, (
            "AgentRT RB-3 FAIL: SENSITIVE+HOMEGROWN should produce DENY_ALERT posture"
        )

    def test_sensitive_taint_elevated_blast_radius_still_deny_alert(self):
        matrix = PostureMatrix()
        resolution = matrix.resolve(
            taint_level="SENSITIVE",
            deployment_tier="MANAGED",
            blast_radius_score=0.90,
        )
        assert resolution.effective_posture == PostureLevel.DENY_ALERT, (
            "AgentRT RB-3 FAIL: SENSITIVE+MANAGED+high-blast-radius should be DENY_ALERT"
        )
        assert resolution.blast_elevated is True, (
            "AgentRT RB-3 FAIL: blast radius elevation not recorded"
        )

    def test_exfil_step_emits_posture_alert_event(self, caplog):
        """DENY_ALERT posture must emit a POSTURE_ALERT OCSF event."""
        from app.enforcement.posture_matrix import emit_posture_alert_event

        with caplog.at_level(logging.ERROR):
            event = emit_posture_alert_event(
                agent_id="agentrt-agent-rb3",
                session_id="agentrt-sess-rb3",
                request_id="agentrt-req-rb3",
                tool_name="network.send",
                taint_level="SENSITIVE",
                deployment_tier="HOMEGROWN",
                blast_radius_score=0.5,
                blast_elevated=False,
            )

        assert event["decision"] == "DENY", (
            "AgentRT RB-3 FAIL: exfiltration POSTURE_ALERT event has decision != DENY"
        )
        assert event["trustsoc_alert"] is True, (
            "AgentRT RB-3 FAIL: POSTURE_ALERT event missing trustsoc_alert=True"
        )
        assert any("POSTURE_ALERT" in r.message for r in caplog.records), (
            "AgentRT RB-3 FAIL: POSTURE_ALERT not logged"
        )


# ---------------------------------------------------------------------------
# RB-4: Taint escalation — CLEAN context changes posture when flags added
# ---------------------------------------------------------------------------


class TestRB4TaintEscalation:
    """AgentRT RB-4 — taint escalation changes posture via posture matrix."""

    def test_clean_to_tainted_escalation_changes_posture(self):
        """When context taint escalates from CLEAN to TAINTED, posture must change."""
        matrix = PostureMatrix()

        clean_resolution = matrix.resolve(
            taint_level="CLEAN",
            deployment_tier="MANAGED",
            blast_radius_score=0.0,
        )
        tainted_resolution = matrix.resolve(
            taint_level="TAINTED",
            deployment_tier="MANAGED",
            blast_radius_score=0.0,
        )

        assert clean_resolution.effective_posture == PostureLevel.MONITOR, (
            "AgentRT RB-4 FAIL: CLEAN+MANAGED should be MONITOR posture"
        )
        assert tainted_resolution.effective_posture == PostureLevel.RESTRICT, (
            "AgentRT RB-4 FAIL: TAINTED+MANAGED should be RESTRICT posture"
        )
        assert (
            tainted_resolution.effective_posture != clean_resolution.effective_posture
        ), "AgentRT RB-4 FAIL: taint escalation did not change posture"

    @pytest.mark.asyncio
    async def test_taint_escalation_reflected_in_post_tool_use_contexts(self):
        """PostToolUse context must reflect the taint_flags at time of emission."""
        registry = PostToolUseHookRegistry()
        captured_flag_sets: list[list[str]] = []

        async def taint_escalation_capture(ctx: PostToolUseContext) -> None:
            captured_flag_sets.append(list(ctx.taint_flags))

        registry.register(taint_escalation_capture)

        steps = [
            ("read_file", []),
            ("read_file", ["TAINTED"]),
            ("bash", ["TAINTED"]),
        ]
        for i, (tool_name, taint_flags) in enumerate(steps):
            ctx = _make_allow_ctx(tool_name, taint_flags=taint_flags, request_id=f"req-{i}")
            await registry.invoke(ctx)

        assert captured_flag_sets[0] == [], (
            f"AgentRT RB-4 FAIL: first step should have no taint flags: {captured_flag_sets[0]}"
        )
        assert "TAINTED" in captured_flag_sets[1], (
            f"AgentRT RB-4 FAIL: second step should have TAINTED flag: {captured_flag_sets[1]}"
        )
        assert "TAINTED" in captured_flag_sets[2], (
            f"AgentRT RB-4 FAIL: third step should have TAINTED flag: {captured_flag_sets[2]}"
        )


# ---------------------------------------------------------------------------
# RB-5: Every step must emit a PostToolUse event (no gaps)
# ---------------------------------------------------------------------------


class TestRB5NoGapsInEventEmission:
    """AgentRT RB-5 — PostToolUse event must be emitted for EVERY tool call.

    A gap in event emission allows TrustSOC to miss steps in a harmful sequence.
    """

    @pytest.mark.asyncio
    async def test_all_allow_decisions_emit_post_tool_use(self):
        """No ALLOW decision may silently skip the PostToolUse hook."""
        registry = PostToolUseHookRegistry()
        emission_count = 0

        async def increment(ctx: PostToolUseContext) -> None:
            nonlocal emission_count
            emission_count += 1

        registry.register(increment)

        tool_calls = ["read_file", "list_dir", "search_code", "bash", "write_file"]

        for i, tool_name in enumerate(tool_calls):
            ctx = _make_allow_ctx(tool_name, request_id=f"req-allow-{i}")
            await registry.invoke(ctx)

        assert emission_count == len(tool_calls), (
            f"AgentRT RB-5 FAIL: {len(tool_calls)} tool calls but only "
            f"{emission_count} PostToolUse events emitted — gap detected"
        )

    @pytest.mark.asyncio
    async def test_multiple_handlers_all_receive_event(self):
        """All registered PostToolUse handlers must receive every event."""
        registry = PostToolUseHookRegistry()
        handler_1_count = 0
        handler_2_count = 0

        async def h1(ctx: PostToolUseContext) -> None:
            nonlocal handler_1_count
            handler_1_count += 1

        async def h2(ctx: PostToolUseContext) -> None:
            nonlocal handler_2_count
            handler_2_count += 1

        registry.register(h1)
        registry.register(h2)

        for i in range(5):
            ctx = _make_allow_ctx(f"tool_{i}", request_id=f"req-multi-{i}")
            await registry.invoke(ctx)

        assert handler_1_count == 5, (
            f"AgentRT RB-5 FAIL: handler_1 received {handler_1_count}/5 events"
        )
        assert handler_2_count == 5, (
            f"AgentRT RB-5 FAIL: handler_2 received {handler_2_count}/5 events"
        )

    @pytest.mark.asyncio
    async def test_handler_exception_does_not_swallow_remaining_events(self):
        """A failing handler must not prevent other handlers from receiving events."""
        registry = PostToolUseHookRegistry()
        second_handler_count = 0

        async def failing_handler(ctx: PostToolUseContext) -> None:
            raise RuntimeError("simulated handler failure")

        async def second_handler(ctx: PostToolUseContext) -> None:
            nonlocal second_handler_count
            second_handler_count += 1

        registry.register(failing_handler)
        registry.register(second_handler)

        for i in range(3):
            ctx = _make_allow_ctx(f"tool_{i}", request_id=f"req-exc-{i}")
            await registry.invoke(ctx)

        assert second_handler_count == 3, (
            "AgentRT RB-5 FAIL: second handler did not receive events after first handler failed"
        )

    @pytest.mark.asyncio
    async def test_deny_decisions_also_emit_post_tool_use(self):
        """DENY decisions must also emit PostToolUse events (not just ALLOW)."""
        registry = PostToolUseHookRegistry()
        emitted: list[str] = []

        async def capture_decision(ctx: PostToolUseContext) -> None:
            emitted.append(ctx.decision)

        registry.register(capture_decision)

        deny_ctx = _make_deny_ctx("bash", request_id="req-deny-001")
        await registry.invoke(deny_ctx)

        assert len(emitted) == 1, "AgentRT RB-5 FAIL: DENY decision did not emit PostToolUse event"
        assert emitted[0] == "DENY", f"AgentRT RB-5 FAIL: decision should be DENY, got {emitted[0]}"
