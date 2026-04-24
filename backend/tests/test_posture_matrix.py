"""Unit tests for Sprint S-E08 — Enforcement Posture Matrix + Blast Radius.

Sprint S-E08 — E08-T09, E08-T10

Covers:
  - All nine base posture matrix cells (3 taint × 3 tier)
  - Blast radius elevation: score ≥ 0.75 elevates posture one tier
  - Blast radius elevation: score < 0.75 does NOT elevate
  - DENY_ALERT posture: hard deny + TrustSOC alert event emitted
  - RESTRICT posture: role-based permit check + HITL stub triggered
  - HOMEGROWN default for unknown/ambiguous deployment tiers
  - SENSITIVE default for unknown taint levels
  - Blast radius FAIL_CLOSED: API unavailable → score = 1.0 → posture elevated
  - BlastRadiusContext: score clamping, is_high_blast_radius
  - TierDetector: explicit config, env markers, default HOMEGROWN
  - Integration: end-to-end posture resolution with session context
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.enforcement.posture_matrix import (
    BLAST_RADIUS_ELEVATION_THRESHOLD,
    PostureDecision,
    PostureLevel,
    PostureMatrix,
    PostureResolution,
    TaintLevel,
    DeploymentTierLabel,
    emit_posture_alert_event,
    posture_matrix,
)
from app.session.blast_radius_client import (
    BLAST_RADIUS_FAIL_CLOSED_DEFAULT,
    BlastRadiusClient,
    BlastRadiusContext,
)
from app.session.tier_detection import (
    DeploymentTier,
    TierDetector,
    tier_detector,
)


# ===========================================================================
# PostureMatrix — base matrix (all nine cells) — E08-T09
# ===========================================================================


class TestBasePosureMatrix:
    """Verify the nine base matrix cells without blast radius elevation."""

    def _resolve(
        self,
        taint: str,
        tier: str,
        score: float = 0.0,
    ) -> PostureResolution:
        return posture_matrix.resolve(
            taint_level=taint,
            deployment_tier=tier,
            blast_radius_score=score,
        )

    # CLEAN (L1) row — all three tiers → MONITOR
    def test_clean_enterprise(self):
        r = self._resolve("CLEAN", "ENTERPRISE")
        assert r.base_posture == PostureLevel.MONITOR
        assert r.effective_posture == PostureLevel.MONITOR
        assert not r.blast_elevated

    def test_clean_managed(self):
        r = self._resolve("CLEAN", "MANAGED")
        assert r.base_posture == PostureLevel.MONITOR
        assert r.effective_posture == PostureLevel.MONITOR

    def test_clean_homegrown(self):
        r = self._resolve("CLEAN", "HOMEGROWN")
        assert r.base_posture == PostureLevel.MONITOR
        assert r.effective_posture == PostureLevel.MONITOR

    # TAINTED (L2) row
    def test_tainted_enterprise(self):
        r = self._resolve("TAINTED", "ENTERPRISE")
        assert r.base_posture == PostureLevel.MONITOR_LOG
        assert r.effective_posture == PostureLevel.MONITOR_LOG

    def test_tainted_managed(self):
        r = self._resolve("TAINTED", "MANAGED")
        assert r.base_posture == PostureLevel.RESTRICT
        assert r.effective_posture == PostureLevel.RESTRICT

    def test_tainted_homegrown(self):
        r = self._resolve("TAINTED", "HOMEGROWN")
        assert r.base_posture == PostureLevel.RESTRICT
        assert r.effective_posture == PostureLevel.RESTRICT

    # SENSITIVE (L3) row
    def test_sensitive_enterprise(self):
        r = self._resolve("SENSITIVE", "ENTERPRISE")
        assert r.base_posture == PostureLevel.RESTRICT
        assert r.effective_posture == PostureLevel.RESTRICT

    def test_sensitive_managed(self):
        r = self._resolve("SENSITIVE", "MANAGED")
        assert r.base_posture == PostureLevel.DENY_ALERT
        assert r.effective_posture == PostureLevel.DENY_ALERT

    def test_sensitive_homegrown(self):
        r = self._resolve("SENSITIVE", "HOMEGROWN")
        assert r.base_posture == PostureLevel.DENY_ALERT
        assert r.effective_posture == PostureLevel.DENY_ALERT


# ===========================================================================
# PostureMatrix — L-notation aliases
# ===========================================================================


class TestTaintLevelAliases:
    def test_l1_alias_resolves_to_clean(self):
        r = posture_matrix.resolve("L1", "ENTERPRISE", 0.0)
        assert r.taint_level == TaintLevel.CLEAN.value

    def test_l2_alias_resolves_to_tainted(self):
        r = posture_matrix.resolve("L2", "ENTERPRISE", 0.0)
        assert r.taint_level == TaintLevel.TAINTED.value

    def test_l3_alias_resolves_to_sensitive(self):
        r = posture_matrix.resolve("L3", "ENTERPRISE", 0.0)
        assert r.taint_level == TaintLevel.SENSITIVE.value

    def test_unknown_taint_defaults_to_sensitive(self):
        r = posture_matrix.resolve("UNKNOWN_TAINT", "ENTERPRISE", 0.0)
        assert r.taint_level == TaintLevel.SENSITIVE.value

    def test_restricted_taint_maps_to_sensitive(self):
        r = posture_matrix.resolve("RESTRICTED", "ENTERPRISE", 0.0)
        assert r.taint_level == TaintLevel.SENSITIVE.value

    def test_case_insensitive_taint(self):
        r = posture_matrix.resolve("clean", "ENTERPRISE", 0.0)
        assert r.taint_level == TaintLevel.CLEAN.value


# ===========================================================================
# PostureMatrix — HOMEGROWN default for ambiguous tier — E08-T09
# ===========================================================================


class TestHomegrownDefault:
    def test_unknown_tier_defaults_to_homegrown(self):
        r = posture_matrix.resolve("CLEAN", "UNKNOWN_TIER", 0.0)
        assert r.deployment_tier == DeploymentTierLabel.HOMEGROWN.value

    def test_empty_tier_defaults_to_homegrown(self):
        r = posture_matrix.resolve("CLEAN", "", 0.0)
        assert r.deployment_tier == DeploymentTierLabel.HOMEGROWN.value

    def test_case_insensitive_tier(self):
        r = posture_matrix.resolve("CLEAN", "homegrown", 0.0)
        assert r.deployment_tier == DeploymentTierLabel.HOMEGROWN.value
        assert r.effective_posture == PostureLevel.MONITOR

    def test_unknown_tier_tainted_resolves_restrict(self):
        r = posture_matrix.resolve("TAINTED", "SOMETHING_CUSTOM", 0.0)
        assert r.deployment_tier == DeploymentTierLabel.HOMEGROWN.value
        assert r.base_posture == PostureLevel.RESTRICT


# ===========================================================================
# Blast Radius Elevation — E08-T09
# ===========================================================================


class TestBlastRadiusElevation:
    """score ≥ 0.75 elevates posture one tier; score < 0.75 does not."""

    def test_no_elevation_below_threshold(self):
        r = posture_matrix.resolve("CLEAN", "ENTERPRISE", blast_radius_score=0.74)
        assert r.effective_posture == PostureLevel.MONITOR
        assert not r.blast_elevated

    def test_elevation_at_exact_threshold(self):
        r = posture_matrix.resolve("CLEAN", "ENTERPRISE", blast_radius_score=0.75)
        assert r.base_posture == PostureLevel.MONITOR
        assert r.effective_posture == PostureLevel.MONITOR_LOG
        assert r.blast_elevated

    def test_elevation_above_threshold(self):
        r = posture_matrix.resolve("CLEAN", "ENTERPRISE", blast_radius_score=0.99)
        assert r.effective_posture == PostureLevel.MONITOR_LOG
        assert r.blast_elevated

    def test_elevation_monitor_to_monitor_log(self):
        r = posture_matrix.resolve("CLEAN", "MANAGED", blast_radius_score=0.80)
        assert r.base_posture == PostureLevel.MONITOR
        assert r.effective_posture == PostureLevel.MONITOR_LOG

    def test_elevation_monitor_log_to_restrict(self):
        r = posture_matrix.resolve("TAINTED", "ENTERPRISE", blast_radius_score=0.90)
        assert r.base_posture == PostureLevel.MONITOR_LOG
        assert r.effective_posture == PostureLevel.RESTRICT

    def test_elevation_restrict_to_deny_alert(self):
        r = posture_matrix.resolve("TAINTED", "MANAGED", blast_radius_score=0.80)
        assert r.base_posture == PostureLevel.RESTRICT
        assert r.effective_posture == PostureLevel.DENY_ALERT

    def test_elevation_already_at_deny_alert_stays(self):
        r = posture_matrix.resolve("SENSITIVE", "MANAGED", blast_radius_score=0.99)
        assert r.base_posture == PostureLevel.DENY_ALERT
        assert r.effective_posture == PostureLevel.DENY_ALERT
        assert r.blast_elevated

    def test_elevation_clamped_score_1_0(self):
        r = posture_matrix.resolve("CLEAN", "ENTERPRISE", blast_radius_score=1.0)
        assert r.blast_elevated
        assert r.effective_posture == PostureLevel.MONITOR_LOG
        assert r.blast_radius_score == 1.0

    def test_elevation_score_zero(self):
        r = posture_matrix.resolve("SENSITIVE", "MANAGED", blast_radius_score=0.0)
        assert r.base_posture == PostureLevel.DENY_ALERT
        assert not r.blast_elevated


# ===========================================================================
# Posture Actions — MONITOR / MONITOR_LOG / RESTRICT / DENY_ALERT
# ===========================================================================


class TestMonitorPosture:
    def test_monitor_allows(self):
        r = posture_matrix.resolve("CLEAN", "ENTERPRISE", 0.0)
        decision = posture_matrix.apply_posture(r, tool_name="bash")
        assert decision.allowed
        assert decision.posture == PostureLevel.MONITOR
        assert not decision.enhanced_logging
        assert not decision.alert_emitted
        assert not decision.hitl_triggered

    def test_monitor_no_alert_event(self):
        r = posture_matrix.resolve("CLEAN", "MANAGED", 0.0)
        decision = posture_matrix.apply_posture(r)
        assert decision.alert_event is None


class TestMonitorLogPosture:
    def test_monitor_log_allows(self):
        r = posture_matrix.resolve("TAINTED", "ENTERPRISE", 0.0)
        decision = posture_matrix.apply_posture(r, tool_name="write_file")
        assert decision.allowed
        assert decision.posture == PostureLevel.MONITOR_LOG
        assert decision.enhanced_logging
        assert not decision.alert_emitted
        assert not decision.hitl_triggered

    def test_monitor_log_elevated_from_monitor(self):
        r = posture_matrix.resolve("CLEAN", "MANAGED", blast_radius_score=0.80)
        assert r.effective_posture == PostureLevel.MONITOR_LOG
        decision = posture_matrix.apply_posture(r)
        assert decision.allowed
        assert decision.enhanced_logging


class TestRestrictPosture:
    def test_restrict_denies_without_permission(self):
        r = posture_matrix.resolve("SENSITIVE", "ENTERPRISE", 0.0)
        decision = posture_matrix.apply_posture(
            r,
            agent_permissions=frozenset({"read"}),
            required_permission="write",
        )
        assert not decision.allowed
        assert decision.posture == PostureLevel.RESTRICT
        assert decision.hitl_triggered

    def test_restrict_allows_with_permission(self):
        r = posture_matrix.resolve("SENSITIVE", "ENTERPRISE", 0.0)
        decision = posture_matrix.apply_posture(
            r,
            agent_permissions=frozenset({"write", "read"}),
            required_permission="write",
        )
        assert decision.allowed
        assert decision.posture == PostureLevel.RESTRICT
        assert decision.hitl_triggered

    def test_restrict_allows_no_required_permission(self):
        r = posture_matrix.resolve("TAINTED", "MANAGED", 0.0)
        decision = posture_matrix.apply_posture(r, agent_permissions=frozenset())
        assert decision.allowed
        assert decision.posture == PostureLevel.RESTRICT
        assert decision.hitl_triggered

    def test_restrict_hitl_triggered_on_allow(self):
        r = posture_matrix.resolve("TAINTED", "HOMEGROWN", 0.0)
        decision = posture_matrix.apply_posture(
            r,
            agent_permissions=frozenset({"execute"}),
            required_permission="execute",
        )
        assert decision.hitl_triggered

    def test_restrict_elevated_from_monitor_log(self):
        r = posture_matrix.resolve("TAINTED", "ENTERPRISE", blast_radius_score=0.90)
        assert r.effective_posture == PostureLevel.RESTRICT
        decision = posture_matrix.apply_posture(
            r,
            agent_permissions=frozenset({"write"}),
            required_permission="write",
        )
        assert decision.allowed
        assert decision.posture == PostureLevel.RESTRICT


class TestDenyAlertPosture:
    def test_deny_alert_hard_denies(self):
        r = posture_matrix.resolve("SENSITIVE", "MANAGED", 0.0)
        decision = posture_matrix.apply_posture(
            r,
            agent_id="agent-1",
            session_id="sess-1",
            tool_name="delete_db",
        )
        assert not decision.allowed
        assert decision.posture == PostureLevel.DENY_ALERT
        assert decision.alert_emitted

    def test_deny_alert_emits_ocsf_event(self):
        r = posture_matrix.resolve("SENSITIVE", "HOMEGROWN", 0.0)
        decision = posture_matrix.apply_posture(
            r,
            agent_id="agent-x",
            session_id="sess-x",
            request_id="req-x",
            tool_name="rm_rf",
        )
        assert decision.alert_event is not None
        event = decision.alert_event
        assert event["class_name"] == "POSTURE_ALERT"
        assert event["decision"] == "DENY"
        assert event["trustsoc_alert"] is True
        assert event["session_flagged_for_review"] is True
        assert event["finding_info"]["posture"] == PostureLevel.DENY_ALERT.value
        assert event["finding_info"]["taint_level"] == "SENSITIVE"
        assert event["finding_info"]["deployment_tier"] == "HOMEGROWN"

    def test_deny_alert_event_contains_blast_radius_score(self):
        r = posture_matrix.resolve("SENSITIVE", "MANAGED", blast_radius_score=0.85)
        decision = posture_matrix.apply_posture(r, agent_id="a", session_id="s")
        assert decision.alert_event is not None
        assert decision.alert_event["finding_info"]["blast_radius_score"] == pytest.approx(0.85)
        assert decision.alert_event["finding_info"]["blast_elevated"] is True

    def test_deny_alert_no_permission_bypass(self):
        r = posture_matrix.resolve("SENSITIVE", "MANAGED", 0.0)
        decision = posture_matrix.apply_posture(
            r,
            agent_permissions=frozenset({"admin", "write", "read"}),
            required_permission="admin",
        )
        assert not decision.allowed


# ===========================================================================
# POSTURE_ALERT OCSF event structure — E08-T06
# ===========================================================================


class TestPostureAlertEvent:
    def test_event_ocsf_structure(self):
        event = emit_posture_alert_event(
            agent_id="agent-a",
            session_id="sess-a",
            request_id="req-a",
            tool_name="drop_table",
            taint_level="SENSITIVE",
            deployment_tier="MANAGED",
            blast_radius_score=0.9,
            blast_elevated=True,
        )
        assert event["class_uid"] == 4003
        assert event["class_name"] == "POSTURE_ALERT"
        assert event["category_uid"] == 4
        assert event["severity_id"] == 5
        assert event["severity"] == "CRITICAL"
        assert event["decision"] == "DENY"
        assert event["metadata"]["event_code"] == "POSTURE_ALERT"
        assert event["metadata"]["profile"] == "TrustFabric/AgentPEP/v1.0"

    def test_event_finding_info(self):
        event = emit_posture_alert_event(
            agent_id="a",
            session_id="s",
            request_id="r",
            tool_name="t",
            taint_level="SENSITIVE",
            deployment_tier="HOMEGROWN",
            blast_radius_score=0.5,
            blast_elevated=False,
        )
        fi = event["finding_info"]
        assert fi["taint_level"] == "SENSITIVE"
        assert fi["deployment_tier"] == "HOMEGROWN"
        assert fi["blast_radius_score"] == pytest.approx(0.5)
        assert fi["blast_elevated"] is False
        assert fi["elevation_threshold"] == BLAST_RADIUS_ELEVATION_THRESHOLD

    def test_event_actor_fields(self):
        event = emit_posture_alert_event(
            agent_id="agent-42",
            session_id="sess-99",
            request_id="",
            tool_name="tool",
            taint_level="CLEAN",
            deployment_tier="ENTERPRISE",
            blast_radius_score=0.0,
            blast_elevated=False,
        )
        assert event["actor"]["agent_id"] == "agent-42"
        assert event["actor"]["session_id"] == "sess-99"

    def test_event_resource_tool_name(self):
        event = emit_posture_alert_event(
            agent_id="",
            session_id="",
            request_id="",
            tool_name="bash_exec",
            taint_level="TAINTED",
            deployment_tier="MANAGED",
            blast_radius_score=0.0,
            blast_elevated=False,
        )
        assert event["resources"][0]["name"] == "bash_exec"


# ===========================================================================
# BlastRadiusContext — E08-T02
# ===========================================================================


class TestBlastRadiusContext:
    def test_score_clamped_above_1(self):
        ctx = BlastRadiusContext(agent_id="a", session_id="s", score=1.5, source="api")
        assert ctx.score == 1.0

    def test_score_clamped_below_0(self):
        ctx = BlastRadiusContext(agent_id="a", session_id="s", score=-0.1, source="api")
        assert ctx.score == 0.0

    def test_is_high_blast_radius_at_threshold(self):
        ctx = BlastRadiusContext(agent_id="a", session_id="s", score=0.75, source="api")
        assert ctx.is_high_blast_radius

    def test_is_high_blast_radius_below_threshold(self):
        ctx = BlastRadiusContext(agent_id="a", session_id="s", score=0.74, source="api")
        assert not ctx.is_high_blast_radius

    def test_fail_closed_returns_max_score(self):
        ctx = BlastRadiusContext.fail_closed("agent-1", "sess-1")
        assert ctx.score == BLAST_RADIUS_FAIL_CLOSED_DEFAULT
        assert ctx.score == 1.0
        assert ctx.source == "fallback"

    def test_fail_closed_is_high_blast_radius(self):
        ctx = BlastRadiusContext.fail_closed("a", "s")
        assert ctx.is_high_blast_radius


# ===========================================================================
# BlastRadiusClient — FAIL_CLOSED on API unavailability — E08-T10
# ===========================================================================


class TestBlastRadiusClientFallback:
    """E08-T10: AAPM Blast Radius API unavailable → defaults to 1.0."""

    @pytest.mark.asyncio
    async def test_no_api_url_returns_default(self):
        client = BlastRadiusClient()
        with patch("app.core.config.settings") as mock_settings:
            mock_settings.aapm_blast_radius_api_url = ""
            mock_settings.aapm_blast_radius_timeout_s = 5.0
            ctx = await client.fetch("agent-1", "sess-1")
        assert ctx.score == 1.0
        assert ctx.source == "default"

    @pytest.mark.asyncio
    async def test_network_error_returns_fail_closed(self):
        client = BlastRadiusClient()
        with patch("app.core.config.settings") as mock_settings:
            mock_settings.aapm_blast_radius_api_url = "https://aapm.internal"
            mock_settings.aapm_blast_radius_timeout_s = 5.0

            async def _raise(*_args, **_kwargs):
                raise ConnectionError("AAPM API unreachable")

            with patch.object(client, "_call_api", side_effect=_raise):
                ctx = await client.fetch("agent-1", "sess-1")
        assert ctx.score == BLAST_RADIUS_FAIL_CLOSED_DEFAULT
        assert ctx.source == "fallback"

    @pytest.mark.asyncio
    async def test_timeout_returns_fail_closed(self):
        client = BlastRadiusClient()
        with patch("app.core.config.settings") as mock_settings:
            mock_settings.aapm_blast_radius_api_url = "https://aapm.internal"
            mock_settings.aapm_blast_radius_timeout_s = 0.001

            async def _sleep_forever(*_args, **_kwargs):
                await asyncio.sleep(10)

            with patch.object(client, "_call_api", side_effect=_sleep_forever):
                ctx = await client.fetch("agent-1", "sess-1")
        assert ctx.score == BLAST_RADIUS_FAIL_CLOSED_DEFAULT
        assert ctx.source == "fallback"

    @pytest.mark.asyncio
    async def test_api_success_parses_score(self):
        client = BlastRadiusClient()
        with patch("app.core.config.settings") as mock_settings:
            mock_settings.aapm_blast_radius_api_url = "https://aapm.internal"
            mock_settings.aapm_blast_radius_timeout_s = 5.0

            async def _return_score(*_args, **_kwargs):
                return 0.42

            with patch.object(client, "_call_api", side_effect=_return_score):
                ctx = await client.fetch("agent-1", "sess-1")
        assert ctx.score == pytest.approx(0.42)
        assert ctx.source == "api"

    def test_fail_closed_posture_elevated(self):
        """E08-T10: API unavailable → score = 1.0 → posture elevated (blast elevation applied)."""
        ctx = BlastRadiusContext.fail_closed("agent-critical", "sess-critical")
        r = posture_matrix.resolve(
            taint_level="CLEAN",
            deployment_tier="ENTERPRISE",
            blast_radius_score=ctx.score,
        )
        assert r.blast_elevated
        assert r.effective_posture == PostureLevel.MONITOR_LOG

    def test_fail_closed_tainted_managed_deny_alert(self):
        """API unavailability on TAINTED/MANAGED → elevates RESTRICT → DENY_ALERT."""
        ctx = BlastRadiusContext.fail_closed("agent-x", "sess-x")
        r = posture_matrix.resolve(
            taint_level="TAINTED",
            deployment_tier="MANAGED",
            blast_radius_score=ctx.score,
        )
        assert r.base_posture == PostureLevel.RESTRICT
        assert r.effective_posture == PostureLevel.DENY_ALERT
        assert r.blast_elevated


# ===========================================================================
# TierDetector — E08-T03
# ===========================================================================


class TestTierDetectorExplicit:
    def test_explicit_enterprise(self):
        detector = TierDetector()
        assert detector.detect("ENTERPRISE") == DeploymentTier.ENTERPRISE

    def test_explicit_managed(self):
        detector = TierDetector()
        assert detector.detect("MANAGED") == DeploymentTier.MANAGED

    def test_explicit_homegrown(self):
        detector = TierDetector()
        assert detector.detect("HOMEGROWN") == DeploymentTier.HOMEGROWN

    def test_explicit_case_insensitive(self):
        detector = TierDetector()
        assert detector.detect("enterprise") == DeploymentTier.ENTERPRISE

    def test_invalid_explicit_falls_through_to_fingerprint(self):
        detector = TierDetector()
        with patch.dict(os.environ, {}, clear=True):
            result = detector.detect("INVALID_TIER")
        assert result == DeploymentTier.HOMEGROWN


class TestTierDetectorEnvMarkers:
    def test_azure_client_id_marks_enterprise(self):
        detector = TierDetector()
        with patch.dict(os.environ, {"AZURE_CLIENT_ID": "some-client-id"}, clear=False):
            tier = detector.detect()
        assert tier == DeploymentTier.ENTERPRISE

    def test_aws_container_credentials_marks_enterprise(self):
        detector = TierDetector()
        with patch.dict(
            os.environ,
            {"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/v2/credentials/..."},
            clear=False,
        ):
            tier = detector.detect()
        assert tier == DeploymentTier.ENTERPRISE

    def test_salesforce_env_marks_managed(self):
        detector = TierDetector()
        with patch.dict(
            os.environ,
            {"SF_AGENT_CONTEXT": "true"},
            clear=False,
        ):
            tier = detector.detect()
        assert tier == DeploymentTier.MANAGED

    def test_agentpep_managed_runtime_marks_managed(self):
        detector = TierDetector()
        with patch.dict(
            os.environ,
            {"AGENTPEP_MANAGED_RUNTIME": "1"},
            clear=False,
        ):
            tier = detector.detect()
        assert tier == DeploymentTier.MANAGED

    def test_agentpep_deployment_tier_env_override(self):
        detector = TierDetector()
        with patch.dict(
            os.environ,
            {"AGENTPEP_DEPLOYMENT_TIER": "ENTERPRISE"},
            clear=False,
        ):
            tier = detector.detect()
        assert tier == DeploymentTier.ENTERPRISE


class TestTierDetectorDefault:
    def test_no_markers_defaults_to_homegrown(self):
        detector = TierDetector()
        safe_env = {
            k: v
            for k, v in os.environ.items()
            if k not in {
                "AZURE_CLIENT_ID",
                "AZURE_MANAGED_IDENTITY_CLIENT_ID",
                "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "GKE_WORKLOAD_IDENTITY",
                "GOOGLE_APPLICATION_CREDENTIALS",
                "AGENTPEP_ENTERPRISE_RUNTIME",
                "SF_AGENT_CONTEXT",
                "SALESFORCE_INSTANCE_URL",
                "SN_AGENT_ID",
                "SERVICENOW_INSTANCE",
                "WORKDAY_AGENT_TENANT",
                "POWER_PLATFORM_AGENT",
                "AGENTPEP_SAAS_RUNTIME",
                "AGENTPEP_MANAGED_RUNTIME",
                "AGENTPEP_DEPLOYMENT_TIER",
            }
        }
        with patch.dict(os.environ, safe_env, clear=True):
            with patch("app.session.tier_detection._sdk_present", return_value=False):
                tier = detector.detect()
        assert tier == DeploymentTier.HOMEGROWN


# ===========================================================================
# AuthorizationRequestBuilder — S-E08 blast_radius_score default = 1.0
# ===========================================================================


class TestRequestBuilderBlastDefault:
    def test_default_blast_radius_score_is_1(self):
        from app.pdp.request_builder import AuthorizationRequestBuilder

        builder = AuthorizationRequestBuilder()
        req = builder.build(tool_name="bash", tool_args={})
        assert req.blast_radius_score == pytest.approx(1.0)

    def test_explicit_blast_radius_score_used(self):
        from app.pdp.request_builder import AuthorizationRequestBuilder

        builder = AuthorizationRequestBuilder()
        req = builder.build(
            tool_name="bash",
            tool_args={},
            blast_radius_score=0.42,
        )
        assert req.blast_radius_score == pytest.approx(0.42)

    def test_blast_radius_score_clamped(self):
        from app.pdp.request_builder import AuthorizationRequestBuilder

        builder = AuthorizationRequestBuilder()
        req = builder.build(tool_name="bash", tool_args={}, blast_radius_score=2.5)
        assert req.blast_radius_score == pytest.approx(1.0)

    def test_blast_radius_score_in_opa_input(self):
        from app.pdp.request_builder import AuthorizationRequestBuilder

        builder = AuthorizationRequestBuilder()
        req = builder.build(
            tool_name="list_files",
            tool_args={},
            blast_radius_score=0.65,
            deployment_tier="MANAGED",
        )
        opa_input = req.to_opa_input()
        assert "blast_radius_score" in opa_input
        assert opa_input["blast_radius_score"] == pytest.approx(0.65)
        assert "deployment_tier" in opa_input
        assert opa_input["deployment_tier"] == "MANAGED"


# ===========================================================================
# Integration — end-to-end session context → posture decision
# ===========================================================================


class TestIntegrationSessionToPosture:
    def test_high_risk_session_deny_alert(self):
        """AAPM API unavailable → score=1.0 → SENSITIVE/MANAGED → DENY_ALERT."""
        ctx = BlastRadiusContext.fail_closed("dangerous-agent", "sess-danger")
        tier = DeploymentTier.MANAGED
        resolution = posture_matrix.resolve(
            taint_level="SENSITIVE",
            deployment_tier=tier.value,
            blast_radius_score=ctx.score,
        )
        decision = posture_matrix.apply_posture(
            resolution,
            agent_id="dangerous-agent",
            session_id="sess-danger",
            tool_name="drop_database",
        )
        assert not decision.allowed
        assert decision.posture == PostureLevel.DENY_ALERT
        assert decision.alert_emitted

    def test_low_risk_session_monitor(self):
        """Low blast radius + CLEAN taint + ENTERPRISE → MONITOR (allow)."""
        ctx = BlastRadiusContext(
            agent_id="safe-agent",
            session_id="sess-safe",
            score=0.10,
            source="api",
        )
        resolution = posture_matrix.resolve(
            taint_level="CLEAN",
            deployment_tier="ENTERPRISE",
            blast_radius_score=ctx.score,
        )
        decision = posture_matrix.apply_posture(resolution)
        assert decision.allowed
        assert decision.posture == PostureLevel.MONITOR

    def test_medium_risk_session_restrict(self):
        """Medium blast radius + TAINTED + MANAGED → RESTRICT; HITL triggered."""
        ctx = BlastRadiusContext(
            agent_id="medium-agent",
            session_id="sess-med",
            score=0.50,
            source="api",
        )
        resolution = posture_matrix.resolve(
            taint_level="TAINTED",
            deployment_tier="MANAGED",
            blast_radius_score=ctx.score,
        )
        decision = posture_matrix.apply_posture(
            resolution,
            agent_permissions=frozenset({"data_access"}),
            required_permission="data_access",
        )
        assert decision.allowed
        assert decision.posture == PostureLevel.RESTRICT
        assert decision.hitl_triggered

    def test_blast_elevation_clean_enterprise_becomes_monitor_log(self):
        """CLEAN/ENTERPRISE + blast ≥ 0.75 → MONITOR_LOG (enhanced logging)."""
        ctx = BlastRadiusContext(
            agent_id="wide-reach",
            session_id="sess-wide",
            score=0.80,
            source="api",
        )
        resolution = posture_matrix.resolve(
            taint_level="CLEAN",
            deployment_tier="ENTERPRISE",
            blast_radius_score=ctx.score,
        )
        decision = posture_matrix.apply_posture(resolution, tool_name="list_files")
        assert decision.allowed
        assert decision.enhanced_logging
        assert resolution.blast_elevated
