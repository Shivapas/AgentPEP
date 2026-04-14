"""Unit tests for Sprint 51 — Rule Bundles, Security Assessment & Network Audit Events.

APEP-404.e: Unit tests for rule bundle format.
APEP-405.e: Unit tests for rule bundle loader.
APEP-406.f: Unit tests for security assessment engine.
APEP-407.e: Unit tests for GET /v1/network/assess endpoint.
APEP-408.c: Unit tests for MITRE ATT&CK technique mapping.
"""

import base64
import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from app.models.rule_bundle import (
    AssessmentCategory,
    AssessmentFinding,
    AssessmentPhase,
    AssessmentSeverity,
    BundleRule,
    BundleRuleType,
    BundleStatus,
    MitreTactic,
    MitreTechnique,
    MitreTechniqueMap,
    RuleBundle,
    RuleBundleListResponse,
    RuleBundleLoadRequest,
    RuleBundleLoadResponse,
    RuleBundleManifest,
    SecurityAssessmentRequest,
    SecurityAssessmentResult,
)


# ---------------------------------------------------------------------------
# APEP-404.e: Rule Bundle Format model tests
# ---------------------------------------------------------------------------


class TestRuleBundleModels:
    """Unit tests for rule bundle Pydantic models."""

    def test_bundle_rule_defaults(self):
        rule = BundleRule(rule_id="DLP-001", rule_type=BundleRuleType.DLP)
        assert rule.rule_id == "DLP-001"
        assert rule.rule_type == BundleRuleType.DLP
        assert rule.severity == AssessmentSeverity.MEDIUM
        assert rule.enabled is True
        assert rule.pattern == ""
        assert rule.mitre_technique_id == ""

    def test_bundle_rule_full(self):
        rule = BundleRule(
            rule_id="DLP-001",
            rule_type=BundleRuleType.DLP,
            pattern=r"(?i)sk-[a-z0-9]{48}",
            severity=AssessmentSeverity.HIGH,
            description="OpenAI API Key",
            mitre_technique_id="T1552",
            enabled=True,
            metadata={"vendor": "openai"},
        )
        assert rule.pattern == r"(?i)sk-[a-z0-9]{48}"
        assert rule.severity == AssessmentSeverity.HIGH
        assert rule.mitre_technique_id == "T1552"
        assert rule.metadata == {"vendor": "openai"}

    def test_bundle_manifest_defaults(self):
        manifest = RuleBundleManifest(name="test-bundle")
        assert manifest.name == "test-bundle"
        assert manifest.version == "1.0.0"
        assert manifest.author == ""
        assert manifest.description == ""
        assert manifest.tags == []
        assert manifest.min_agentpep_version == "1.0.0"
        assert manifest.created_at is not None

    def test_bundle_manifest_full(self):
        manifest = RuleBundleManifest(
            name="community-dlp-v2",
            version="2.1.0",
            author="AgentPEP Community",
            description="Community DLP patterns",
            tags=["dlp", "community"],
        )
        assert manifest.name == "community-dlp-v2"
        assert manifest.version == "2.1.0"
        assert manifest.author == "AgentPEP Community"
        assert len(manifest.tags) == 2

    def test_rule_bundle_defaults(self):
        manifest = RuleBundleManifest(name="test")
        bundle = RuleBundle(manifest=manifest)
        assert bundle.bundle_id is not None
        assert isinstance(bundle.bundle_id, UUID)
        assert bundle.status == BundleStatus.PENDING_REVIEW
        assert bundle.verified is False
        assert bundle.rules == []
        assert bundle.signature == ""

    def test_rule_bundle_full(self):
        manifest = RuleBundleManifest(name="test")
        rules = [
            BundleRule(rule_id="R1", rule_type=BundleRuleType.DLP),
            BundleRule(rule_id="R2", rule_type=BundleRuleType.INJECTION),
        ]
        bundle = RuleBundle(
            manifest=manifest,
            rules=rules,
            status=BundleStatus.ACTIVE,
            signature="abc123",
            signing_key_id="key-1",
            verified=True,
            loaded_at=datetime.now(UTC),
            file_path="/path/to/bundle.yaml",
        )
        assert len(bundle.rules) == 2
        assert bundle.status == BundleStatus.ACTIVE
        assert bundle.verified is True
        assert bundle.signing_key_id == "key-1"

    def test_bundle_status_enum(self):
        assert BundleStatus.ACTIVE == "ACTIVE"
        assert BundleStatus.INACTIVE == "INACTIVE"
        assert BundleStatus.INVALID == "INVALID"
        assert BundleStatus.PENDING_REVIEW == "PENDING_REVIEW"

    def test_bundle_rule_type_enum(self):
        assert BundleRuleType.DLP == "DLP"
        assert BundleRuleType.INJECTION == "INJECTION"
        assert BundleRuleType.URL_BLOCK == "URL_BLOCK"
        assert BundleRuleType.CHAIN_PATTERN == "CHAIN_PATTERN"
        assert BundleRuleType.CUSTOM == "CUSTOM"

    def test_rule_bundle_list_response(self):
        manifest = RuleBundleManifest(name="test")
        bundle = RuleBundle(manifest=manifest)
        resp = RuleBundleListResponse(bundles=[bundle], total=1)
        assert resp.total == 1
        assert len(resp.bundles) == 1

    def test_rule_bundle_load_request_yaml(self):
        req = RuleBundleLoadRequest(
            yaml_content="manifest:\n  name: test",
            verify_signature=False,
            activate=True,
        )
        assert req.yaml_content is not None
        assert req.file_path is None
        assert req.verify_signature is False
        assert req.activate is True

    def test_rule_bundle_load_request_file(self):
        req = RuleBundleLoadRequest(file_path="/bundles/community.yaml")
        assert req.file_path == "/bundles/community.yaml"
        assert req.verify_signature is True

    def test_rule_bundle_load_response(self):
        manifest = RuleBundleManifest(name="test")
        bundle = RuleBundle(manifest=manifest)
        resp = RuleBundleLoadResponse(
            bundle=bundle,
            rules_loaded=5,
            rules_skipped=1,
            warnings=["Rule at index 3 missing rule_id"],
        )
        assert resp.rules_loaded == 5
        assert resp.rules_skipped == 1
        assert len(resp.warnings) == 1


# ---------------------------------------------------------------------------
# APEP-405.e: Rule Bundle Loader tests
# ---------------------------------------------------------------------------


class TestRuleBundleLoader:
    """Unit tests for the rule bundle loader service."""

    def test_load_from_yaml_minimal(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        yaml_content = """
manifest:
  name: test-bundle
rules:
  - rule_id: R1
    rule_type: DLP
    pattern: "test-pattern"
"""
        result = loader.load_from_yaml(yaml_content, verify_signature=False)
        assert result.rules_loaded == 1
        assert result.rules_skipped == 0
        assert result.bundle.manifest.name == "test-bundle"
        assert result.bundle.rules[0].rule_id == "R1"

    def test_load_from_yaml_with_multiple_rules(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        yaml_content = """
manifest:
  name: multi-rule-bundle
  version: 2.0.0
  author: Test Author
rules:
  - rule_id: DLP-001
    rule_type: DLP
    pattern: "sk-[a-z0-9]+"
    severity: HIGH
    description: OpenAI API Key
  - rule_id: INJ-001
    rule_type: INJECTION
    pattern: "ignore all previous"
    severity: CRITICAL
  - rule_id: URL-001
    rule_type: URL_BLOCK
    pattern: "evil\\\\.com"
    severity: MEDIUM
"""
        result = loader.load_from_yaml(yaml_content, verify_signature=False)
        assert result.rules_loaded == 3
        assert result.bundle.manifest.version == "2.0.0"
        assert result.bundle.manifest.author == "Test Author"

    def test_load_from_yaml_skips_invalid_rules(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        yaml_content = """
manifest:
  name: partial-bundle
rules:
  - rule_id: R1
    rule_type: DLP
  - not_a_mapping
  - rule_type: DLP
"""
        result = loader.load_from_yaml(yaml_content, verify_signature=False)
        assert result.rules_loaded == 1
        assert result.rules_skipped == 2
        assert len(result.warnings) == 2

    def test_load_from_yaml_invalid_yaml(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        with pytest.raises(ValueError, match="Invalid YAML"):
            loader.load_from_yaml("{{invalid yaml}}: [", verify_signature=False)

    def test_load_from_yaml_missing_manifest(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        with pytest.raises(ValueError, match="manifest"):
            loader.load_from_yaml("rules: []", verify_signature=False)

    def test_load_from_yaml_missing_name(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        with pytest.raises(ValueError, match="name"):
            loader.load_from_yaml("manifest:\n  version: '1.0'\nrules: []", verify_signature=False)

    def test_list_bundles(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        yaml1 = "manifest:\n  name: b1\nrules: []"
        yaml2 = "manifest:\n  name: b2\nrules: []"
        loader.load_from_yaml(yaml1, verify_signature=False)
        loader.load_from_yaml(yaml2, verify_signature=False)
        resp = loader.list_bundles()
        assert resp.total == 2

    def test_list_bundles_filtered(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        yaml1 = "manifest:\n  name: b1\nrules: []"
        result = loader.load_from_yaml(yaml1, verify_signature=False, activate=True)
        loader.load_from_yaml("manifest:\n  name: b2\nrules: []", verify_signature=False)
        active_resp = loader.list_bundles(status=BundleStatus.ACTIVE)
        assert active_resp.total == 1
        assert active_resp.bundles[0].manifest.name == "b1"

    def test_activate_deactivate_bundle(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        result = loader.load_from_yaml(
            "manifest:\n  name: test\nrules: []", verify_signature=False
        )
        bid = result.bundle.bundle_id
        # Activate
        bundle = loader.activate_bundle(bid)
        assert bundle is not None
        assert bundle.status == BundleStatus.ACTIVE
        # Deactivate
        bundle = loader.deactivate_bundle(bid)
        assert bundle is not None
        assert bundle.status == BundleStatus.INACTIVE

    def test_remove_bundle(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        result = loader.load_from_yaml(
            "manifest:\n  name: test\nrules: []", verify_signature=False
        )
        bid = result.bundle.bundle_id
        assert loader.remove_bundle(bid) is True
        assert loader.get_bundle(bid) is None
        assert loader.remove_bundle(bid) is False

    def test_get_active_rules(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        yaml_content = """
manifest:
  name: active-bundle
rules:
  - rule_id: R1
    rule_type: DLP
    enabled: true
  - rule_id: R2
    rule_type: INJECTION
    enabled: false
"""
        result = loader.load_from_yaml(yaml_content, verify_signature=False, activate=True)
        # Only enabled rules from active bundles
        active_rules = loader.get_active_rules()
        assert len(active_rules) == 1
        assert active_rules[0].rule_id == "R1"

    def test_get_active_rules_by_type(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        yaml_content = """
manifest:
  name: typed-bundle
rules:
  - rule_id: R1
    rule_type: DLP
  - rule_id: R2
    rule_type: INJECTION
  - rule_id: R3
    rule_type: DLP
"""
        loader.load_from_yaml(yaml_content, verify_signature=False, activate=True)
        dlp_rules = loader.get_active_rules(rule_type=BundleRuleType.DLP)
        assert len(dlp_rules) == 2
        inj_rules = loader.get_active_rules(rule_type=BundleRuleType.INJECTION)
        assert len(inj_rules) == 1

    def test_stats(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        loader.load_from_yaml(
            "manifest:\n  name: b1\nrules:\n  - rule_id: R1\n    rule_type: DLP",
            verify_signature=False,
            activate=True,
        )
        stats = loader.stats()
        assert stats["total_bundles"] == 1
        assert stats["active_bundles"] == 1
        assert stats["total_rules"] == 1
        assert stats["active_rules"] == 1
        assert stats["trusted_keys"] == 0

    def test_trusted_key_management(self):
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        loader.register_trusted_key("key-1", b"\x00" * 32)
        assert "key-1" in loader.list_trusted_keys()

    def test_signature_verification_no_nacl_key(self):
        """Signature fails when key is not registered."""
        from app.services.rule_bundle_loader import RuleBundleLoader

        loader = RuleBundleLoader()
        yaml_content = """
manifest:
  name: signed-bundle
signature: dGVzdA==
signing_key_id: unknown-key
rules:
  - rule_id: R1
    rule_type: DLP
"""
        result = loader.load_from_yaml(yaml_content, verify_signature=True)
        assert result.bundle.verified is False
        assert any("FAILED" in w or "unknown" in w.lower() for w in result.warnings)


# ---------------------------------------------------------------------------
# APEP-406.f: Security Assessment Engine tests
# ---------------------------------------------------------------------------


class TestSecurityAssessmentModels:
    """Unit tests for security assessment Pydantic models."""

    def test_assessment_finding_defaults(self):
        finding = AssessmentFinding(
            category=AssessmentCategory.DLP_COVERAGE,
            phase=AssessmentPhase.CONFIG_AUDIT,
        )
        assert finding.finding_id is not None
        assert finding.severity == AssessmentSeverity.MEDIUM
        assert finding.passed is False
        assert finding.evidence == {}

    def test_assessment_finding_full(self):
        finding = AssessmentFinding(
            category=AssessmentCategory.AUTH_CONFIG,
            phase=AssessmentPhase.DEPLOYMENT_PROBE,
            severity=AssessmentSeverity.CRITICAL,
            title="API auth disabled",
            description="Auth is disabled in production",
            recommendation="Enable auth_enabled",
            mitre_technique_id="T1190",
            passed=False,
            evidence={"auth_enabled": False},
        )
        assert finding.severity == AssessmentSeverity.CRITICAL
        assert finding.mitre_technique_id == "T1190"
        assert finding.evidence["auth_enabled"] is False

    def test_assessment_request_defaults(self):
        req = SecurityAssessmentRequest()
        assert len(req.phases) == 3
        assert req.categories is None
        assert req.include_passed is True

    def test_assessment_request_custom(self):
        req = SecurityAssessmentRequest(
            phases=[AssessmentPhase.CONFIG_AUDIT],
            categories=[AssessmentCategory.DLP_COVERAGE, AssessmentCategory.AUTH_CONFIG],
            include_passed=False,
        )
        assert len(req.phases) == 1
        assert len(req.categories) == 2
        assert req.include_passed is False

    def test_assessment_result_defaults(self):
        result = SecurityAssessmentResult()
        assert result.assessment_id is not None
        assert result.overall_score == 0.0
        assert result.grade == "F"
        assert result.total_checks == 0

    def test_assessment_result_scoring(self):
        result = SecurityAssessmentResult(
            total_checks=10,
            passed_checks=8,
            failed_checks=2,
            critical_findings=0,
            high_findings=1,
            overall_score=85.0,
            grade="B",
        )
        assert result.grade == "B"
        assert result.overall_score == 85.0

    def test_assessment_category_enum(self):
        assert AssessmentCategory.DLP_COVERAGE == "DLP_COVERAGE"
        assert AssessmentCategory.KILL_SWITCH == "KILL_SWITCH"
        assert AssessmentCategory.NETWORK_EGRESS == "NETWORK_EGRESS"
        assert len(AssessmentCategory) == 12

    def test_assessment_phase_enum(self):
        assert AssessmentPhase.CONFIG_AUDIT == "CONFIG_AUDIT"
        assert AssessmentPhase.ATTACK_SIMULATION == "ATTACK_SIMULATION"
        assert AssessmentPhase.DEPLOYMENT_PROBE == "DEPLOYMENT_PROBE"


class TestSecurityAssessmentEngine:
    """Unit tests for the security assessment engine service."""

    @pytest.mark.asyncio
    async def test_run_assessment_default(self):
        from app.services.security_assessment import SecurityAssessmentEngine

        engine = SecurityAssessmentEngine()
        result = await engine.run_assessment()
        assert result.assessment_id is not None
        assert result.total_checks > 0
        assert 0.0 <= result.overall_score <= 100.0
        assert result.grade in ("A", "B", "C", "D", "F")
        assert result.latency_ms >= 0
        assert result.completed_at is not None
        assert len(result.phases_run) == 3

    @pytest.mark.asyncio
    async def test_run_assessment_config_audit_only(self):
        from app.services.security_assessment import SecurityAssessmentEngine

        engine = SecurityAssessmentEngine()
        request = SecurityAssessmentRequest(
            phases=[AssessmentPhase.CONFIG_AUDIT],
        )
        result = await engine.run_assessment(request)
        assert AssessmentPhase.CONFIG_AUDIT in result.phases_run
        assert AssessmentPhase.ATTACK_SIMULATION not in result.phases_run
        assert result.total_checks > 0

    @pytest.mark.asyncio
    async def test_run_assessment_specific_categories(self):
        from app.services.security_assessment import SecurityAssessmentEngine

        engine = SecurityAssessmentEngine()
        request = SecurityAssessmentRequest(
            phases=[AssessmentPhase.CONFIG_AUDIT],
            categories=[AssessmentCategory.AUTH_CONFIG],
        )
        result = await engine.run_assessment(request)
        for finding in result.findings:
            assert finding.category == AssessmentCategory.AUTH_CONFIG

    @pytest.mark.asyncio
    async def test_run_assessment_exclude_passed(self):
        from app.services.security_assessment import SecurityAssessmentEngine

        engine = SecurityAssessmentEngine()
        request = SecurityAssessmentRequest(include_passed=False)
        result = await engine.run_assessment(request)
        for finding in result.findings:
            assert finding.passed is False

    @pytest.mark.asyncio
    async def test_assessment_score_grade_mapping(self):
        from app.services.security_assessment import _grade

        assert _grade(95.0) == "A"
        assert _grade(85.0) == "B"
        assert _grade(75.0) == "C"
        assert _grade(65.0) == "D"
        assert _grade(50.0) == "F"

    @pytest.mark.asyncio
    async def test_last_result_cached(self):
        from app.services.security_assessment import SecurityAssessmentEngine

        engine = SecurityAssessmentEngine()
        assert engine.last_result is None
        result = await engine.run_assessment()
        assert engine.last_result is not None
        assert engine.last_result.assessment_id == result.assessment_id


# ---------------------------------------------------------------------------
# APEP-408.c: MITRE ATT&CK Technique Mapping tests
# ---------------------------------------------------------------------------


class TestMitreTechniqueModels:
    """Unit tests for MITRE ATT&CK Pydantic models."""

    def test_mitre_technique(self):
        t = MitreTechnique(
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic=MitreTactic.INITIAL_ACCESS,
            description="Test",
        )
        assert t.technique_id == "T1190"
        assert t.tactic == MitreTactic.INITIAL_ACCESS

    def test_mitre_tactic_enum(self):
        assert MitreTactic.INITIAL_ACCESS == "TA0001"
        assert MitreTactic.EXFILTRATION == "TA0010"

    def test_mitre_technique_map(self):
        m = MitreTechniqueMap()
        assert m.techniques == {}
        assert m.event_type_mappings == {}
        assert m.rule_id_mappings == {}
        assert m.last_updated is not None


class TestMitreAttackMapper:
    """Unit tests for the MITRE ATT&CK mapper service."""

    def test_get_technique(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        t = mapper.get_technique("T1190")
        assert t is not None
        assert t.technique_name == "Exploit Public-Facing Application"

    def test_get_technique_unknown(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        assert mapper.get_technique("T9999") is None

    def test_get_techniques_for_event(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        techs = mapper.get_techniques_for_event("DLP_HIT")
        assert len(techs) > 0
        assert "T1552" in techs

    def test_get_techniques_for_unknown_event(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        techs = mapper.get_techniques_for_event("UNKNOWN_EVENT")
        assert techs == []

    def test_get_primary_technique_for_event(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        t = mapper.get_primary_technique_for_event("SSRF_BLOCKED")
        assert t == "T1190"

    def test_get_primary_technique_for_unknown_event(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        assert mapper.get_primary_technique_for_event("UNKNOWN") == ""

    def test_register_rule_mapping(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        mapper.register_rule_mapping("DLP-001", "T1552")
        assert mapper.get_technique_for_rule("DLP-001") == "T1552"

    def test_enrich_event_with_rule(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        mapper.register_rule_mapping("DLP-001", "T1048")
        # Rule mapping takes priority
        result = mapper.enrich_event("DLP_HIT", "DLP-001")
        assert result == "T1048"

    def test_enrich_event_without_rule(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        result = mapper.enrich_event("INJECTION_DETECTED")
        assert result == "T1059"

    def test_enrich_event_unknown(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        assert mapper.enrich_event("UNKNOWN") == ""

    def test_register_custom_technique(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        custom = MitreTechnique(
            technique_id="T9999",
            technique_name="Custom Technique",
        )
        mapper.register_custom_technique(custom)
        assert mapper.get_technique("T9999") is not None

    def test_get_full_map(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        full_map = mapper.get_full_map()
        assert isinstance(full_map, MitreTechniqueMap)
        assert len(full_map.techniques) > 0
        assert len(full_map.event_type_mappings) > 0

    def test_stats(self):
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        stats = mapper.stats()
        assert stats["techniques"] > 0
        assert stats["event_type_mappings"] > 0
        assert stats["rule_id_mappings"] == 0

    def test_all_event_types_mapped(self):
        """Ensure all NetworkEventType values have MITRE mappings."""
        from app.models.network_scan import NetworkEventType
        from app.services.mitre_attack_mapper import MitreAttackMapper

        mapper = MitreAttackMapper()
        for event_type in NetworkEventType:
            techs = mapper.get_techniques_for_event(event_type.value)
            assert len(techs) > 0, f"No MITRE mapping for {event_type.value}"
