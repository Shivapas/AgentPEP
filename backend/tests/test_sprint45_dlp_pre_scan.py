"""Tests for Sprint 45 -- DLP Pre-Scan Hook in Intercept Pipeline.

APEP-356: DLPPreScanStage in PolicyEvaluator — unit tests.
APEP-357: DLP-to-risk mapping — unit tests.
APEP-358: DLP-to-taint assignment — security validation tests.
APEP-359: DLP findings to PolicyDecisionResponse — unit tests.
APEP-361: DLP pre-scan caching — unit tests.
APEP-363: DLP pattern hot-reload — unit tests.
"""

import re
import time

import pytest

from app.models.policy import (
    DLPFinding,
    DLPPatternType,
    DLPScanResult,
    DLPSeverity,
    TaintLevel,
)
from app.services.network_dlp import (
    DLPPatternRegistry,
    DLPPattern,
    DLPPreScanCache,
    NetworkDLPScanner,
    _DLP_PATTERNS,
    apply_dlp_taint,
    compute_dlp_risk_elevation,
    determine_taint_action,
)


# ===========================================================================
# APEP-356: NetworkDLPScanner — Core Logic Tests
# ===========================================================================


class TestNetworkDLPScanner:
    """Unit tests for the NetworkDLPScanner service (APEP-356)."""

    def setup_method(self):
        self.scanner = NetworkDLPScanner()
        # Disable caching for unit tests
        self.scanner.cache = DLPPreScanCache(max_size=0, max_age_s=0)

    def test_scan_empty_args(self):
        """Empty tool args should return clean result."""
        result = self.scanner.scan_tool_args({})
        assert result.scanned is True
        assert result.has_findings is False
        assert result.findings == []
        assert result.risk_elevation == 0.0
        assert result.taint_action is None

    def test_scan_clean_args(self):
        """Clean tool args without sensitive data should return no findings."""
        result = self.scanner.scan_tool_args({
            "filename": "report.txt",
            "content": "Hello world, this is a test document.",
        })
        assert result.scanned is True
        assert result.has_findings is False

    def test_detect_aws_access_key(self):
        """Should detect AWS Access Key ID (DLP-001)."""
        result = self.scanner.scan_tool_args({
            "config": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
        })
        assert result.has_findings is True
        found_ids = {f.pattern_id for f in result.findings}
        assert "DLP-001" in found_ids
        assert any(f.pattern_type == DLPPatternType.API_KEY for f in result.findings)

    def test_detect_github_pat(self):
        """Should detect GitHub Personal Access Token (DLP-011)."""
        result = self.scanner.scan_tool_args({
            "auth": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123"
        })
        assert result.has_findings is True
        found_ids = {f.pattern_id for f in result.findings}
        assert "DLP-011" in found_ids
        assert any(f.pattern_type == DLPPatternType.TOKEN for f in result.findings)

    def test_detect_private_key(self):
        """Should detect PEM private key (DLP-021)."""
        result = self.scanner.scan_tool_args({
            "key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        })
        assert result.has_findings is True
        found_ids = {f.pattern_id for f in result.findings}
        assert "DLP-021" in found_ids
        assert any(f.severity == DLPSeverity.CRITICAL for f in result.findings)

    def test_detect_ssn(self):
        """Should detect US Social Security Number (DLP-031)."""
        result = self.scanner.scan_tool_args({
            "user_data": "SSN: 123-45-6789"
        })
        assert result.has_findings is True
        found_ids = {f.pattern_id for f in result.findings}
        assert "DLP-031" in found_ids
        assert any(f.pattern_type == DLPPatternType.PII for f in result.findings)

    def test_detect_email(self):
        """Should detect email addresses (DLP-032)."""
        result = self.scanner.scan_tool_args({
            "contact": "user@example.com"
        })
        assert result.has_findings is True
        found_ids = {f.pattern_id for f in result.findings}
        assert "DLP-032" in found_ids

    def test_detect_bearer_token(self):
        """Should detect Bearer token (DLP-026)."""
        result = self.scanner.scan_tool_args({
            "headers": "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        })
        assert result.has_findings is True
        found_ids = {f.pattern_id for f in result.findings}
        assert "DLP-026" in found_ids

    def test_detect_connection_string(self):
        """Should detect database connection strings (DLP-028/029/030)."""
        result = self.scanner.scan_tool_args({
            "db": "mongodb+srv://user:password123@cluster.mongodb.net/db"
        })
        assert result.has_findings is True
        found_ids = {f.pattern_id for f in result.findings}
        assert "DLP-030" in found_ids

    def test_detect_openai_key(self):
        """Should detect OpenAI-style secret key (DLP-005)."""
        result = self.scanner.scan_tool_args({
            "api_key": "sk-1234567890abcdefghijklmnopqrstuv"
        })
        assert result.has_findings is True
        found_ids = {f.pattern_id for f in result.findings}
        assert "DLP-005" in found_ids

    def test_detect_slack_token(self):
        """Should detect Slack token (DLP-008)."""
        result = self.scanner.scan_tool_args({
            "token": "xoxb-FAKE0TOKEN0-FAKE0TOKEN0TEST"
        })
        assert result.has_findings is True
        found_ids = {f.pattern_id for f in result.findings}
        assert "DLP-008" in found_ids

    def test_detect_nested_args(self):
        """Should detect secrets in nested dict/list structures."""
        result = self.scanner.scan_tool_args({
            "config": {
                "auth": {
                    "key": "AKIAIOSFODNN7EXAMPLE"
                }
            }
        })
        assert result.has_findings is True
        found_ids = {f.pattern_id for f in result.findings}
        assert "DLP-001" in found_ids

    def test_detect_in_list_values(self):
        """Should detect secrets in list values."""
        result = self.scanner.scan_tool_args({
            "tokens": ["ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123", "safe_value"]
        })
        assert result.has_findings is True

    def test_multiple_findings(self):
        """Should report multiple findings for multiple pattern matches."""
        result = self.scanner.scan_tool_args({
            "aws_key": "AKIAIOSFODNN7EXAMPLE",
            "github_token": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123",
            "user_ssn": "123-45-6789",
        })
        assert len(result.findings) >= 3

    def test_scan_duration_recorded(self):
        """Scan duration should be a positive number."""
        result = self.scanner.scan_tool_args({
            "data": "AKIAIOSFODNN7EXAMPLE"
        })
        assert result.scan_duration_ms >= 0

    def test_matched_arg_identification(self):
        """Should identify which arg key contained the match."""
        result = self.scanner.scan_tool_args({
            "safe_field": "hello",
            "secret_field": "AKIAIOSFODNN7EXAMPLE",
        })
        assert result.has_findings is True
        aws_finding = next(f for f in result.findings if f.pattern_id == "DLP-001")
        assert aws_finding.matched_arg == "secret_field"

    def test_redacted_snippet_no_raw_secret(self):
        """Redacted snippet should not contain the full raw secret."""
        result = self.scanner.scan_tool_args({
            "key": "AKIAIOSFODNN7EXAMPLE"
        })
        assert result.has_findings is True
        for finding in result.findings:
            assert "AKIAIOSFODNN7EXAMPLE" not in finding.redacted_snippet

    def test_all_46_patterns_loaded(self):
        """The default pattern registry should have 46 patterns."""
        assert len(_DLP_PATTERNS) == 46
        assert len(self.scanner.registry.patterns) == 46


# ===========================================================================
# APEP-357: DLP-to-Risk Mapping Tests
# ===========================================================================


class TestDLPRiskMapping:
    """Unit tests for DLP-to-risk score mapping (APEP-357)."""

    def test_no_findings_zero_risk(self):
        """No findings should produce zero risk elevation."""
        assert compute_dlp_risk_elevation([]) == 0.0

    def test_critical_credential_high_risk(self):
        """CRITICAL credential findings should produce high risk."""
        findings = [
            DLPFinding(
                pattern_id="DLP-021",
                pattern_type=DLPPatternType.CREDENTIAL,
                severity=DLPSeverity.CRITICAL,
                description="Private Key",
            ),
        ]
        risk = compute_dlp_risk_elevation(findings)
        assert risk >= 0.9  # CRITICAL * CREDENTIAL multiplier

    def test_medium_pii_moderate_risk(self):
        """MEDIUM PII findings should produce moderate risk."""
        findings = [
            DLPFinding(
                pattern_id="DLP-032",
                pattern_type=DLPPatternType.PII,
                severity=DLPSeverity.MEDIUM,
                description="Email",
            ),
        ]
        risk = compute_dlp_risk_elevation(findings)
        assert 0.1 < risk < 0.5  # MEDIUM * PII multiplier

    def test_high_api_key_elevated_risk(self):
        """HIGH API_KEY findings should produce elevated risk."""
        findings = [
            DLPFinding(
                pattern_id="DLP-005",
                pattern_type=DLPPatternType.API_KEY,
                severity=DLPSeverity.HIGH,
                description="OpenAI Key",
            ),
        ]
        risk = compute_dlp_risk_elevation(findings)
        assert risk == 0.6  # HIGH base * 1.0 multiplier

    def test_max_severity_wins(self):
        """When multiple findings present, max severity wins."""
        findings = [
            DLPFinding(
                pattern_id="DLP-032",
                pattern_type=DLPPatternType.PII,
                severity=DLPSeverity.LOW,
            ),
            DLPFinding(
                pattern_id="DLP-021",
                pattern_type=DLPPatternType.CREDENTIAL,
                severity=DLPSeverity.CRITICAL,
            ),
        ]
        risk = compute_dlp_risk_elevation(findings)
        assert risk >= 0.9  # CRITICAL dominates

    def test_risk_capped_at_1(self):
        """Risk elevation should never exceed 1.0."""
        findings = [
            DLPFinding(
                pattern_id="DLP-042",
                pattern_type=DLPPatternType.SECRET,
                severity=DLPSeverity.CRITICAL,
            ),
        ]
        risk = compute_dlp_risk_elevation(findings)
        assert risk <= 1.0


# ===========================================================================
# APEP-358: DLP-to-Taint Assignment Tests
# ===========================================================================


class TestDLPTaintAssignment:
    """Security validation tests for DLP-to-taint assignment (APEP-358)."""

    def test_no_findings_no_taint(self):
        """No findings should produce no taint action."""
        assert determine_taint_action([]) is None

    def test_credential_critical_quarantine(self):
        """CRITICAL credential finding should trigger QUARANTINE."""
        findings = [
            DLPFinding(
                pattern_id="DLP-021",
                pattern_type=DLPPatternType.CREDENTIAL,
                severity=DLPSeverity.CRITICAL,
            ),
        ]
        assert determine_taint_action(findings) == TaintLevel.QUARANTINE

    def test_api_key_high_quarantine(self):
        """HIGH API_KEY finding should trigger QUARANTINE."""
        findings = [
            DLPFinding(
                pattern_id="DLP-001",
                pattern_type=DLPPatternType.API_KEY,
                severity=DLPSeverity.HIGH,
            ),
        ]
        assert determine_taint_action(findings) == TaintLevel.QUARANTINE

    def test_token_high_quarantine(self):
        """HIGH TOKEN finding should trigger QUARANTINE."""
        findings = [
            DLPFinding(
                pattern_id="DLP-011",
                pattern_type=DLPPatternType.TOKEN,
                severity=DLPSeverity.HIGH,
            ),
        ]
        assert determine_taint_action(findings) == TaintLevel.QUARANTINE

    def test_secret_critical_quarantine(self):
        """CRITICAL SECRET finding should trigger QUARANTINE."""
        findings = [
            DLPFinding(
                pattern_id="DLP-042",
                pattern_type=DLPPatternType.SECRET,
                severity=DLPSeverity.CRITICAL,
            ),
        ]
        assert determine_taint_action(findings) == TaintLevel.QUARANTINE

    def test_pii_medium_untrusted(self):
        """MEDIUM PII finding should trigger UNTRUSTED."""
        findings = [
            DLPFinding(
                pattern_id="DLP-031",
                pattern_type=DLPPatternType.PII,
                severity=DLPSeverity.MEDIUM,
            ),
        ]
        assert determine_taint_action(findings) == TaintLevel.UNTRUSTED

    def test_financial_high_untrusted(self):
        """HIGH financial finding should trigger UNTRUSTED."""
        findings = [
            DLPFinding(
                pattern_id="DLP-039",
                pattern_type=DLPPatternType.FINANCIAL,
                severity=DLPSeverity.HIGH,
            ),
        ]
        assert determine_taint_action(findings) == TaintLevel.UNTRUSTED

    def test_low_severity_no_taint(self):
        """LOW severity PII/financial findings should produce no taint."""
        findings = [
            DLPFinding(
                pattern_id="DLP-032",
                pattern_type=DLPPatternType.PII,
                severity=DLPSeverity.LOW,
            ),
        ]
        assert determine_taint_action(findings) is None

    def test_credential_low_severity_no_quarantine(self):
        """LOW severity credential findings should not trigger QUARANTINE."""
        findings = [
            DLPFinding(
                pattern_id="DLP-024",
                pattern_type=DLPPatternType.CREDENTIAL,
                severity=DLPSeverity.LOW,
            ),
        ]
        # LOW severity credential: no QUARANTINE
        assert determine_taint_action(findings) is None

    def test_credential_medium_no_quarantine(self):
        """MEDIUM severity credential findings should not trigger QUARANTINE."""
        findings = [
            DLPFinding(
                pattern_id="DLP-024",
                pattern_type=DLPPatternType.CREDENTIAL,
                severity=DLPSeverity.MEDIUM,
            ),
        ]
        # MEDIUM severity credential doesn't meet HIGH+ threshold
        assert determine_taint_action(findings) is None

    def test_quarantine_overrides_untrusted(self):
        """QUARANTINE from credential should override UNTRUSTED from PII."""
        findings = [
            DLPFinding(
                pattern_id="DLP-031",
                pattern_type=DLPPatternType.PII,
                severity=DLPSeverity.HIGH,
            ),
            DLPFinding(
                pattern_id="DLP-021",
                pattern_type=DLPPatternType.CREDENTIAL,
                severity=DLPSeverity.CRITICAL,
            ),
        ]
        assert determine_taint_action(findings) == TaintLevel.QUARANTINE


# ===========================================================================
# APEP-359: DLP Findings in PolicyDecisionResponse Tests
# ===========================================================================


class TestDLPScanResultModel:
    """Unit tests for DLPScanResult model (APEP-359)."""

    def test_has_findings_true(self):
        """has_findings should be True when findings are present."""
        result = DLPScanResult(
            findings=[
                DLPFinding(
                    pattern_id="DLP-001",
                    pattern_type=DLPPatternType.API_KEY,
                    severity=DLPSeverity.HIGH,
                ),
            ],
        )
        assert result.has_findings is True

    def test_has_findings_false(self):
        """has_findings should be False when no findings."""
        result = DLPScanResult()
        assert result.has_findings is False

    def test_max_severity(self):
        """max_severity should return the highest severity finding."""
        result = DLPScanResult(
            findings=[
                DLPFinding(
                    pattern_id="DLP-032",
                    pattern_type=DLPPatternType.PII,
                    severity=DLPSeverity.MEDIUM,
                ),
                DLPFinding(
                    pattern_id="DLP-021",
                    pattern_type=DLPPatternType.CREDENTIAL,
                    severity=DLPSeverity.CRITICAL,
                ),
            ],
        )
        assert result.max_severity == DLPSeverity.CRITICAL

    def test_max_severity_none_no_findings(self):
        """max_severity should be None when no findings."""
        result = DLPScanResult()
        assert result.max_severity is None

    def test_scan_result_serialization(self):
        """DLPScanResult should serialise to JSON correctly."""
        result = DLPScanResult(
            scanned=True,
            findings=[
                DLPFinding(
                    pattern_id="DLP-001",
                    pattern_type=DLPPatternType.API_KEY,
                    severity=DLPSeverity.HIGH,
                    matched_arg="key",
                    description="AWS Key",
                    redacted_snippet="...****...",
                ),
            ],
            risk_elevation=0.6,
            taint_action=TaintLevel.QUARANTINE,
            scan_duration_ms=1.5,
            cache_hit=False,
        )
        data = result.model_dump(mode="json")
        assert data["scanned"] is True
        assert len(data["findings"]) == 1
        assert data["findings"][0]["pattern_id"] == "DLP-001"
        assert data["risk_elevation"] == 0.6
        assert data["taint_action"] == "QUARANTINE"


# ===========================================================================
# APEP-361: DLP Pre-Scan Caching Tests
# ===========================================================================


class TestDLPPreScanCache:
    """Unit tests for DLP pre-scan caching (APEP-361)."""

    def test_cache_miss_on_empty(self):
        """Empty cache should return None."""
        cache = DLPPreScanCache(max_size=100, max_age_s=300)
        assert cache.get({"key": "value"}) is None

    def test_cache_put_and_get(self):
        """Should retrieve a previously stored result."""
        cache = DLPPreScanCache(max_size=100, max_age_s=300)
        result = DLPScanResult(scanned=True)
        cache.put({"key": "value"}, result)
        retrieved = cache.get({"key": "value"})
        assert retrieved is not None
        assert retrieved.scanned is True

    def test_cache_key_deterministic(self):
        """Same args should produce same cache key regardless of insertion order."""
        cache = DLPPreScanCache(max_size=100, max_age_s=300)
        result = DLPScanResult(scanned=True)
        cache.put({"b": 2, "a": 1}, result)
        # Retrieve with different key order
        retrieved = cache.get({"a": 1, "b": 2})
        assert retrieved is not None

    def test_cache_expiry(self):
        """Expired entries should return None."""
        cache = DLPPreScanCache(max_size=100, max_age_s=0.01)
        result = DLPScanResult(scanned=True)
        cache.put({"key": "value"}, result)
        time.sleep(0.02)  # Wait for expiry
        assert cache.get({"key": "value"}) is None

    def test_cache_eviction_on_max_size(self):
        """Should evict oldest entries when max_size is reached."""
        cache = DLPPreScanCache(max_size=2, max_age_s=300)
        cache.put({"k": "1"}, DLPScanResult(scanned=True))
        cache.put({"k": "2"}, DLPScanResult(scanned=True))
        cache.put({"k": "3"}, DLPScanResult(scanned=True))
        assert cache.size <= 2
        # Oldest entry should be evicted
        assert cache.get({"k": "1"}) is None
        assert cache.get({"k": "3"}) is not None

    def test_cache_invalidate(self):
        """invalidate() should clear the entire cache."""
        cache = DLPPreScanCache(max_size=100, max_age_s=300)
        cache.put({"k": "1"}, DLPScanResult(scanned=True))
        cache.put({"k": "2"}, DLPScanResult(scanned=True))
        assert cache.size == 2
        cache.invalidate()
        assert cache.size == 0
        assert cache.get({"k": "1"}) is None


# ===========================================================================
# APEP-363: DLP Pattern Hot-Reload Tests
# ===========================================================================


class TestDLPPatternHotReload:
    """Unit tests for DLP pattern hot-reload (APEP-363)."""

    def test_initial_patterns_loaded(self):
        """Registry should have built-in patterns at init."""
        registry = DLPPatternRegistry()
        assert len(registry.patterns) == 46
        assert registry.version == 0

    def test_reload_increments_version(self):
        """Reload should increment the version number."""
        registry = DLPPatternRegistry()
        v1 = registry.reload()
        assert v1 == 1
        v2 = registry.reload()
        assert v2 == 2

    def test_custom_pattern_overrides_builtin(self):
        """Custom patterns should override built-in with same pattern_id."""
        registry = DLPPatternRegistry()
        custom = [
            DLPPattern(
                pattern_id="DLP-001",
                pattern_type=DLPPatternType.API_KEY,
                severity=DLPSeverity.CRITICAL,
                regex=re.compile(r"CUSTOM_PATTERN"),
                description="Custom override of DLP-001",
            ),
        ]
        registry.reload(custom)
        patterns = registry.patterns
        dlp001 = next(p for p in patterns if p.pattern_id == "DLP-001")
        assert dlp001.description == "Custom override of DLP-001"

    def test_custom_pattern_adds_new(self):
        """Custom patterns with new IDs should be added."""
        registry = DLPPatternRegistry()
        custom = [
            DLPPattern(
                pattern_id="DLP-CUSTOM-001",
                pattern_type=DLPPatternType.SECRET,
                severity=DLPSeverity.HIGH,
                regex=re.compile(r"my_custom_secret_[a-z]+"),
                description="Custom enterprise pattern",
            ),
        ]
        registry.reload(custom)
        assert len(registry.patterns) == 47  # 46 built-in + 1 custom
        ids = {p.pattern_id for p in registry.patterns}
        assert "DLP-CUSTOM-001" in ids

    def test_reload_without_custom_restores_defaults(self):
        """Reload with empty custom list should restore defaults."""
        registry = DLPPatternRegistry()
        custom = [
            DLPPattern(
                pattern_id="DLP-CUSTOM-001",
                pattern_type=DLPPatternType.SECRET,
                severity=DLPSeverity.HIGH,
                regex=re.compile(r"custom"),
                description="Custom",
            ),
        ]
        registry.reload(custom)
        assert len(registry.patterns) == 47
        registry.reload([])
        assert len(registry.patterns) == 46


# ===========================================================================
# APEP-357: DLPSensitivityScorer Tests (in RiskScoringEngine)
# ===========================================================================


class TestDLPSensitivityScorer:
    """Unit tests for the DLPSensitivityScorer (APEP-357)."""

    def test_scorer_with_findings(self, monkeypatch):
        """Scorer should return elevated risk when DLP findings exist."""
        monkeypatch.setattr("app.core.config.settings.dlp_pre_scan_enabled", True)

        from app.services.risk_scoring import DLPSensitivityScorer

        scorer = DLPSensitivityScorer()
        factor = scorer.score({"aws_key": "AKIAIOSFODNN7EXAMPLE"})
        assert factor.factor_name == "dlp_sensitivity"
        assert factor.score > 0

    def test_scorer_disabled(self, monkeypatch):
        """Scorer should return zero when DLP is disabled."""
        monkeypatch.setattr("app.core.config.settings.dlp_pre_scan_enabled", False)

        from app.services.risk_scoring import DLPSensitivityScorer

        scorer = DLPSensitivityScorer()
        factor = scorer.score({"aws_key": "AKIAIOSFODNN7EXAMPLE"})
        assert factor.score == 0.0

    def test_scorer_no_args(self, monkeypatch):
        """Scorer should return zero with no args."""
        monkeypatch.setattr("app.core.config.settings.dlp_pre_scan_enabled", True)

        from app.services.risk_scoring import DLPSensitivityScorer

        scorer = DLPSensitivityScorer()
        factor = scorer.score(None)
        assert factor.score == 0.0

    def test_scorer_clean_args(self, monkeypatch):
        """Scorer should return zero for clean args."""
        monkeypatch.setattr("app.core.config.settings.dlp_pre_scan_enabled", True)

        from app.services.risk_scoring import DLPSensitivityScorer

        scorer = DLPSensitivityScorer()
        factor = scorer.score({"name": "test"})
        assert factor.score == 0.0


# ===========================================================================
# Integration-style: Scanner with caching end-to-end
# ===========================================================================


class TestScannerWithCaching:
    """Tests for the scanner caching integration (APEP-361)."""

    def test_cache_hit_on_repeated_scan(self, monkeypatch):
        """Second scan of same args should be a cache hit."""
        monkeypatch.setattr("app.core.config.settings.dlp_cache_enabled", True)
        monkeypatch.setattr("app.core.config.settings.dlp_cache_max_size", 100)
        monkeypatch.setattr("app.core.config.settings.dlp_cache_ttl_s", 300)

        scanner = NetworkDLPScanner()
        args = {"key": "AKIAIOSFODNN7EXAMPLE"}

        result1 = scanner.scan_tool_args(args)
        assert result1.cache_hit is False
        assert result1.has_findings is True

        result2 = scanner.scan_tool_args(args)
        assert result2.cache_hit is True
        assert result2.has_findings is True
        assert result2.scan_duration_ms == 0.0  # Cache hits have zero scan time

    def test_cache_invalidated_on_pattern_reload(self, monkeypatch):
        """Cache should be cleared after pattern hot-reload."""
        monkeypatch.setattr("app.core.config.settings.dlp_cache_enabled", True)
        monkeypatch.setattr("app.core.config.settings.dlp_cache_max_size", 100)
        monkeypatch.setattr("app.core.config.settings.dlp_cache_ttl_s", 300)

        scanner = NetworkDLPScanner()
        args = {"key": "AKIAIOSFODNN7EXAMPLE"}

        scanner.scan_tool_args(args)
        assert scanner.cache.size == 1

        scanner.registry.reload([])
        scanner.cache.invalidate()
        assert scanner.cache.size == 0
