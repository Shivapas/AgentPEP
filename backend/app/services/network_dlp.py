"""Network DLP Scanner — Sprint 44/45 (APEP-348, APEP-356..363).

Sprint 44 (APEP-348): Core NetworkDLPScanner service with 46 DLP patterns
covering API keys, tokens, credentials, PII, and financial data.

Sprint 45:
  APEP-356: DLPPreScanStage — pre-evaluation hook in PolicyEvaluator pipeline.
  APEP-357: DLP-to-risk mapping — auto-elevate risk score on DLP hits.
  APEP-358: DLP-to-taint assignment — auto-taint QUARANTINE on credential detection.
  APEP-359: DLP findings attached to PolicyDecisionResponse.
  APEP-360: Prometheus metrics for DLP scan operations.
  APEP-361: DLP pre-scan result caching (SHA-256 keyed).
  APEP-363: DLP pattern hot-reload from MongoDB.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import threading
from dataclasses import dataclass
from typing import Any

from app.core.config import settings
from app.core.structured_logging import get_logger
from app.models.policy import (
    DLPFinding,
    DLPPatternType,
    DLPScanResult,
    DLPSeverity,
    TaintLevel,
)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# DLP Pattern definitions (Sprint 44 — APEP-348)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DLPPattern:
    """A single DLP detection pattern."""

    pattern_id: str
    pattern_type: DLPPatternType
    severity: DLPSeverity
    regex: re.Pattern[str]
    description: str


# 46 DLP patterns covering API keys, tokens, credentials, PII, and financial data.
_DLP_PATTERNS: list[DLPPattern] = [
    # ── API Keys ──────────────────────────────────────────────────────
    DLPPattern("DLP-001", DLPPatternType.API_KEY, DLPSeverity.CRITICAL,
               re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
    DLPPattern("DLP-002", DLPPatternType.API_KEY, DLPSeverity.CRITICAL,
               re.compile(r"ABIA[0-9A-Z]{16}"), "AWS STS Access Key"),
    DLPPattern("DLP-003", DLPPatternType.API_KEY, DLPSeverity.CRITICAL,
               re.compile(r"ACCA[0-9A-Z]{16}"), "AWS CloudFront Access Key"),
    DLPPattern("DLP-004", DLPPatternType.API_KEY, DLPSeverity.HIGH,
               re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API Key"),
    DLPPattern("DLP-005", DLPPatternType.API_KEY, DLPSeverity.HIGH,
               re.compile(r"sk-[A-Za-z0-9]{32,}"), "OpenAI / Stripe Secret Key"),
    DLPPattern("DLP-006", DLPPatternType.API_KEY, DLPSeverity.HIGH,
               re.compile(r"sk-ant-[A-Za-z0-9\-]{32,}"), "Anthropic API Key"),
    DLPPattern("DLP-007", DLPPatternType.API_KEY, DLPSeverity.HIGH,
               re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
               "SendGrid API Key"),
    DLPPattern("DLP-008", DLPPatternType.API_KEY, DLPSeverity.HIGH,
               re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "Slack Token"),
    DLPPattern("DLP-009", DLPPatternType.API_KEY, DLPSeverity.MEDIUM,
               re.compile(r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}"), "Square API Key"),
    DLPPattern("DLP-010", DLPPatternType.API_KEY, DLPSeverity.HIGH,
               re.compile(r"rk_live_[0-9A-Za-z]{24,}"), "Stripe Restricted Key"),

    # ── Tokens ────────────────────────────────────────────────────────
    DLPPattern("DLP-011", DLPPatternType.TOKEN, DLPSeverity.CRITICAL,
               re.compile(r"ghp_[A-Za-z0-9]{36}"), "GitHub Personal Access Token"),
    DLPPattern("DLP-012", DLPPatternType.TOKEN, DLPSeverity.CRITICAL,
               re.compile(r"gho_[A-Za-z0-9]{36}"), "GitHub OAuth Token"),
    DLPPattern("DLP-013", DLPPatternType.TOKEN, DLPSeverity.CRITICAL,
               re.compile(r"ghu_[A-Za-z0-9]{36}"), "GitHub User-to-Server Token"),
    DLPPattern("DLP-014", DLPPatternType.TOKEN, DLPSeverity.CRITICAL,
               re.compile(r"ghs_[A-Za-z0-9]{36}"), "GitHub Server-to-Server Token"),
    DLPPattern("DLP-015", DLPPatternType.TOKEN, DLPSeverity.HIGH,
               re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), "GitLab Personal Access Token"),
    DLPPattern("DLP-016", DLPPatternType.TOKEN, DLPSeverity.HIGH,
               re.compile(r"npm_[A-Za-z0-9]{36}"), "npm Access Token"),
    DLPPattern("DLP-017", DLPPatternType.TOKEN, DLPSeverity.HIGH,
               re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}"),
               "PyPI API Token"),
    DLPPattern("DLP-018", DLPPatternType.TOKEN, DLPSeverity.HIGH,
               re.compile(r"dop_v1_[a-f0-9]{64}"), "DigitalOcean PAT"),
    DLPPattern("DLP-019", DLPPatternType.TOKEN, DLPSeverity.HIGH,
               re.compile(r"hf_[A-Za-z0-9]{34}"), "Hugging Face Token"),
    DLPPattern("DLP-020", DLPPatternType.TOKEN, DLPSeverity.MEDIUM,
               re.compile(r"v2/[A-Za-z0-9\-_]{32,}"), "Docker Registry Token"),

    # ── Credentials ───────────────────────────────────────────────────
    DLPPattern("DLP-021", DLPPatternType.CREDENTIAL, DLPSeverity.CRITICAL,
               re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
               "PEM Private Key"),
    DLPPattern("DLP-022", DLPPatternType.CREDENTIAL, DLPSeverity.CRITICAL,
               re.compile(r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----"),
               "EC Private Key"),
    DLPPattern("DLP-023", DLPPatternType.CREDENTIAL, DLPSeverity.CRITICAL,
               re.compile(r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----"),
               "PGP Private Key"),
    DLPPattern("DLP-024", DLPPatternType.CREDENTIAL, DLPSeverity.HIGH,
               re.compile(
                   r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}",
               ), "Password Assignment"),
    DLPPattern("DLP-025", DLPPatternType.CREDENTIAL, DLPSeverity.HIGH,
               re.compile(
                   r"(?i)(secret|auth_token|access_key|private_key)\s*[=:]\s*['\"]?[^\s'\"]{8,}",
               ), "Secret/Auth Token Assignment"),
    DLPPattern("DLP-026", DLPPatternType.CREDENTIAL, DLPSeverity.HIGH,
               re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
               "Bearer Token"),
    DLPPattern("DLP-027", DLPPatternType.CREDENTIAL, DLPSeverity.HIGH,
               re.compile(r"(?i)basic\s+[A-Za-z0-9+/]{20,}={0,2}"),
               "Basic Auth Credentials"),
    DLPPattern("DLP-028", DLPPatternType.CREDENTIAL, DLPSeverity.HIGH,
               re.compile(r"(?i)mysql://[^\s:]+:[^\s@]+@"), "MySQL Connection String"),
    DLPPattern("DLP-029", DLPPatternType.CREDENTIAL, DLPSeverity.HIGH,
               re.compile(r"(?i)postgres(ql)?://[^\s:]+:[^\s@]+@"),
               "PostgreSQL Connection String"),
    DLPPattern("DLP-030", DLPPatternType.CREDENTIAL, DLPSeverity.HIGH,
               re.compile(r"(?i)mongodb(\+srv)?://[^\s:]+:[^\s@]+@"),
               "MongoDB Connection String"),

    # ── PII ───────────────────────────────────────────────────────────
    DLPPattern("DLP-031", DLPPatternType.PII, DLPSeverity.HIGH,
               re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "US Social Security Number"),
    DLPPattern("DLP-032", DLPPatternType.PII, DLPSeverity.MEDIUM,
               re.compile(
                   r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
               ), "Email Address"),
    DLPPattern("DLP-033", DLPPatternType.PII, DLPSeverity.MEDIUM,
               re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"),
               "US Phone Number"),
    DLPPattern("DLP-034", DLPPatternType.PII, DLPSeverity.HIGH,
               re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b"),
               "IBAN"),
    DLPPattern("DLP-035", DLPPatternType.PII, DLPSeverity.MEDIUM,
               re.compile(r"\b[A-Z]\d{7}\b"), "Passport Number (US-style)"),
    DLPPattern("DLP-036", DLPPatternType.PII, DLPSeverity.HIGH,
               re.compile(
                   r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
               ), "Credit Card Number"),
    DLPPattern("DLP-037", DLPPatternType.PII, DLPSeverity.MEDIUM,
               re.compile(r"(?i)\bdate[_\s]*of[_\s]*birth\s*[=:]\s*\d{4}[-/]\d{2}[-/]\d{2}"),
               "Date of Birth"),
    DLPPattern("DLP-038", DLPPatternType.PII, DLPSeverity.MEDIUM,
               re.compile(r"(?i)\bdriver[_\s]*licen[cs]e\s*[=:#]\s*[A-Z0-9\-]{6,}"),
               "Driver's License Number"),

    # ── Financial ─────────────────────────────────────────────────────
    DLPPattern("DLP-039", DLPPatternType.FINANCIAL, DLPSeverity.HIGH,
               re.compile(
                   r"(?i)(account_number|routing_number|swift_code|bank_account)\s*[=:]\s*[^\s]{6,}",
               ), "Bank Account Details"),
    DLPPattern("DLP-040", DLPPatternType.FINANCIAL, DLPSeverity.MEDIUM,
               re.compile(
                   r"(?i)(amount|balance|transaction|payment)\s*[=:]\s*\$?\d{4,}",
               ), "Financial Transaction Data"),
    DLPPattern("DLP-041", DLPPatternType.FINANCIAL, DLPSeverity.HIGH,
               re.compile(r"\b[0-9]{9}\b"), "US Routing Number (9-digit)"),

    # ── Secrets / Certificates ────────────────────────────────────────
    DLPPattern("DLP-042", DLPPatternType.SECRET, DLPSeverity.CRITICAL,
               re.compile(r"(?i)(aws_secret_access_key|aws_session_token)\s*[=:]\s*[^\s]{20,}"),
               "AWS Secret Access Key"),
    DLPPattern("DLP-043", DLPPatternType.SECRET, DLPSeverity.HIGH,
               re.compile(r"(?i)twilio[_\s]*auth[_\s]*token\s*[=:]\s*[a-f0-9]{32}"),
               "Twilio Auth Token"),
    DLPPattern("DLP-044", DLPPatternType.SECRET, DLPSeverity.HIGH,
               re.compile(r"(?i)github[_\s]*secret\s*[=:]\s*[^\s]{20,}"),
               "GitHub Webhook Secret"),
    DLPPattern("DLP-045", DLPPatternType.CERTIFICATE, DLPSeverity.HIGH,
               re.compile(r"-----BEGIN\s+CERTIFICATE-----"),
               "X.509 Certificate"),
    DLPPattern("DLP-046", DLPPatternType.SECRET, DLPSeverity.HIGH,
               re.compile(r"(?i)(jwt_secret|signing_key|encryption_key)\s*[=:]\s*[^\s]{16,}"),
               "Application Secret Key"),
]


# ---------------------------------------------------------------------------
# DLP-to-Risk Mapping (Sprint 45 — APEP-357)
# ---------------------------------------------------------------------------

# Severity-based risk elevation for DLP findings.
_SEVERITY_RISK_MAP: dict[DLPSeverity, float] = {
    DLPSeverity.LOW: 0.1,
    DLPSeverity.MEDIUM: 0.3,
    DLPSeverity.HIGH: 0.6,
    DLPSeverity.CRITICAL: 0.9,
}

# Pattern-type-based risk multiplier — credentials and secrets are riskier.
_PATTERN_TYPE_RISK_MULTIPLIER: dict[DLPPatternType, float] = {
    DLPPatternType.API_KEY: 1.0,
    DLPPatternType.TOKEN: 1.0,
    DLPPatternType.CREDENTIAL: 1.1,
    DLPPatternType.PII: 0.8,
    DLPPatternType.FINANCIAL: 0.9,
    DLPPatternType.SECRET: 1.1,
    DLPPatternType.CERTIFICATE: 0.7,
}

# Pattern types that trigger automatic QUARANTINE taint (APEP-358).
_CREDENTIAL_TYPES: frozenset[DLPPatternType] = frozenset({
    DLPPatternType.API_KEY,
    DLPPatternType.TOKEN,
    DLPPatternType.CREDENTIAL,
    DLPPatternType.SECRET,
})


def compute_dlp_risk_elevation(findings: list[DLPFinding]) -> float:
    """Compute risk score elevation from DLP findings (APEP-357).

    Takes the maximum severity-based score across all findings,
    with a pattern-type multiplier applied.  The final score is
    clamped to [0, 1].
    """
    if not findings:
        return 0.0

    max_risk = 0.0
    for f in findings:
        base = _SEVERITY_RISK_MAP.get(f.severity, 0.0)
        multiplier = _PATTERN_TYPE_RISK_MULTIPLIER.get(f.pattern_type, 1.0)
        max_risk = max(max_risk, base * multiplier)

    return min(round(max_risk, 4), 1.0)


def determine_taint_action(findings: list[DLPFinding]) -> TaintLevel | None:
    """Determine taint level from DLP findings (APEP-358).

    Returns QUARANTINE if any credential/secret pattern is found at HIGH+
    severity, UNTRUSTED for PII/financial findings, or None if no taint
    action is needed.
    """
    if not findings:
        return None

    has_credential = False
    has_sensitive = False

    for f in findings:
        if f.pattern_type in _CREDENTIAL_TYPES:
            if f.severity in (DLPSeverity.HIGH, DLPSeverity.CRITICAL):
                has_credential = True
        if f.pattern_type in (DLPPatternType.PII, DLPPatternType.FINANCIAL):
            if f.severity in (DLPSeverity.MEDIUM, DLPSeverity.HIGH, DLPSeverity.CRITICAL):
                has_sensitive = True

    if has_credential:
        return TaintLevel.QUARANTINE
    if has_sensitive:
        return TaintLevel.UNTRUSTED
    return None


# ---------------------------------------------------------------------------
# DLP Pre-Scan Cache (Sprint 45 — APEP-361)
# ---------------------------------------------------------------------------


class DLPPreScanCache:
    """In-memory LRU cache for DLP pre-scan results (APEP-361).

    Keys are SHA-256 hashes of canonicalised tool arguments.  Results are
    evicted after ``max_age_s`` seconds or when the cache exceeds
    ``max_size`` entries (LRU eviction).

    Thread-safe for concurrent reads/writes.
    """

    def __init__(
        self,
        max_size: int = 10_000,
        max_age_s: float = 300.0,
    ) -> None:
        self._max_size = max_size
        self._max_age_s = max_age_s
        self._cache: dict[str, tuple[float, DLPScanResult]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _make_key(tool_args: dict[str, Any]) -> str:
        """Compute SHA-256 hash of canonicalised tool args."""
        canonical = json.dumps(tool_args, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def get(self, tool_args: dict[str, Any]) -> DLPScanResult | None:
        """Retrieve a cached scan result, or None on miss/expiry."""
        key = self._make_key(tool_args)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            ts, result = entry
            if (time.monotonic() - ts) > self._max_age_s:
                del self._cache[key]
                return None
            return result

    def put(self, tool_args: dict[str, Any], result: DLPScanResult) -> None:
        """Store a scan result in the cache."""
        if self._max_size <= 0:
            return
        key = self._make_key(tool_args)
        with self._lock:
            # Evict oldest entries if over capacity
            while len(self._cache) >= self._max_size and self._cache:
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            self._cache[key] = (time.monotonic(), result)

    def invalidate(self) -> None:
        """Clear the entire cache (used on pattern hot-reload)."""
        with self._lock:
            self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


# ---------------------------------------------------------------------------
# DLP Pattern Hot-Reload (Sprint 45 — APEP-363)
# ---------------------------------------------------------------------------


class DLPPatternRegistry:
    """Registry of DLP patterns with hot-reload support (APEP-363).

    Patterns are loaded from the built-in ``_DLP_PATTERNS`` list at init.
    ``reload_from_db()`` can be called to merge additional patterns from
    MongoDB at runtime without restarting the service.

    Thread-safe: reads and writes are protected by a lock.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._patterns: list[DLPPattern] = list(_DLP_PATTERNS)
        self._custom_patterns: list[DLPPattern] = []
        self._version: int = 0

    @property
    def patterns(self) -> list[DLPPattern]:
        with self._lock:
            return list(self._patterns)

    @property
    def version(self) -> int:
        return self._version

    def reload(self, custom_patterns: list[DLPPattern] | None = None) -> int:
        """Hot-reload patterns: merge built-in + custom patterns.

        Returns the new version number.
        """
        with self._lock:
            self._custom_patterns = list(custom_patterns) if custom_patterns else []
            # Merge: built-in first, then custom (custom can override by pattern_id)
            seen_ids: set[str] = set()
            merged: list[DLPPattern] = []
            for p in self._custom_patterns:
                if p.pattern_id not in seen_ids:
                    merged.append(p)
                    seen_ids.add(p.pattern_id)
            for p in _DLP_PATTERNS:
                if p.pattern_id not in seen_ids:
                    merged.append(p)
                    seen_ids.add(p.pattern_id)
            self._patterns = merged
            self._version += 1
            return self._version

    async def reload_from_db(self) -> int:
        """Load custom DLP patterns from MongoDB and hot-reload (APEP-363).

        Custom patterns in ``dlp_patterns`` collection override built-in
        patterns with the same ``pattern_id``.
        """
        from app.db import mongodb as db_module

        db = db_module.get_database()
        custom: list[DLPPattern] = []
        cursor = db["dlp_patterns"].find({"enabled": True})
        async for doc in cursor:
            try:
                custom.append(DLPPattern(
                    pattern_id=doc["pattern_id"],
                    pattern_type=DLPPatternType(doc["pattern_type"]),
                    severity=DLPSeverity(doc["severity"]),
                    regex=re.compile(doc["regex_pattern"]),
                    description=doc.get("description", ""),
                ))
            except (KeyError, ValueError, re.error) as exc:
                logger.warning(
                    "Skipping invalid custom DLP pattern %s: %s",
                    doc.get("pattern_id", "?"),
                    exc,
                )

        new_version = self.reload(custom)
        logger.info(
            "DLP patterns hot-reloaded: version=%d total=%d custom=%d",
            new_version,
            len(self._patterns),
            len(custom),
        )
        return new_version


# ---------------------------------------------------------------------------
# NetworkDLPScanner (Sprint 44 — APEP-348, Sprint 45 — APEP-356)
# ---------------------------------------------------------------------------


class NetworkDLPScanner:
    """Scans tool arguments for sensitive data using DLP patterns.

    Core capabilities:
      - Pattern matching against 46+ DLP signatures (APEP-348)
      - Risk elevation computation (APEP-357)
      - Taint action determination (APEP-358)
      - Result caching (APEP-361)
      - Pattern hot-reload (APEP-363)
    """

    def __init__(self) -> None:
        self.registry = DLPPatternRegistry()
        self.cache = DLPPreScanCache(
            max_size=settings.dlp_cache_max_size,
            max_age_s=settings.dlp_cache_ttl_s,
        )

    def scan_tool_args(self, tool_args: dict[str, Any]) -> DLPScanResult:
        """Scan tool arguments for DLP pattern matches.

        This is the primary entry point used by DLPPreScanStage in the
        PolicyEvaluator pipeline.

        Returns a DLPScanResult with findings, risk elevation, and taint action.
        """
        if not tool_args:
            return DLPScanResult(scanned=True)

        # Check cache first (APEP-361)
        if settings.dlp_cache_enabled:
            cached = self.cache.get(tool_args)
            if cached is not None:
                return DLPScanResult(
                    scanned=cached.scanned,
                    findings=cached.findings,
                    risk_elevation=cached.risk_elevation,
                    taint_action=cached.taint_action,
                    scan_duration_ms=0.0,
                    cache_hit=True,
                )

        start = time.monotonic()
        flattened = _flatten_args_to_str(tool_args)
        findings = self._match_patterns(flattened, tool_args)

        risk_elevation = compute_dlp_risk_elevation(findings)
        taint_action = determine_taint_action(findings)
        scan_duration_ms = (time.monotonic() - start) * 1000

        result = DLPScanResult(
            scanned=True,
            findings=findings,
            risk_elevation=risk_elevation,
            taint_action=taint_action,
            scan_duration_ms=round(scan_duration_ms, 3),
            cache_hit=False,
        )

        # Store in cache (APEP-361)
        if settings.dlp_cache_enabled:
            self.cache.put(tool_args, result)

        return result

    def _match_patterns(
        self,
        flattened: str,
        tool_args: dict[str, Any],
    ) -> list[DLPFinding]:
        """Match all DLP patterns against the flattened tool args string."""
        findings: list[DLPFinding] = []
        patterns = self.registry.patterns

        for pattern in patterns:
            match = pattern.regex.search(flattened)
            if match:
                # Find which arg key contained the match
                matched_arg = _find_matching_arg(tool_args, pattern.regex)
                # Create redacted snippet (show context, redact the actual secret)
                snippet = _redact_match(flattened, match)

                findings.append(DLPFinding(
                    pattern_id=pattern.pattern_id,
                    pattern_type=pattern.pattern_type,
                    severity=pattern.severity,
                    matched_arg=matched_arg,
                    description=pattern.description,
                    redacted_snippet=snippet,
                ))

        return findings

    async def reload_patterns(self) -> int:
        """Hot-reload DLP patterns from MongoDB (APEP-363).

        Invalidates the scan cache after reload since patterns may have changed.
        """
        version = await self.registry.reload_from_db()
        self.cache.invalidate()
        return version


# ---------------------------------------------------------------------------
# DLP-to-Taint Security Guard (Sprint 45 — APEP-358.c)
# ---------------------------------------------------------------------------


def apply_dlp_taint(
    session_id: str,
    agent_id: str,
    scan_result: DLPScanResult,
) -> list[str]:
    """Apply taint labels based on DLP scan findings (APEP-358).

    When DLP detects credential patterns, creates a QUARANTINE taint node
    in the session graph.  For PII/financial findings, assigns UNTRUSTED.

    Returns the list of taint flags applied (for inclusion in the response).

    This function is a security guard: it validates that the scan result
    actually warrants tainting before modifying the session graph.
    """
    from app.services.taint_graph import session_graph_manager

    taint_flags: list[str] = []

    if not scan_result.has_findings or scan_result.taint_action is None:
        return taint_flags

    # Validate taint action is legitimate based on findings
    credential_findings = [
        f for f in scan_result.findings
        if f.pattern_type in _CREDENTIAL_TYPES
        and f.severity in (DLPSeverity.HIGH, DLPSeverity.CRITICAL)
    ]
    pii_financial_findings = [
        f for f in scan_result.findings
        if f.pattern_type in (DLPPatternType.PII, DLPPatternType.FINANCIAL)
        and f.severity in (DLPSeverity.MEDIUM, DLPSeverity.HIGH, DLPSeverity.CRITICAL)
    ]

    if scan_result.taint_action == TaintLevel.QUARANTINE and not credential_findings:
        logger.warning(
            "dlp_taint_guard_rejected",
            session_id=session_id,
            detail="QUARANTINE requested but no qualifying credential findings",
        )
        return taint_flags

    if scan_result.taint_action == TaintLevel.UNTRUSTED and not pii_financial_findings:
        logger.warning(
            "dlp_taint_guard_rejected",
            session_id=session_id,
            detail="UNTRUSTED requested but no qualifying PII/financial findings",
        )
        return taint_flags

    # Apply taint to the session graph
    graph = session_graph_manager.get_session(session_id)
    if graph is None:
        # Create a session graph if one doesn't exist
        from app.models.policy import TaintSource

        graph = session_graph_manager.create_session(session_id)
        node = graph.add_node(
            source=TaintSource.TOOL_OUTPUT,
            taint_level=scan_result.taint_action,
            agent_id=agent_id,
        )
        taint_flags.append(scan_result.taint_action.value)
        logger.info(
            "dlp_taint_applied",
            session_id=session_id,
            agent_id=agent_id,
            taint_level=scan_result.taint_action.value,
            node_id=str(node.node_id),
            finding_count=len(scan_result.findings),
        )
    else:
        from app.models.policy import TaintSource

        node = graph.add_node(
            source=TaintSource.TOOL_OUTPUT,
            taint_level=scan_result.taint_action,
            agent_id=agent_id,
        )
        taint_flags.append(scan_result.taint_action.value)
        logger.info(
            "dlp_taint_applied",
            session_id=session_id,
            agent_id=agent_id,
            taint_level=scan_result.taint_action.value,
            node_id=str(node.node_id),
            finding_count=len(scan_result.findings),
        )

    return taint_flags


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _flatten_args_to_str(args: dict[str, Any]) -> str:
    """Recursively flatten argument dict values to a single string."""
    parts: list[str] = []
    for key, val in args.items():
        parts.append(str(key))
        if isinstance(val, dict):
            parts.append(_flatten_args_to_str(val))
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    parts.append(_flatten_args_to_str(item))
                else:
                    parts.append(str(item))
        else:
            parts.append(str(val))
    return " ".join(parts)


def _find_matching_arg(args: dict[str, Any], pattern: re.Pattern[str]) -> str:
    """Find the top-level arg key that contains a pattern match."""
    for key, val in args.items():
        val_str = json.dumps(val, default=str) if not isinstance(val, str) else val
        if pattern.search(val_str):
            return key
    return ""


def _redact_match(text: str, match: re.Match[str]) -> str:
    """Create a redacted snippet around a match (no raw secrets)."""
    start = max(0, match.start() - 10)
    end = min(len(text), match.end() + 10)
    prefix = text[start:match.start()]
    suffix = text[match.end():end]
    redacted = "*" * min(len(match.group()), 8)
    return f"...{prefix}{redacted}{suffix}..."


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

network_dlp_scanner = NetworkDLPScanner()
