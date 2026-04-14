"""URL Scanner — 11-layer URL analysis pipeline.

Sprint 44 — APEP-349/351: Orchestrates an 11-layer pipeline that scans URLs
through scheme validation, domain blocklist, SSRF guard, DLP pattern matching,
entropy analysis, per-domain rate limiting, and more.

The 11 layers are:
  1. Scheme validation (http/https only)
  2. URL parsing & normalisation
  3. Domain blocklist lookup (APEP-350)
  4. SSRF guard / private IP detection (APEP-353)
  5. DNS resolution validation
  6. DLP pattern matching on URL components (APEP-351)
  7. Entropy analysis on path & query (APEP-352)
  8. Per-domain rate limiting (APEP-354)
  9. Per-domain data budget (APEP-354)
 10. URL path traversal detection
 11. Credential-in-URL detection
"""

from __future__ import annotations

import logging
import re
import time
from urllib.parse import unquote, urlparse

from app.models.network_scan import (
    ScanFinding,
    ScanSeverity,
    URLScanLayerResult,
    URLScanResult,
)
from app.services.domain_blocklist import domain_blocklist
from app.services.domain_rate_limiter import domain_rate_limiter
from app.services.entropy_analyzer import entropy_analyzer
from app.services.network_dlp_scanner import network_dlp_scanner
from app.services.ssrf_guard import ssrf_guard

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Layer implementations
# ---------------------------------------------------------------------------

_ALLOWED_SCHEMES = {"http", "https"}

# Path traversal patterns
_PATH_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2e%2e[/\\%])", re.IGNORECASE)

# Credential-in-URL pattern (user:pass@host)
_CREDENTIAL_IN_URL_RE = re.compile(r"://[^/@]+:[^/@]+@")

# Suspicious file extensions in URL path
_SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".sh", ".vbs",
    ".msi", ".scr", ".pif", ".com", ".dll",
}


def _layer_scheme_validation(url: str, parsed: object) -> URLScanLayerResult:
    """Layer 1: Validate URL scheme."""
    start = time.monotonic()
    scheme = parsed.scheme.lower()  # type: ignore[attr-defined]
    findings: list[ScanFinding] = []
    passed = True

    if scheme not in _ALLOWED_SCHEMES:
        passed = False
        findings.append(
            ScanFinding(
                rule_id="URL-SCHEME-001",
                scanner="URLScanner",
                severity=ScanSeverity.HIGH,
                description=f"Disallowed URL scheme: {scheme}",
                matched_text=url[:200],
            )
        )

    elapsed = int((time.monotonic() - start) * 1_000_000)
    return URLScanLayerResult(layer_name="scheme_validation", passed=passed, findings=findings, latency_us=elapsed)


def _layer_url_parsing(url: str, parsed: object) -> URLScanLayerResult:
    """Layer 2: URL parsing & normalisation validation."""
    start = time.monotonic()
    findings: list[ScanFinding] = []
    passed = True

    hostname = parsed.hostname  # type: ignore[attr-defined]
    if not hostname:
        passed = False
        findings.append(
            ScanFinding(
                rule_id="URL-PARSE-001",
                scanner="URLScanner",
                severity=ScanSeverity.HIGH,
                description="URL has no valid hostname",
                matched_text=url[:200],
            )
        )

    # Check for double-encoding
    decoded = unquote(unquote(url))
    if decoded != unquote(url) and decoded != url:
        findings.append(
            ScanFinding(
                rule_id="URL-PARSE-002",
                scanner="URLScanner",
                severity=ScanSeverity.MEDIUM,
                description="Double URL-encoding detected (potential evasion)",
                matched_text=url[:200],
            )
        )

    elapsed = int((time.monotonic() - start) * 1_000_000)
    return URLScanLayerResult(layer_name="url_parsing", passed=passed, findings=findings, latency_us=elapsed)


def _layer_domain_blocklist(url: str, parsed: object) -> URLScanLayerResult:
    """Layer 3: Domain blocklist lookup."""
    start = time.monotonic()
    hostname = parsed.hostname or ""  # type: ignore[attr-defined]
    findings = domain_blocklist.scan(hostname)
    passed = len(findings) == 0
    elapsed = int((time.monotonic() - start) * 1_000_000)
    return URLScanLayerResult(layer_name="domain_blocklist", passed=passed, findings=findings, latency_us=elapsed)


def _layer_ssrf_guard(url: str, parsed: object) -> URLScanLayerResult:
    """Layer 4: SSRF guard / private IP detection."""
    start = time.monotonic()
    findings = ssrf_guard.scan(url)
    passed = len(findings) == 0
    elapsed = int((time.monotonic() - start) * 1_000_000)
    return URLScanLayerResult(layer_name="ssrf_guard", passed=passed, findings=findings, latency_us=elapsed)


def _layer_dns_validation(url: str, parsed: object) -> URLScanLayerResult:
    """Layer 5: DNS resolution validation (performed by SSRF guard)."""
    # This is handled as part of SSRF guard layer 4 which resolves DNS.
    # This layer checks for additional DNS-related indicators.
    start = time.monotonic()
    findings: list[ScanFinding] = []
    hostname = parsed.hostname or ""  # type: ignore[attr-defined]

    # Check for IP-address-as-hostname (potential SSRF bypass)
    if hostname and hostname.replace(".", "").isdigit():
        findings.append(
            ScanFinding(
                rule_id="URL-DNS-001",
                scanner="URLScanner",
                severity=ScanSeverity.LOW,
                description="URL uses raw IP address instead of domain name",
                matched_text=hostname,
            )
        )

    # Check for hex/octal IP encoding (e.g., 0x7f000001)
    if hostname and (hostname.startswith("0x") or hostname.startswith("0o")):
        findings.append(
            ScanFinding(
                rule_id="URL-DNS-002",
                scanner="URLScanner",
                severity=ScanSeverity.HIGH,
                description="URL uses hex/octal-encoded IP address (SSRF evasion)",
                matched_text=hostname,
            )
        )

    elapsed = int((time.monotonic() - start) * 1_000_000)
    return URLScanLayerResult(layer_name="dns_validation", passed=True, findings=findings, latency_us=elapsed)


def _layer_dlp_pattern_matching(url: str, parsed: object) -> URLScanLayerResult:
    """Layer 6: DLP pattern matching on URL components (APEP-351)."""
    start = time.monotonic()
    # Scan the full URL for DLP patterns
    findings = network_dlp_scanner.scan_url(url)

    # Also scan the decoded URL
    decoded = unquote(url)
    if decoded != url:
        decoded_findings = network_dlp_scanner.scan_url(decoded)
        existing_ids = {f.rule_id for f in findings}
        for f in decoded_findings:
            if f.rule_id not in existing_ids:
                findings.append(f)

    passed = len(findings) == 0
    elapsed = int((time.monotonic() - start) * 1_000_000)
    return URLScanLayerResult(layer_name="dlp_pattern_matching", passed=passed, findings=findings, latency_us=elapsed)


def _layer_entropy_analysis(url: str, parsed: object) -> URLScanLayerResult:
    """Layer 7: Entropy analysis on path and query parameters."""
    start = time.monotonic()
    findings: list[ScanFinding] = []

    # Analyse path and query for high-entropy tokens
    path = parsed.path or ""  # type: ignore[attr-defined]
    query = parsed.query or ""  # type: ignore[attr-defined]
    text_to_scan = f"{path} {query}"

    findings = entropy_analyzer.scan(text_to_scan)
    passed = len(findings) == 0
    elapsed = int((time.monotonic() - start) * 1_000_000)
    return URLScanLayerResult(layer_name="entropy_analysis", passed=passed, findings=findings, latency_us=elapsed)


def _layer_domain_rate_limit(url: str, parsed: object) -> URLScanLayerResult:
    """Layer 8: Per-domain request rate limiting."""
    start = time.monotonic()
    hostname = parsed.hostname or ""  # type: ignore[attr-defined]
    findings = domain_rate_limiter.scan(hostname)
    passed = len(findings) == 0
    elapsed = int((time.monotonic() - start) * 1_000_000)
    return URLScanLayerResult(layer_name="domain_rate_limit", passed=passed, findings=findings, latency_us=elapsed)


def _layer_data_budget(url: str, parsed: object) -> URLScanLayerResult:
    """Layer 9: Per-domain data budget (checked via rate limiter, data_bytes=0 for URL scan)."""
    # Data budget is tracked by the rate limiter when actual data transfer occurs.
    # During URL scanning, we just check the current state.
    start = time.monotonic()
    hostname = parsed.hostname or ""  # type: ignore[attr-defined]
    state = domain_rate_limiter.get_state(hostname)
    findings: list[ScanFinding] = []

    if state.exceeded and state.data_bytes_transferred >= state.data_budget_bytes:
        findings.append(
            ScanFinding(
                rule_id="DATABUDGET-001",
                scanner="DomainRateLimiter",
                severity=ScanSeverity.MEDIUM,
                description=f"Data budget exceeded for {hostname}",
                matched_text=hostname,
                metadata={
                    "data_bytes": state.data_bytes_transferred,
                    "data_budget_bytes": state.data_budget_bytes,
                },
            )
        )

    passed = len(findings) == 0
    elapsed = int((time.monotonic() - start) * 1_000_000)
    return URLScanLayerResult(layer_name="data_budget", passed=passed, findings=findings, latency_us=elapsed)


def _layer_path_traversal(url: str, parsed: object) -> URLScanLayerResult:
    """Layer 10: URL path traversal detection."""
    start = time.monotonic()
    findings: list[ScanFinding] = []
    path = parsed.path or ""  # type: ignore[attr-defined]
    decoded_path = unquote(path)

    if _PATH_TRAVERSAL_RE.search(decoded_path):
        findings.append(
            ScanFinding(
                rule_id="URL-TRAVERSAL-001",
                scanner="URLScanner",
                severity=ScanSeverity.HIGH,
                description="Path traversal pattern detected in URL",
                matched_text=decoded_path[:200],
                mitre_technique_id="T1083",
            )
        )

    # Check for suspicious file extensions
    path_lower = decoded_path.lower()
    for ext in _SUSPICIOUS_EXTENSIONS:
        if path_lower.endswith(ext):
            findings.append(
                ScanFinding(
                    rule_id="URL-TRAVERSAL-002",
                    scanner="URLScanner",
                    severity=ScanSeverity.MEDIUM,
                    description=f"Suspicious file extension in URL: {ext}",
                    matched_text=decoded_path[:200],
                )
            )
            break

    passed = len(findings) == 0
    elapsed = int((time.monotonic() - start) * 1_000_000)
    return URLScanLayerResult(layer_name="path_traversal", passed=passed, findings=findings, latency_us=elapsed)


def _layer_credential_in_url(url: str, parsed: object) -> URLScanLayerResult:
    """Layer 11: Credential-in-URL detection (user:pass@host)."""
    start = time.monotonic()
    findings: list[ScanFinding] = []

    if _CREDENTIAL_IN_URL_RE.search(url):
        findings.append(
            ScanFinding(
                rule_id="URL-CRED-001",
                scanner="URLScanner",
                severity=ScanSeverity.CRITICAL,
                description="Credentials embedded in URL (user:password@host)",
                matched_text=url[:200],
                mitre_technique_id="T1552.001",
            )
        )

    # Also check for password= or token= in query string
    query = parsed.query or ""  # type: ignore[attr-defined]
    query_lower = query.lower()
    for param in ("password=", "passwd=", "secret=", "token=", "api_key=", "apikey="):
        if param in query_lower:
            findings.append(
                ScanFinding(
                    rule_id="URL-CRED-002",
                    scanner="URLScanner",
                    severity=ScanSeverity.HIGH,
                    description=f"Sensitive parameter in URL query string: {param.rstrip('=')}",
                    matched_text=query[:200],
                    mitre_technique_id="T1552.001",
                )
            )
            break

    passed = len(findings) == 0
    elapsed = int((time.monotonic() - start) * 1_000_000)
    return URLScanLayerResult(layer_name="credential_in_url", passed=passed, findings=findings, latency_us=elapsed)


# ---------------------------------------------------------------------------
# Pipeline definition
# ---------------------------------------------------------------------------

# The 11 layers in execution order
_LAYERS = [
    _layer_scheme_validation,       # 1
    _layer_url_parsing,             # 2
    _layer_domain_blocklist,        # 3
    _layer_ssrf_guard,              # 4
    _layer_dns_validation,          # 5
    _layer_dlp_pattern_matching,    # 6
    _layer_entropy_analysis,        # 7
    _layer_domain_rate_limit,       # 8
    _layer_data_budget,             # 9
    _layer_path_traversal,          # 10
    _layer_credential_in_url,       # 11
]

# Layers whose failure means a hard block (pipeline short-circuits)
_BLOCKING_LAYERS = {
    "scheme_validation",
    "url_parsing",
    "domain_blocklist",
    "ssrf_guard",
}


# ---------------------------------------------------------------------------
# URLScanner
# ---------------------------------------------------------------------------


class URLScanner:
    """11-layer URL analysis pipeline.

    Executes each layer sequentially.  Blocking layers (scheme, parse,
    blocklist, SSRF) short-circuit the pipeline on failure.  Non-blocking
    layers (DLP, entropy, rate limit, etc.) accumulate findings.

    Thread-safe: all layer functions use thread-safe singletons.
    """

    def scan(self, url: str) -> URLScanResult:
        """Run the full 11-layer scan pipeline on *url*."""
        start = time.monotonic()
        parsed = urlparse(url)

        all_findings: list[ScanFinding] = []
        layer_results: list[URLScanLayerResult] = []
        blocked = False

        for layer_fn in _LAYERS:
            try:
                result = layer_fn(url, parsed)
            except Exception as exc:
                logger.warning(
                    "url_scanner_layer_error",
                    layer=layer_fn.__name__,
                    url=url[:200],
                    error=str(exc),
                )
                result = URLScanLayerResult(
                    layer_name=layer_fn.__name__.replace("_layer_", ""),
                    passed=True,
                    findings=[],
                )

            layer_results.append(result)
            all_findings.extend(result.findings)

            # Short-circuit on blocking layer failure
            if not result.passed and result.layer_name in _BLOCKING_LAYERS:
                blocked = True
                break

        total_us = int((time.monotonic() - start) * 1_000_000)
        allowed = not blocked and all(r.passed for r in layer_results)

        return URLScanResult(
            url=url,
            allowed=allowed,
            blocked=blocked,
            layer_results=layer_results,
            findings=all_findings,
            total_latency_us=total_us,
        )

    def scan_quick(self, url: str) -> bool:
        """Quick check: returns True if URL passes all blocking layers."""
        parsed = urlparse(url)
        for layer_fn in _LAYERS:
            result = layer_fn(url, parsed)
            if not result.passed and result.layer_name in _BLOCKING_LAYERS:
                return False
        return True


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

url_scanner = URLScanner()
