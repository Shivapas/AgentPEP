"""CISPipeline — multi-tier Content Ingestion Security scanner (APEP-420.e).

Sprint 53: Integrates the ONNXSemanticClassifier as Tier 1 in the CIS
scanner pipeline, alongside the existing Tier 0 regex-based
InjectionSignatureLibrary.

Pipeline architecture:
  Tier 0: InjectionSignatureLibrary (204 patterns, 25 categories) — fast regex
  Tier 1: ONNXSemanticClassifier (MiniLM-L6-v2, 94.3% F1) — semantic ML
  Tier 2: (future) LLM fallback — general-purpose, slower

Execution flow:
  1. Check CISAllowlist → bypass if allowlisted.
  2. Check CISTrustCache → bypass if cached clean.
  3. Run Tier 0 (regex).
  4. Run Tier 1 (ONNX) — if available, else fallback gracefully.
  5. Combine findings from all tiers.
  6. Apply taint based on combined verdict.
  7. Cache clean results.
  8. Emit Prometheus metrics.
"""

from __future__ import annotations

import logging
import time

from app.core.observability import (
    ONNX_CHUNKS_PER_INPUT,
    ONNX_FALLBACK_TOTAL,
    ONNX_INFERENCE_LATENCY,
    ONNX_INFERENCE_TOTAL,
    ONNX_MODEL_STATUS,
    ONNX_SCORE_HISTOGRAM,
)
from app.models.network_scan import ScanFinding, ScanSeverity
from app.models.onnx_classifier import (
    CISTierResult,
    ONNXClassificationVerdict,
)
from app.services.cis_allowlist import CISAllowlist, cis_allowlist
from app.services.cis_trust_cache import CISTrustCache, cis_trust_cache
from app.services.injection_signatures import InjectionSignatureLibrary, injection_library
from app.services.onnx_semantic_classifier import (
    ONNXSemanticClassifier,
    onnx_semantic_classifier,
)
from app.services.scan_mode_router import CISScanMode, ScanModeRouter, scan_mode_router

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline result
# ---------------------------------------------------------------------------


class CISPipelineResult:
    """Aggregated result from all tiers of the CIS pipeline."""

    __slots__ = (
        "allowed",
        "findings",
        "tier_results",
        "scan_mode",
        "taint_level",
        "cache_hit",
        "allowlisted",
        "latency_ms",
    )

    def __init__(
        self,
        *,
        allowed: bool = True,
        findings: list[ScanFinding] | None = None,
        tier_results: list[CISTierResult] | None = None,
        scan_mode: str = "STANDARD",
        taint_level: str | None = None,
        cache_hit: bool = False,
        allowlisted: bool = False,
        latency_ms: int = 0,
    ) -> None:
        self.allowed = allowed
        self.findings = findings or []
        self.tier_results = tier_results or []
        self.scan_mode = scan_mode
        self.taint_level = taint_level
        self.cache_hit = cache_hit
        self.allowlisted = allowlisted
        self.latency_ms = latency_ms


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class CISPipeline:
    """Multi-tier Content Ingestion Security scanner pipeline.

    Runs Tier 0 (regex) and Tier 1 (ONNX) sequentially, combines findings,
    and determines the overall verdict and taint assignment.

    Parameters
    ----------
    scan_mode_router:
        Tier 0 regex scanner with mode-based filtering.
    onnx_classifier:
        Tier 1 ONNX semantic classifier.
    trust_cache:
        Content-hash trust cache for scan bypass.
    allowlist:
        Permanent content allowlist for scan bypass.
    """

    def __init__(
        self,
        scan_mode_router: ScanModeRouter | None = None,
        onnx_classifier: ONNXSemanticClassifier | None = None,
        trust_cache: CISTrustCache | None = None,
        allowlist: CISAllowlist | None = None,
    ) -> None:
        self._tier0 = scan_mode_router or scan_mode_router
        self._tier1 = onnx_classifier or onnx_semantic_classifier
        self._cache = trust_cache or cis_trust_cache
        self._allowlist = allowlist or cis_allowlist

    def scan(
        self,
        text: str,
        scan_mode: str = "STANDARD",
        tiers: list[int] | None = None,
        tenant_id: str = "",
        use_cache: bool = True,
    ) -> CISPipelineResult:
        """Run the multi-tier scan pipeline on *text*.

        Parameters
        ----------
        text:
            Content to scan.
        scan_mode:
            CIS scan mode (STRICT, STANDARD, LENIENT).
        tiers:
            Which tiers to run.  Default: [0, 1].
        tenant_id:
            Tenant for allowlist lookups.
        use_cache:
            Whether to check/update the trust cache.
        """
        start = time.monotonic()
        active_tiers = tiers if tiers is not None else [0, 1]
        findings: list[ScanFinding] = []
        tier_results: list[CISTierResult] = []

        # Emit ONNX model readiness gauge
        ONNX_MODEL_STATUS.set(1.0 if self._tier1.is_available else 0.0)

        # 1. Allowlist check
        if self._allowlist.is_allowed(text, tenant_id=tenant_id):
            return CISPipelineResult(
                allowed=True,
                scan_mode=scan_mode,
                allowlisted=True,
                latency_ms=self._elapsed_ms(start),
            )

        # 2. Trust cache check
        if use_cache and self._cache.is_trusted(text):
            return CISPipelineResult(
                allowed=True,
                scan_mode=scan_mode,
                cache_hit=True,
                latency_ms=self._elapsed_ms(start),
            )

        try:
            mode = CISScanMode(scan_mode)
        except ValueError:
            mode = CISScanMode.STRICT

        # 3. Tier 0: Regex scan
        if 0 in active_tiers:
            t0_start = time.monotonic()
            from app.services.scan_mode_router import scan_mode_router as _router

            matches = _router.check(text, mode=mode)
            t0_latency = self._elapsed_ms(t0_start)

            t0_verdict = ONNXClassificationVerdict.CLEAN
            for match in matches:
                sev = ScanSeverity.MEDIUM
                try:
                    sev = ScanSeverity(match.severity)
                except ValueError:
                    pass
                findings.append(
                    ScanFinding(
                        rule_id=match.signature_id,
                        scanner="InjectionSignatureLibrary",
                        severity=sev,
                        description=match.description,
                        matched_text=text[:200],
                    )
                )
                if match.severity in ("CRITICAL", "HIGH"):
                    t0_verdict = ONNXClassificationVerdict.MALICIOUS
                elif (
                    match.severity == "MEDIUM"
                    and t0_verdict == ONNXClassificationVerdict.CLEAN
                ):
                    t0_verdict = ONNXClassificationVerdict.SUSPICIOUS

            tier_results.append(
                CISTierResult(
                    tier=0,
                    scanner_name="InjectionSignatureLibrary",
                    verdict=t0_verdict,
                    findings_count=len(matches),
                    latency_ms=t0_latency,
                )
            )

        # 4. Tier 1: ONNX semantic classifier
        if 1 in active_tiers:
            t1_start = time.monotonic()
            onnx_result = self._tier1.classify(text, scan_mode=scan_mode)
            t1_latency = self._elapsed_ms(t1_start)

            # Emit Prometheus metrics
            ONNX_INFERENCE_TOTAL.labels(verdict=onnx_result.verdict.value).inc()
            ONNX_INFERENCE_LATENCY.observe(t1_latency / 1000.0)
            ONNX_SCORE_HISTOGRAM.observe(onnx_result.score)
            ONNX_CHUNKS_PER_INPUT.observe(onnx_result.chunks_analyzed)

            if onnx_result.fallback_used:
                ONNX_FALLBACK_TOTAL.inc()

            if onnx_result.verdict != ONNXClassificationVerdict.CLEAN:
                sev = (
                    ScanSeverity.CRITICAL
                    if onnx_result.verdict == ONNXClassificationVerdict.MALICIOUS
                    else ScanSeverity.HIGH
                )
                findings.append(
                    ScanFinding(
                        rule_id="ONNX-SEMANTIC",
                        scanner="ONNXSemanticClassifier",
                        severity=sev,
                        description=(
                            f"ONNX semantic classifier: {onnx_result.verdict.value} "
                            f"(score={onnx_result.score:.3f}, mode={scan_mode})"
                        ),
                        matched_text=text[:200],
                        metadata={
                            "score": onnx_result.score,
                            "chunks": onnx_result.chunks_analyzed,
                            "fallback": onnx_result.fallback_used,
                        },
                    )
                )

            tier_results.append(
                CISTierResult(
                    tier=1,
                    scanner_name="ONNXSemanticClassifier",
                    verdict=onnx_result.verdict,
                    score=onnx_result.score,
                    findings_count=1 if onnx_result.verdict != ONNXClassificationVerdict.CLEAN else 0,
                    latency_ms=t1_latency,
                )
            )

        # 5. Determine combined verdict
        has_critical = any(f.severity == ScanSeverity.CRITICAL for f in findings)
        has_high = any(f.severity == ScanSeverity.HIGH for f in findings)
        allowed = not (has_critical or has_high)

        # 6. Taint assignment
        taint_level: str | None = None
        if findings:
            if has_critical or has_high:
                taint_level = "QUARANTINE"
            else:
                taint_level = "UNTRUSTED"

        # 7. Cache clean results
        if not findings and use_cache:
            active_cats = len(_router.active_categories(mode)) if 0 in active_tiers else 0
            self._cache.mark_trusted(text, categories_checked=active_cats)

        latency = self._elapsed_ms(start)

        return CISPipelineResult(
            allowed=allowed,
            findings=findings,
            tier_results=tier_results,
            scan_mode=scan_mode,
            taint_level=taint_level,
            latency_ms=latency,
        )

    @staticmethod
    def _elapsed_ms(start: float) -> int:
        return int((time.monotonic() - start) * 1000)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

cis_pipeline = CISPipeline()
