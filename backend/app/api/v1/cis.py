"""CIS endpoints — Content Ingestion Security scanner API (Sprint 53).

APEP-420.d/421.d/422.d/423.d/425.d/426.d: REST endpoints for the ONNX
semantic classifier, model management, batch inference, and benchmarking.

Endpoints:
  POST /v1/cis/scan-text     — Scan text through multi-tier pipeline
  POST /v1/cis/classify      — Direct ONNX classification (bypass Tier 0)
  POST /v1/cis/batch         — Async batch classification
  GET  /v1/cis/model/status  — ONNX model status and metadata
  POST /v1/cis/model/install — Download and verify ONNX model
  GET  /v1/cis/thresholds    — Current per-mode thresholds
  PUT  /v1/cis/thresholds    — Update per-mode thresholds
  POST /v1/cis/benchmark     — Run benchmark against dataset
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.observability import (
    ONNX_BATCH_LATENCY,
    ONNX_BATCH_SIZE,
    ONNX_BATCH_TOTAL,
    ONNX_BENCHMARK_F1,
)
from app.models.onnx_classifier import (
    BatchInferenceRequest,
    BatchInferenceResult,
    BenchmarkDatasetEntry,
    BenchmarkResult,
    ONNXClassificationResult,
    ONNXModeThresholds,
    ONNXModelInfo,
)
from app.services.cis_pipeline import CISPipelineResult, cis_pipeline
from app.services.onnx_benchmark import onnx_benchmark
from app.services.onnx_model_manager import onnx_model_manager
from app.services.onnx_semantic_classifier import onnx_semantic_classifier

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/cis", tags=["cis"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CISScanTextRequest(BaseModel):
    """Request for multi-tier CIS text scan."""

    text: str = Field(..., min_length=1, description="Text content to scan")
    scan_mode: str = Field(default="STANDARD", description="STRICT, STANDARD, or LENIENT")
    tiers: list[int] = Field(default=[0, 1], description="Tiers to run: 0=regex, 1=ONNX")
    session_id: str | None = Field(default=None, description="Session ID for taint propagation")
    tenant_id: str = Field(default="", description="Tenant ID for allowlist lookups")
    use_cache: bool = Field(default=True, description="Use trust cache for bypass")


class CISScanTextResponse(BaseModel):
    """Response from multi-tier CIS text scan."""

    allowed: bool = True
    findings: list[dict[str, Any]] = Field(default_factory=list)
    tier_results: list[dict[str, Any]] = Field(default_factory=list)
    scan_mode: str = "STANDARD"
    taint_assigned: str | None = None
    cache_hit: bool = False
    allowlisted: bool = False
    latency_ms: int = 0


class CISClassifyRequest(BaseModel):
    """Request for direct ONNX classification."""

    text: str = Field(..., min_length=1, description="Text to classify")
    scan_mode: str = Field(default="STANDARD")


class CISModelInstallRequest(BaseModel):
    """Request to download and install the ONNX model."""

    url: str = Field(..., description="URL to download the ONNX model from")


class CISBenchmarkRequest(BaseModel):
    """Request to run a benchmark against a labeled dataset."""

    dataset: list[BenchmarkDatasetEntry] = Field(
        ..., min_length=1, description="Labeled dataset entries"
    )
    scan_mode: str = Field(default="STANDARD")
    dataset_name: str = Field(default="custom")


# ---------------------------------------------------------------------------
# POST /v1/cis/scan-text
# ---------------------------------------------------------------------------


@router.post("/scan-text", response_model=CISScanTextResponse)
async def scan_text(request: CISScanTextRequest) -> CISScanTextResponse:
    """Scan text content through the multi-tier CIS pipeline."""
    result: CISPipelineResult = cis_pipeline.scan(
        text=request.text,
        scan_mode=request.scan_mode,
        tiers=request.tiers,
        tenant_id=request.tenant_id,
        use_cache=request.use_cache,
    )

    # Apply taint if session_id provided and findings exist
    if request.session_id and result.taint_level:
        try:
            from app.models.policy import TaintLevel
            from app.services.taint_graph import session_graph_manager

            graph = session_graph_manager.get_or_create(request.session_id)
            taint = (
                TaintLevel.QUARANTINE
                if result.taint_level == "QUARANTINE"
                else TaintLevel.UNTRUSTED
            )
            graph.add_node(
                value=f"cis_finding:{result.findings[0].rule_id}" if result.findings else "cis_finding",
                taint_level=taint,
                source="TOOL_OUTPUT",
            )
        except Exception:
            logger.exception("Failed to apply taint from CIS scan")

    return CISScanTextResponse(
        allowed=result.allowed,
        findings=[
            {
                "rule_id": f.rule_id,
                "scanner": f.scanner,
                "severity": f.severity.value,
                "description": f.description,
            }
            for f in result.findings
        ],
        tier_results=[
            {
                "tier": tr.tier,
                "scanner_name": tr.scanner_name,
                "verdict": tr.verdict.value,
                "score": tr.score,
                "findings_count": tr.findings_count,
                "latency_ms": tr.latency_ms,
            }
            for tr in result.tier_results
        ],
        scan_mode=result.scan_mode,
        taint_assigned=result.taint_level,
        cache_hit=result.cache_hit,
        allowlisted=result.allowlisted,
        latency_ms=result.latency_ms,
    )


# ---------------------------------------------------------------------------
# POST /v1/cis/classify
# ---------------------------------------------------------------------------


@router.post("/classify", response_model=ONNXClassificationResult)
async def classify(request: CISClassifyRequest) -> ONNXClassificationResult:
    """Run direct ONNX classification on text (bypasses Tier 0 regex)."""
    return onnx_semantic_classifier.classify(
        text=request.text,
        scan_mode=request.scan_mode,
    )


# ---------------------------------------------------------------------------
# POST /v1/cis/batch
# ---------------------------------------------------------------------------


@router.post("/batch", response_model=BatchInferenceResult)
async def batch_classify(request: BatchInferenceRequest) -> BatchInferenceResult:
    """Run async batch inference over multiple texts."""
    start = time.monotonic()
    ONNX_BATCH_SIZE.observe(len(request.texts))

    result = await onnx_semantic_classifier.classify_batch(request)

    elapsed = (time.monotonic() - start)
    ONNX_BATCH_LATENCY.observe(elapsed)
    ONNX_BATCH_TOTAL.labels(status=result.status.value).inc()

    return result


# ---------------------------------------------------------------------------
# GET /v1/cis/model/status
# ---------------------------------------------------------------------------


@router.get("/model/status", response_model=ONNXModelInfo)
async def model_status() -> ONNXModelInfo:
    """Return ONNX model status and metadata."""
    return onnx_model_manager.info


# ---------------------------------------------------------------------------
# POST /v1/cis/model/install
# ---------------------------------------------------------------------------


@router.post("/model/install", response_model=ONNXModelInfo)
async def model_install(request: CISModelInstallRequest) -> ONNXModelInfo:
    """Download and install the ONNX model from a URL.

    After download, the model is verified via SHA-256 and the classifier
    is reloaded.
    """
    success = await onnx_model_manager.download(request.url)
    if success:
        onnx_semantic_classifier.reload()
    return onnx_model_manager.info


# ---------------------------------------------------------------------------
# GET /v1/cis/thresholds
# ---------------------------------------------------------------------------


@router.get("/thresholds", response_model=ONNXModeThresholds)
async def get_thresholds() -> ONNXModeThresholds:
    """Return current per-mode ONNX classification thresholds."""
    return onnx_semantic_classifier.thresholds


# ---------------------------------------------------------------------------
# PUT /v1/cis/thresholds
# ---------------------------------------------------------------------------


@router.put("/thresholds", response_model=ONNXModeThresholds)
async def update_thresholds(body: ONNXModeThresholds) -> ONNXModeThresholds:
    """Update per-mode ONNX classification thresholds."""
    onnx_semantic_classifier._thresholds = body
    return onnx_semantic_classifier.thresholds


# ---------------------------------------------------------------------------
# POST /v1/cis/benchmark
# ---------------------------------------------------------------------------


@router.post("/benchmark", response_model=BenchmarkResult)
async def run_benchmark(request: CISBenchmarkRequest) -> BenchmarkResult:
    """Run a benchmark of the ONNX classifier against a labeled dataset."""
    result = onnx_benchmark.run(
        dataset=request.dataset,
        scan_mode=request.scan_mode,
        dataset_name=request.dataset_name,
    )

    # Emit metric
    ONNX_BENCHMARK_F1.labels(
        dataset=request.dataset_name,
        scan_mode=request.scan_mode,
    ).set(result.f1_score)

    return result
