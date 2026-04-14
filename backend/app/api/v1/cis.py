"""CIS endpoints — Content Ingestion Security scanner API (Sprint 53 + 54).

APEP-420.d/421.d/422.d/423.d/425.d/426.d: REST endpoints for the ONNX
semantic classifier, model management, batch inference, and benchmarking.

Sprint 54 — APEP-428.d/430.d/432.b: Adds pre-session repository scanning,
individual file scanning, scan-on-session-start hook, and PostToolUse
auto-scan endpoints.

Endpoints:
  POST /v1/cis/scan-text     — Scan text through multi-tier pipeline
  POST /v1/cis/scan-repo     — Pre-session repository scan (Sprint 54)
  POST /v1/cis/scan-file     — Scan individual file (Sprint 54)
  POST /v1/cis/session-scan  — Scan-on-session-start hook (Sprint 54)
  POST /v1/cis/post-tool-scan — PostToolUse auto-scan (Sprint 54)
  POST /v1/cis/classify      — Direct ONNX classification (bypass Tier 0)
  POST /v1/cis/batch         — Async batch classification
  GET  /v1/cis/model/status  — ONNX model status and metadata
  POST /v1/cis/model/install — Download and verify ONNX model
  GET  /v1/cis/thresholds    — Current per-mode thresholds
  PUT  /v1/cis/thresholds    — Update per-mode thresholds
  POST /v1/cis/benchmark     — Run benchmark against dataset
  GET  /v1/cis/findings      — List recent CIS findings (Sprint 54)
"""

from __future__ import annotations

import logging
import time
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.observability import (
    CIS_REPO_SCAN_LATENCY,
    CIS_REPO_SCAN_TOTAL,
    CIS_FILE_SCAN_TOTAL,
    CIS_POST_TOOL_SCAN_TOTAL,
    CIS_SESSION_SCAN_TOTAL,
    ONNX_BATCH_LATENCY,
    ONNX_BATCH_SIZE,
    ONNX_BATCH_TOTAL,
    ONNX_BENCHMARK_F1,
)
from app.models.cis_scanner import (
    CISFinding,
    FileScanRequest,
    FileScanResult,
    PostToolScanRequest,
    PostToolScanResult,
    RepoScanRequest,
    RepoScanResult,
    SessionStartScanRequest,
    SessionStartScanResult,
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
from app.services.cis_post_tool_scan import cis_post_tool_scan
from app.services.cis_repo_scanner import cis_repo_scanner
from app.services.cis_session_hook import cis_session_hook
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
# POST /v1/cis/scan-repo (Sprint 54 — APEP-428)
# ---------------------------------------------------------------------------


@router.post("/scan-repo", response_model=RepoScanResult)
async def scan_repo(request: RepoScanRequest) -> RepoScanResult:
    """Scan an entire repository through the CIS pipeline (pre-session Layer 0).

    Walks the repository directory, identifies agent instruction files
    (CLAUDE.md, .cursorrules, AGENTS.md), and scans all text files.
    Instruction files are always scanned in STRICT mode.
    """
    result = cis_repo_scanner.scan(request)

    CIS_REPO_SCAN_TOTAL.labels(
        verdict=result.verdict.value,
    ).inc()
    CIS_REPO_SCAN_LATENCY.observe(result.latency_ms / 1000.0)

    # Apply taint if session_id provided.
    if request.session_id and result.taint_assigned:
        _apply_taint(request.session_id, result.taint_assigned, f"repo_scan:{result.scan_id}")

    return result


# ---------------------------------------------------------------------------
# POST /v1/cis/scan-file (Sprint 54 — APEP-432)
# ---------------------------------------------------------------------------


@router.post("/scan-file", response_model=FileScanResult)
async def scan_file(request: FileScanRequest) -> FileScanResult:
    """Scan a single file through the CIS pipeline.

    Auto-detects scan mode based on file type: instruction files use STRICT,
    test files use LENIENT, and other files use STANDARD.
    """
    import os
    import time as _time

    from app.services.cis_instruction_scanner import cis_instruction_scanner

    start = _time.monotonic()

    is_instruction = cis_instruction_scanner.is_instruction_file(request.file_path)
    instruction_type = cis_instruction_scanner.classify(request.file_path) if is_instruction else None
    scan_mode = cis_instruction_scanner.scan_mode_for_file(
        request.file_path, requested_mode=request.scan_mode
    )

    # Read file.
    try:
        with open(request.file_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("Cannot read file for CIS scan: %s", exc)
        return FileScanResult(
            file_path=request.file_path,
            scan_mode_applied=scan_mode,
            is_instruction_file=is_instruction,
            instruction_file_type=instruction_type,
            latency_ms=int((_time.monotonic() - start) * 1000),
        )

    # Scan through pipeline.
    pipeline_result = cis_pipeline.scan(
        text=content,
        scan_mode=scan_mode,
        tiers=request.tiers,
        tenant_id=request.tenant_id,
        use_cache=request.use_cache,
    )

    findings: list[CISFinding] = []
    for f in pipeline_result.findings:
        findings.append(
            CISFinding(
                rule_id=f.rule_id,
                scanner=f.scanner,
                severity=f.severity.value,
                description=f.description,
                matched_text=f.matched_text[:200],
                file_path=request.file_path,
            )
        )

    has_blocking = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    taint_assigned = pipeline_result.taint_level

    CIS_FILE_SCAN_TOTAL.labels(
        verdict="MALICIOUS" if has_blocking else "CLEAN",
        is_instruction=str(is_instruction),
    ).inc()

    # Apply taint.
    if request.session_id and taint_assigned:
        _apply_taint(request.session_id, taint_assigned, f"file_scan:{request.file_path}")

    from app.models.cis_scanner import CISScanVerdict

    verdict = CISScanVerdict.CLEAN
    if any(f.severity == "CRITICAL" for f in findings):
        verdict = CISScanVerdict.MALICIOUS
    elif any(f.severity == "HIGH" for f in findings):
        verdict = CISScanVerdict.SUSPICIOUS

    return FileScanResult(
        file_path=request.file_path,
        allowed=not has_blocking,
        verdict=verdict,
        findings=findings,
        scan_mode_applied=scan_mode,
        is_instruction_file=is_instruction,
        instruction_file_type=instruction_type,
        taint_assigned=taint_assigned,
        cache_hit=pipeline_result.cache_hit,
        latency_ms=int((_time.monotonic() - start) * 1000),
    )


# ---------------------------------------------------------------------------
# POST /v1/cis/session-scan (Sprint 54 — APEP-430)
# ---------------------------------------------------------------------------


@router.post("/session-scan", response_model=SessionStartScanResult)
async def session_scan(request: SessionStartScanRequest) -> SessionStartScanResult:
    """Run scan-on-session-start hook.

    Scans the repository (if repo_path provided) before an agent session
    begins, applying taint labels to the session graph.
    """
    result = cis_session_hook.on_session_start(request)

    CIS_SESSION_SCAN_TOTAL.labels(
        session_allowed=str(result.session_allowed),
    ).inc()

    return result


# ---------------------------------------------------------------------------
# POST /v1/cis/post-tool-scan (Sprint 54 — APEP-431)
# ---------------------------------------------------------------------------


@router.post("/post-tool-scan", response_model=PostToolScanResult)
async def post_tool_scan(request: PostToolScanRequest) -> PostToolScanResult:
    """PostToolUse auto-scan — scan tool output for injection.

    Scans all tool output through the CIS pipeline after execution.
    Auto-escalates MEDIUM findings to HIGH and applies QUARANTINE taint
    if injection is detected.
    """
    result = cis_post_tool_scan.scan(request)

    CIS_POST_TOOL_SCAN_TOTAL.labels(
        verdict=result.verdict.value,
        escalated=str(result.escalated),
    ).inc()

    return result


# ---------------------------------------------------------------------------
# GET /v1/cis/findings (Sprint 54 — APEP-433 support)
# ---------------------------------------------------------------------------


class CISFindingsQuery(BaseModel):
    """Query parameters for GET /v1/cis/findings."""

    session_id: str | None = Field(default=None, description="Filter by session ID")
    severity: str | None = Field(default=None, description="Filter by severity")
    scanner: str | None = Field(default=None, description="Filter by scanner name")
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class CISFindingsResponse(BaseModel):
    """Response for GET /v1/cis/findings."""

    findings: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0


@router.get("/findings", response_model=CISFindingsResponse)
async def list_findings(
    session_id: str | None = None,
    severity: str | None = None,
    scanner: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> CISFindingsResponse:
    """List recent CIS findings for the Policy Console findings screen."""
    try:
        from app.db.mongodb import get_database

        db = get_database()
        query: dict[str, Any] = {}
        if session_id:
            query["session_id"] = session_id
        if severity:
            query["severity"] = severity
        if scanner:
            query["scanner"] = scanner

        collection = db["cis_findings"]
        total = await collection.count_documents(query)
        cursor = collection.find(query).sort("timestamp", -1).skip(offset).limit(limit)
        docs = await cursor.to_list(length=limit)

        findings = []
        for doc in docs:
            doc["_id"] = str(doc["_id"])
            findings.append(doc)

        return CISFindingsResponse(findings=findings, total=total)
    except Exception:
        logger.exception("Failed to query CIS findings")
        return CISFindingsResponse(findings=[], total=0)


# ---------------------------------------------------------------------------
# Shared helper — taint application
# ---------------------------------------------------------------------------


def _apply_taint(session_id: str, taint_level: str, source_label: str) -> None:
    """Apply taint label to session graph (shared across endpoints)."""
    try:
        from app.models.policy import TaintLevel
        from app.services.taint_graph import session_graph_manager

        graph = session_graph_manager.get_or_create(session_id)
        taint = (
            TaintLevel.QUARANTINE
            if taint_level == "QUARANTINE"
            else TaintLevel.UNTRUSTED
        )
        graph.add_node(
            value=f"cis_finding:{source_label}",
            taint_level=taint,
            source="TOOL_OUTPUT",
        )
    except Exception:
        logger.exception("Failed to apply taint from CIS scan")


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
