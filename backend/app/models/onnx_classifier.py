"""Pydantic models for Sprint 53 — ONNX Semantic Injection Classifier.

APEP-420/421/422/423/425/426: Data models for the ONNXSemanticClassifier
service, model download and verification, per-mode classification thresholds,
text chunking, async batch inference, and benchmarking.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ONNXClassificationVerdict(StrEnum):
    """Classification verdict from the ONNX semantic classifier."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class ONNXModelStatus(StrEnum):
    """Lifecycle status of the ONNX model."""

    NOT_INSTALLED = "NOT_INSTALLED"
    DOWNLOADING = "DOWNLOADING"
    VERIFYING = "VERIFYING"
    READY = "READY"
    FAILED = "FAILED"


class BatchJobStatus(StrEnum):
    """Status of an async batch inference job."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


# ---------------------------------------------------------------------------
# ONNX Model Metadata (APEP-421)
# ---------------------------------------------------------------------------


class ONNXModelInfo(BaseModel):
    """Metadata about the ONNX MiniLM-L6-v2 model."""

    model_name: str = Field(
        default="minilm-l6-v2-injection-classifier",
        description="Model identifier",
    )
    model_path: str = Field(
        default="/opt/agentpep/models/injection_classifier.onnx",
        description="Filesystem path where the ONNX model is stored",
    )
    tokenizer_path: str = Field(
        default="/opt/agentpep/models/tokenizer",
        description="Filesystem path for the tokenizer files",
    )
    expected_sha256: str = Field(
        default="",
        description="Expected SHA-256 hash of the ONNX model file for integrity verification",
    )
    actual_sha256: str = Field(
        default="",
        description="Computed SHA-256 hash after download",
    )
    status: ONNXModelStatus = Field(
        default=ONNXModelStatus.NOT_INSTALLED,
        description="Current model lifecycle status",
    )
    file_size_bytes: int = Field(default=0, description="Model file size in bytes")
    downloaded_at: datetime | None = Field(
        default=None, description="When the model was last downloaded"
    )
    verified_at: datetime | None = Field(
        default=None, description="When the model hash was last verified"
    )


# ---------------------------------------------------------------------------
# Classification Thresholds (APEP-422)
# ---------------------------------------------------------------------------


class ONNXThresholds(BaseModel):
    """ONNX classification thresholds for a specific scan mode.

    Scores below ``suspicious`` are CLEAN.
    Scores >= ``suspicious`` and < ``malicious`` are SUSPICIOUS.
    Scores >= ``malicious`` are MALICIOUS.
    """

    suspicious: float = Field(
        default=0.65,
        ge=0.0,
        le=1.0,
        description="Score threshold for SUSPICIOUS verdict",
    )
    malicious: float = Field(
        default=0.88,
        ge=0.0,
        le=1.0,
        description="Score threshold for MALICIOUS verdict",
    )


class ONNXModeThresholds(BaseModel):
    """Per-mode ONNX classification thresholds (APEP-422).

    Maps CISScanMode values to their ONNX thresholds, matching the PRD:
      STRICT:   suspicious=0.50, malicious=0.80
      STANDARD: suspicious=0.65, malicious=0.88
      LENIENT:  suspicious=0.75, malicious=0.92
    """

    strict: ONNXThresholds = Field(
        default_factory=lambda: ONNXThresholds(suspicious=0.50, malicious=0.80),
    )
    standard: ONNXThresholds = Field(
        default_factory=lambda: ONNXThresholds(suspicious=0.65, malicious=0.88),
    )
    lenient: ONNXThresholds = Field(
        default_factory=lambda: ONNXThresholds(suspicious=0.75, malicious=0.92),
    )

    def get_thresholds(self, mode: str) -> ONNXThresholds:
        """Return thresholds for the given mode string (case-insensitive)."""
        mode_upper = mode.upper()
        if mode_upper == "STRICT":
            return self.strict
        elif mode_upper == "LENIENT":
            return self.lenient
        return self.standard


# ---------------------------------------------------------------------------
# Text Chunk (APEP-423)
# ---------------------------------------------------------------------------


class TextChunk(BaseModel):
    """A chunk of text extracted for classification."""

    text: str = Field(..., description="The chunk text")
    offset: int = Field(default=0, description="Character offset in the original text")
    length: int = Field(default=0, description="Length of this chunk")
    chunk_index: int = Field(default=0, description="Index of this chunk in the sequence")


# ---------------------------------------------------------------------------
# Classification Result (APEP-420)
# ---------------------------------------------------------------------------


class ONNXClassificationResult(BaseModel):
    """Result from the ONNX semantic classifier for a single text input."""

    text_hash: str = Field(default="", description="SHA-256 hash of the input text")
    score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Injection probability score from the ONNX model",
    )
    verdict: ONNXClassificationVerdict = Field(
        default=ONNXClassificationVerdict.CLEAN,
        description="Classification verdict based on thresholds",
    )
    scan_mode: str = Field(default="STANDARD", description="Scan mode used for thresholds")
    thresholds_applied: ONNXThresholds | None = Field(
        default=None, description="Thresholds that produced this verdict"
    )
    chunks_analyzed: int = Field(
        default=1, description="Number of text chunks analyzed"
    )
    max_chunk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Highest score among all chunks (for chunked inputs)",
    )
    latency_ms: int = Field(default=0, description="Inference latency in milliseconds")
    model_available: bool = Field(
        default=True,
        description="Whether the ONNX model was available; False triggers fallback",
    )
    fallback_used: bool = Field(
        default=False,
        description="Whether a fallback was used instead of the ONNX model",
    )


# ---------------------------------------------------------------------------
# Batch Inference (APEP-425)
# ---------------------------------------------------------------------------


class BatchInferenceRequest(BaseModel):
    """Request for async batch inference over multiple text inputs."""

    batch_id: UUID = Field(default_factory=uuid4, description="Unique batch identifier")
    texts: list[str] = Field(..., min_length=1, description="List of texts to classify")
    scan_mode: str = Field(default="STANDARD", description="Scan mode for thresholds")
    session_id: str | None = Field(
        default=None, description="Session ID for taint propagation"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class BatchInferenceResult(BaseModel):
    """Result of an async batch inference job."""

    batch_id: UUID = Field(..., description="Batch identifier matching the request")
    status: BatchJobStatus = Field(default=BatchJobStatus.PENDING)
    results: list[ONNXClassificationResult] = Field(default_factory=list)
    total_texts: int = Field(default=0, description="Total number of texts in the batch")
    completed_texts: int = Field(default=0, description="Number of texts processed so far")
    total_latency_ms: int = Field(default=0, description="Total batch processing time")
    error: str | None = Field(default=None, description="Error message if batch failed")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = Field(default=None)


# ---------------------------------------------------------------------------
# Benchmark (APEP-426)
# ---------------------------------------------------------------------------


class BenchmarkDatasetEntry(BaseModel):
    """A single entry in a benchmark dataset."""

    text: str = Field(..., description="Input text")
    label: int = Field(..., ge=0, le=1, description="Ground truth: 0=benign, 1=injection")


class BenchmarkResult(BaseModel):
    """Result from benchmarking the ONNX classifier against ToolTrust metrics."""

    benchmark_id: UUID = Field(default_factory=uuid4)
    dataset_name: str = Field(default="", description="Name of the benchmark dataset")
    total_samples: int = Field(default=0)
    true_positives: int = Field(default=0)
    false_positives: int = Field(default=0)
    true_negatives: int = Field(default=0)
    false_negatives: int = Field(default=0)
    precision: float = Field(default=0.0, ge=0.0, le=1.0)
    recall: float = Field(default=0.0, ge=0.0, le=1.0)
    f1_score: float = Field(default=0.0, ge=0.0, le=1.0)
    target_f1: float = Field(
        default=0.943,
        description="ToolTrust published F1 target (94.3%)",
    )
    meets_target: bool = Field(
        default=False,
        description="Whether the measured F1 meets or exceeds the target",
    )
    avg_latency_ms: float = Field(default=0.0, description="Average per-sample inference latency")
    scan_mode: str = Field(default="STANDARD")
    run_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ---------------------------------------------------------------------------
# CIS Scan Tier Result (shared with scan pipeline)
# ---------------------------------------------------------------------------


class CISTierResult(BaseModel):
    """Per-tier outcome in the multi-tier CIS scanner pipeline."""

    tier: int = Field(..., description="Tier number: 0=regex, 1=ONNX, 2=LLM")
    scanner_name: str = Field(..., description="Name of the scanner that ran")
    verdict: ONNXClassificationVerdict = Field(default=ONNXClassificationVerdict.CLEAN)
    score: float | None = Field(
        default=None, description="Numeric score (for ONNX tier)"
    )
    findings_count: int = Field(default=0)
    latency_ms: int = Field(default=0)
