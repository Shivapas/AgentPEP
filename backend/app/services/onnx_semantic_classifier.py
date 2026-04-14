"""ONNXSemanticClassifier — ONNX MiniLM-L6-v2 injection classifier (APEP-420).

Sprint 53: Tier 1 semantic injection classifier using a fine-tuned
MiniLM-L6-v2 model exported to ONNX format.  Integrates with the CIS
scanner pipeline as the middle tier between regex-based Tier 0
(InjectionSignatureLibrary) and the optional LLM-based Tier 2 fallback.

Capabilities:
  - APEP-420: ONNXSemanticClassifier service with ONNX Runtime inference.
  - APEP-422: Per-mode classification thresholds (STRICT/STANDARD/LENIENT).
  - APEP-423: Text chunking for long content via ONNXTextChunker.
  - APEP-424: Graceful fallback when the ONNX model is absent.
  - APEP-425: Async batch inference for multiple texts.

The classifier loads the ONNX model via ``onnxruntime`` (optional dependency).
If the model or runtime is unavailable, the classifier degrades gracefully
by delegating all classification to the regex-based Tier 0 scanner.

Thread-safety: the ONNX session is created once at init and is read-only
during inference.  The ``threading.Lock`` protects model reload only.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
import threading
from datetime import UTC, datetime
from uuid import UUID

from app.models.onnx_classifier import (
    BatchInferenceRequest,
    BatchInferenceResult,
    BatchJobStatus,
    ONNXClassificationResult,
    ONNXClassificationVerdict,
    ONNXModeThresholds,
    ONNXThresholds,
    TextChunk,
)
from app.services.onnx_model_manager import ONNXModelManager, onnx_model_manager
from app.services.onnx_text_chunker import ONNXTextChunker, onnx_text_chunker

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional ONNX Runtime import
# ---------------------------------------------------------------------------

_onnxruntime = None
_tokenizers = None

try:
    import onnxruntime  # type: ignore[import-untyped]

    _onnxruntime = onnxruntime
except ImportError:
    logger.info("onnxruntime not installed — ONNX Tier 1 classifier will use fallback")

try:
    from tokenizers import Tokenizer  # type: ignore[import-untyped]

    _tokenizers = Tokenizer
except ImportError:
    logger.info("tokenizers not installed — ONNX Tier 1 classifier will use fallback")


# ---------------------------------------------------------------------------
# Softmax helper
# ---------------------------------------------------------------------------


def _softmax(logits: list[float]) -> list[float]:
    """Compute softmax over a list of logits."""
    import math

    max_val = max(logits)
    exps = [math.exp(x - max_val) for x in logits]
    total = sum(exps)
    return [e / total for e in exps]


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


class ONNXSemanticClassifier:
    """Tier 1 ONNX-based semantic injection classifier.

    Parameters
    ----------
    model_manager:
        Manages the ONNX model lifecycle (download, verify, status).
    text_chunker:
        Splits long text into overlapping chunks for inference.
    thresholds:
        Per-scan-mode classification thresholds.
    """

    def __init__(
        self,
        model_manager: ONNXModelManager | None = None,
        text_chunker: ONNXTextChunker | None = None,
        thresholds: ONNXModeThresholds | None = None,
    ) -> None:
        self._model_manager = model_manager or onnx_model_manager
        self._text_chunker = text_chunker or onnx_text_chunker
        self._thresholds = thresholds or ONNXModeThresholds()
        self._lock = threading.Lock()

        # ONNX session and tokenizer — loaded lazily
        self._session = None
        self._tokenizer = None
        self._model_loaded = False

        # Attempt to load if model is available
        self._try_load()

    # -- Model Loading ------------------------------------------------------

    def _try_load(self) -> bool:
        """Attempt to load the ONNX session and tokenizer.

        Returns ``True`` if both loaded successfully.
        """
        if _onnxruntime is None or _tokenizers is None:
            logger.info("ONNX runtime or tokenizers not available — using fallback")
            return False

        if not self._model_manager.is_ready:
            logger.info("ONNX model not ready — using fallback")
            return False

        try:
            model_path = str(self._model_manager.model_path)
            tokenizer_path = str(self._model_manager.tokenizer_path / "tokenizer.json")

            sess_options = _onnxruntime.SessionOptions()
            sess_options.graph_optimization_level = (
                _onnxruntime.GraphOptimizationLevel.ORT_ENABLE_ALL
            )
            sess_options.intra_op_num_threads = 2

            session = _onnxruntime.InferenceSession(
                model_path, sess_options, providers=["CPUExecutionProvider"]
            )
            tokenizer = _tokenizers(tokenizer_path)

            with self._lock:
                self._session = session
                self._tokenizer = tokenizer
                self._model_loaded = True

            logger.info("ONNX semantic classifier loaded successfully")
            return True

        except Exception:
            logger.exception("Failed to load ONNX model — using fallback")
            with self._lock:
                self._model_loaded = False
            return False

    def reload(self) -> bool:
        """Re-verify the model and reload the ONNX session."""
        try:
            self._model_manager.verify()
        except FileNotFoundError:
            with self._lock:
                self._model_loaded = False
            return False
        return self._try_load()

    # -- Properties ---------------------------------------------------------

    @property
    def is_available(self) -> bool:
        """Return ``True`` if the ONNX model is loaded and ready."""
        with self._lock:
            return self._model_loaded

    @property
    def thresholds(self) -> ONNXModeThresholds:
        """Return the current threshold configuration."""
        return self._thresholds

    # -- Classification (APEP-420) -----------------------------------------

    def classify(
        self,
        text: str,
        scan_mode: str = "STANDARD",
    ) -> ONNXClassificationResult:
        """Classify *text* for prompt injection.

        If the ONNX model is not available, returns a fallback result with
        ``model_available=False`` and ``fallback_used=True`` (APEP-424).

        For text longer than the chunk limit, splits into overlapping chunks
        and returns the maximum score across all chunks (APEP-423).
        """
        start = time.monotonic()
        text_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        mode_thresholds = self._thresholds.get_thresholds(scan_mode)

        if not self.is_available:
            return self._fallback_result(text_hash, scan_mode, mode_thresholds, start)

        # Chunk the text (APEP-423)
        chunks = self._text_chunker.chunk(text)
        if not chunks:
            return ONNXClassificationResult(
                text_hash=text_hash,
                score=0.0,
                verdict=ONNXClassificationVerdict.CLEAN,
                scan_mode=scan_mode,
                thresholds_applied=mode_thresholds,
                chunks_analyzed=0,
                max_chunk_score=0.0,
                latency_ms=self._elapsed_ms(start),
                model_available=True,
                fallback_used=False,
            )

        # Run inference on each chunk
        scores = []
        for chunk in chunks:
            score = self._infer(chunk.text)
            scores.append(score)

        max_score = max(scores)
        verdict = self._apply_thresholds(max_score, mode_thresholds)

        return ONNXClassificationResult(
            text_hash=text_hash,
            score=max_score,
            verdict=verdict,
            scan_mode=scan_mode,
            thresholds_applied=mode_thresholds,
            chunks_analyzed=len(chunks),
            max_chunk_score=max_score,
            latency_ms=self._elapsed_ms(start),
            model_available=True,
            fallback_used=False,
        )

    # -- Batch Inference (APEP-425) ----------------------------------------

    async def classify_batch(
        self,
        request: BatchInferenceRequest,
    ) -> BatchInferenceResult:
        """Classify a batch of texts asynchronously.

        Runs inference in a thread pool to avoid blocking the event loop.
        """
        start = time.monotonic()

        if not self.is_available:
            return BatchInferenceResult(
                batch_id=request.batch_id,
                status=BatchJobStatus.COMPLETED,
                results=[
                    self.classify(t, request.scan_mode) for t in request.texts
                ],
                total_texts=len(request.texts),
                completed_texts=len(request.texts),
                total_latency_ms=self._elapsed_ms(start),
                completed_at=datetime.now(UTC),
            )

        loop = asyncio.get_event_loop()
        results: list[ONNXClassificationResult] = []

        try:
            for text in request.texts:
                result = await loop.run_in_executor(
                    None, self.classify, text, request.scan_mode
                )
                results.append(result)

            return BatchInferenceResult(
                batch_id=request.batch_id,
                status=BatchJobStatus.COMPLETED,
                results=results,
                total_texts=len(request.texts),
                completed_texts=len(results),
                total_latency_ms=self._elapsed_ms(start),
                completed_at=datetime.now(UTC),
            )

        except Exception as exc:
            logger.exception("Batch inference failed: %s", exc)
            return BatchInferenceResult(
                batch_id=request.batch_id,
                status=BatchJobStatus.FAILED,
                results=results,
                total_texts=len(request.texts),
                completed_texts=len(results),
                total_latency_ms=self._elapsed_ms(start),
                error=str(exc),
            )

    # -- Inference ----------------------------------------------------------

    def _infer(self, text: str) -> float:
        """Run ONNX inference on a single text string.

        Returns the injection probability score (0.0–1.0).
        """
        with self._lock:
            session = self._session
            tokenizer = self._tokenizer

        if session is None or tokenizer is None:
            return 0.0

        # Tokenize
        encoding = tokenizer.encode(text)
        input_ids = encoding.ids[:512]
        attention_mask = encoding.attention_mask[:512]

        # Pad to 512
        pad_len = 512 - len(input_ids)
        input_ids = input_ids + [0] * pad_len
        attention_mask = attention_mask + [0] * pad_len

        import numpy as np  # type: ignore[import-untyped]

        inputs = {
            "input_ids": np.array([input_ids], dtype=np.int64),
            "attention_mask": np.array([attention_mask], dtype=np.int64),
        }

        # Attempt to pass token_type_ids if the model expects them.
        input_names = {inp.name for inp in session.get_inputs()}
        if "token_type_ids" in input_names:
            inputs["token_type_ids"] = np.zeros_like(inputs["input_ids"])

        logits = session.run(None, inputs)[0][0]
        probs = _softmax(logits.tolist())

        # Assume binary classification: index 1 = injection probability
        injection_score = probs[1] if len(probs) > 1 else probs[0]
        return float(injection_score)

    # -- Threshold application (APEP-422) -----------------------------------

    @staticmethod
    def _apply_thresholds(
        score: float,
        thresholds: ONNXThresholds,
    ) -> ONNXClassificationVerdict:
        """Map a score to a verdict using the given thresholds."""
        if score >= thresholds.malicious:
            return ONNXClassificationVerdict.MALICIOUS
        if score >= thresholds.suspicious:
            return ONNXClassificationVerdict.SUSPICIOUS
        return ONNXClassificationVerdict.CLEAN

    # -- Fallback (APEP-424) -----------------------------------------------

    def _fallback_result(
        self,
        text_hash: str,
        scan_mode: str,
        thresholds: ONNXThresholds,
        start: float,
    ) -> ONNXClassificationResult:
        """Return a fallback result when the ONNX model is not available.

        The fallback reports ``model_available=False`` and ``fallback_used=True``
        with a CLEAN verdict and zero score.  The caller (pipeline integrator)
        should rely on Tier 0 regex results when the ONNX tier is degraded.
        """
        return ONNXClassificationResult(
            text_hash=text_hash,
            score=0.0,
            verdict=ONNXClassificationVerdict.CLEAN,
            scan_mode=scan_mode,
            thresholds_applied=thresholds,
            chunks_analyzed=0,
            max_chunk_score=0.0,
            latency_ms=self._elapsed_ms(start),
            model_available=False,
            fallback_used=True,
        )

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def _elapsed_ms(start: float) -> int:
        return int((time.monotonic() - start) * 1000)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

onnx_semantic_classifier = ONNXSemanticClassifier()
