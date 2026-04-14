"""ONNXBenchmark — benchmark ONNX classifier against ToolTrust metrics (APEP-426).

Sprint 53: Provides a benchmarking framework to validate the ONNX semantic
classifier's F1 score against the ToolTrust published target of 94.3%.

The benchmark runs the classifier against a labeled dataset (each entry has
``text`` and ``label`` where 0=benign, 1=injection) and computes precision,
recall, F1, and per-sample latency.

Usage:
  1. Provide a dataset via :meth:`run` (list of BenchmarkDatasetEntry).
  2. The classifier is invoked on each sample.
  3. Results are compared against ground truth.
  4. A :class:`BenchmarkResult` is returned with full metrics.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime

from app.models.onnx_classifier import (
    BenchmarkDatasetEntry,
    BenchmarkResult,
    ONNXClassificationVerdict,
)
from app.services.onnx_semantic_classifier import (
    ONNXSemanticClassifier,
    onnx_semantic_classifier,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ToolTrust published target
# ---------------------------------------------------------------------------

_TOOLTRUST_F1_TARGET = 0.943  # 94.3% F1


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------


class ONNXBenchmark:
    """Benchmarks the ONNX classifier against a labeled dataset.

    Parameters
    ----------
    classifier:
        The ONNX classifier to benchmark.  Defaults to the module singleton.
    target_f1:
        F1 target to validate against (default: ToolTrust 94.3%).
    """

    def __init__(
        self,
        classifier: ONNXSemanticClassifier | None = None,
        target_f1: float = _TOOLTRUST_F1_TARGET,
    ) -> None:
        self._classifier = classifier or onnx_semantic_classifier
        self._target_f1 = target_f1

    def run(
        self,
        dataset: list[BenchmarkDatasetEntry],
        scan_mode: str = "STANDARD",
        dataset_name: str = "",
    ) -> BenchmarkResult:
        """Run the benchmark on *dataset* and return metrics.

        Parameters
        ----------
        dataset:
            List of labeled samples (text + label).
        scan_mode:
            Scan mode for threshold application.
        dataset_name:
            Human-readable name for the dataset.
        """
        if not dataset:
            return BenchmarkResult(
                dataset_name=dataset_name,
                scan_mode=scan_mode,
                target_f1=self._target_f1,
            )

        tp = fp = tn = fn = 0
        total_latency_ms = 0.0

        for entry in dataset:
            start = time.monotonic()
            result = self._classifier.classify(entry.text, scan_mode=scan_mode)
            elapsed = (time.monotonic() - start) * 1000
            total_latency_ms += elapsed

            # Predicted positive if SUSPICIOUS or MALICIOUS
            predicted_positive = result.verdict in (
                ONNXClassificationVerdict.SUSPICIOUS,
                ONNXClassificationVerdict.MALICIOUS,
            )
            actual_positive = entry.label == 1

            if predicted_positive and actual_positive:
                tp += 1
            elif predicted_positive and not actual_positive:
                fp += 1
            elif not predicted_positive and actual_positive:
                fn += 1
            else:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        avg_latency = total_latency_ms / len(dataset) if dataset else 0.0

        result = BenchmarkResult(
            dataset_name=dataset_name,
            total_samples=len(dataset),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            target_f1=self._target_f1,
            meets_target=f1 >= self._target_f1,
            avg_latency_ms=round(avg_latency, 2),
            scan_mode=scan_mode,
            run_at=datetime.now(UTC),
        )

        logger.info(
            "Benchmark %s: F1=%.4f (target=%.4f) %s — %d samples, %.1fms avg",
            dataset_name,
            f1,
            self._target_f1,
            "PASS" if result.meets_target else "FAIL",
            len(dataset),
            avg_latency,
        )

        return result


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

onnx_benchmark = ONNXBenchmark()
