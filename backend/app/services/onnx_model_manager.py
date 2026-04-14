"""ONNXModelManager — model download and SHA-256 verification (APEP-421).

Sprint 53: Manages the lifecycle of the ONNX MiniLM-L6-v2 injection
classifier model.  Downloads the model from a configurable URL, verifies
its SHA-256 hash, and reports readiness status.

The model is stored at ``/opt/agentpep/models/`` by default (overridable
via ``ONNX_MODEL_DIR`` environment variable).

Security:
  - SHA-256 verification prevents tampered models from loading.
  - Download uses ``httpx`` with timeout and size limits.
  - Model status transitions are thread-safe.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from datetime import UTC, datetime
from pathlib import Path

from app.models.onnx_classifier import ONNXModelInfo, ONNXModelStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_MODEL_DIR = os.environ.get("ONNX_MODEL_DIR", "/opt/agentpep/models")
_DEFAULT_MODEL_FILENAME = "injection_classifier.onnx"
_DEFAULT_TOKENIZER_DIR = "tokenizer"
_MAX_MODEL_SIZE_BYTES = 200 * 1024 * 1024  # 200 MB safety limit
_DOWNLOAD_TIMEOUT_S = 120


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class ONNXModelManager:
    """Manages ONNX model download, verification, and lifecycle status.

    Parameters
    ----------
    model_dir:
        Directory where the model and tokenizer are stored.
    expected_sha256:
        Expected SHA-256 hash of the model file.  If empty, verification
        is skipped (development mode only).
    """

    def __init__(
        self,
        model_dir: str = _DEFAULT_MODEL_DIR,
        expected_sha256: str = "",
    ) -> None:
        self._model_dir = Path(model_dir)
        self._expected_sha256 = expected_sha256
        self._lock = threading.Lock()
        self._info = ONNXModelInfo(
            model_path=str(self._model_dir / _DEFAULT_MODEL_FILENAME),
            tokenizer_path=str(self._model_dir / _DEFAULT_TOKENIZER_DIR),
            expected_sha256=expected_sha256,
        )

        # Probe local filesystem on init
        self._check_local()

    # -- Public API ---------------------------------------------------------

    @property
    def info(self) -> ONNXModelInfo:
        """Return current model metadata (snapshot)."""
        with self._lock:
            return self._info.model_copy()

    @property
    def is_ready(self) -> bool:
        """Return ``True`` if the model is verified and ready for inference."""
        with self._lock:
            return self._info.status == ONNXModelStatus.READY

    @property
    def model_path(self) -> Path:
        """Filesystem path to the ONNX model file."""
        return self._model_dir / _DEFAULT_MODEL_FILENAME

    @property
    def tokenizer_path(self) -> Path:
        """Filesystem path to the tokenizer directory."""
        return self._model_dir / _DEFAULT_TOKENIZER_DIR

    def verify(self) -> bool:
        """Verify the model's SHA-256 hash.

        Returns ``True`` if the hash matches the expected value, or if no
        expected hash was configured (development mode).

        Raises
        ------
        FileNotFoundError
            If the model file does not exist.
        """
        model_path = self.model_path
        if not model_path.is_file():
            raise FileNotFoundError(f"ONNX model not found at {model_path}")

        actual_hash = self._compute_sha256(model_path)
        file_size = model_path.stat().st_size

        with self._lock:
            self._info = self._info.model_copy(
                update={
                    "actual_sha256": actual_hash,
                    "file_size_bytes": file_size,
                }
            )

            if not self._expected_sha256:
                # No expected hash — accept model (development mode).
                self._info = self._info.model_copy(
                    update={
                        "status": ONNXModelStatus.READY,
                        "verified_at": datetime.now(UTC),
                    }
                )
                logger.warning(
                    "ONNX model loaded without SHA-256 verification (dev mode)"
                )
                return True

            if actual_hash == self._expected_sha256:
                self._info = self._info.model_copy(
                    update={
                        "status": ONNXModelStatus.READY,
                        "verified_at": datetime.now(UTC),
                    }
                )
                logger.info("ONNX model SHA-256 verified: %s", actual_hash[:16])
                return True

            self._info = self._info.model_copy(
                update={"status": ONNXModelStatus.FAILED}
            )
            logger.error(
                "ONNX model SHA-256 mismatch: expected=%s actual=%s",
                self._expected_sha256[:16],
                actual_hash[:16],
            )
            return False

    async def download(self, url: str) -> bool:
        """Download the ONNX model from *url* and verify its hash.

        Returns ``True`` if the model was downloaded and verified successfully.
        """
        import httpx

        with self._lock:
            self._info = self._info.model_copy(
                update={"status": ONNXModelStatus.DOWNLOADING}
            )

        try:
            self._model_dir.mkdir(parents=True, exist_ok=True)
            dest = self.model_path

            async with httpx.AsyncClient(timeout=_DOWNLOAD_TIMEOUT_S) as client:
                response = await client.get(url, follow_redirects=True)
                response.raise_for_status()

                content = response.content
                if len(content) > _MAX_MODEL_SIZE_BYTES:
                    raise ValueError(
                        f"Model size {len(content)} exceeds limit "
                        f"{_MAX_MODEL_SIZE_BYTES}"
                    )

                dest.write_bytes(content)

            with self._lock:
                self._info = self._info.model_copy(
                    update={
                        "status": ONNXModelStatus.VERIFYING,
                        "downloaded_at": datetime.now(UTC),
                        "file_size_bytes": len(content),
                    }
                )

            return self.verify()

        except Exception as exc:
            logger.exception("ONNX model download failed: %s", exc)
            with self._lock:
                self._info = self._info.model_copy(
                    update={"status": ONNXModelStatus.FAILED}
                )
            return False

    # -- Internal -----------------------------------------------------------

    def _check_local(self) -> None:
        """Check if the model file already exists on disk."""
        model_path = self.model_path
        if model_path.is_file():
            try:
                self.verify()
            except Exception:
                logger.debug("ONNX model not found at %s", model_path)
        else:
            logger.info(
                "ONNX model not installed at %s — Tier 1 will use fallback",
                model_path,
            )

    @staticmethod
    def _compute_sha256(path: Path) -> str:
        """Compute the SHA-256 hex digest of a file."""
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                block = f.read(65536)
                if not block:
                    break
                sha.update(block)
        return sha.hexdigest()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

onnx_model_manager = ONNXModelManager()
