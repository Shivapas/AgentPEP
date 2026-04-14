"""ONNXTextChunker — text chunking for long content (APEP-423).

Sprint 53: Splits long text into overlapping chunks suitable for the ONNX
MiniLM-L6-v2 classifier whose token limit is 512 tokens (~2048 characters).
Uses a sliding window with configurable overlap so that injection payloads
spanning chunk boundaries are not missed.

Strategy:
  1. If text fits within ``max_chunk_chars``, return a single chunk.
  2. Otherwise, split into overlapping windows of ``max_chunk_chars`` with
     ``overlap_chars`` overlap between consecutive windows.
  3. Prefer splitting at sentence boundaries (period, newline) within the
     overlap region to avoid cutting mid-word.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.onnx_classifier import TextChunk


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_MAX_CHUNK_CHARS = 2048
_DEFAULT_OVERLAP_CHARS = 200


# ---------------------------------------------------------------------------
# Chunker
# ---------------------------------------------------------------------------


@dataclass
class ONNXTextChunker:
    """Splits long text into overlapping chunks for ONNX inference.

    Parameters
    ----------
    max_chunk_chars:
        Maximum characters per chunk.  The MiniLM-L6-v2 tokenizer has a
        512-token limit which maps to roughly 2 048 characters in English.
    overlap_chars:
        Number of overlapping characters between consecutive chunks.
        Ensures injection payloads at chunk boundaries are captured.
    """

    max_chunk_chars: int = _DEFAULT_MAX_CHUNK_CHARS
    overlap_chars: int = _DEFAULT_OVERLAP_CHARS

    def chunk(self, text: str) -> list[TextChunk]:
        """Split *text* into chunks.

        Returns a list of :class:`TextChunk` objects.  For short texts that
        fit within a single chunk, a single-element list is returned.
        """
        if not text:
            return []

        text_len = len(text)
        if text_len <= self.max_chunk_chars:
            return [
                TextChunk(
                    text=text,
                    offset=0,
                    length=text_len,
                    chunk_index=0,
                )
            ]

        chunks: list[TextChunk] = []
        step = self.max_chunk_chars - self.overlap_chars
        if step <= 0:
            step = self.max_chunk_chars  # fallback: no overlap

        offset = 0
        idx = 0
        while offset < text_len:
            end = min(offset + self.max_chunk_chars, text_len)
            chunk_text = text[offset:end]

            # Try to find a sentence boundary in the overlap region to make
            # a cleaner split.  Only adjust if we're not at the end of text.
            if end < text_len:
                boundary_start = max(0, len(chunk_text) - self.overlap_chars)
                boundary_region = chunk_text[boundary_start:]
                # Search for last sentence-ending character in the overlap region.
                best_split = -1
                for sep in ("\n", ". ", "? ", "! "):
                    pos = boundary_region.rfind(sep)
                    if pos != -1:
                        candidate = boundary_start + pos + len(sep)
                        if candidate > best_split:
                            best_split = candidate

                if best_split > 0:
                    chunk_text = chunk_text[:best_split]
                    end = offset + best_split

            chunks.append(
                TextChunk(
                    text=chunk_text,
                    offset=offset,
                    length=len(chunk_text),
                    chunk_index=idx,
                )
            )
            idx += 1

            # Advance by step, but never go backwards
            next_offset = offset + step
            if next_offset <= offset:
                next_offset = offset + 1
            offset = next_offset

        return chunks


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

onnx_text_chunker = ONNXTextChunker()
