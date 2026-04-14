"""Echo Detector — Sprint 35 (APEP-279).

Identifies repeated or near-duplicate patterns in tool call arguments
that suggest prompt manipulation, replay attacks, or repetitive injection
attempts.

Uses a combination of exact hash matching and Jaccard similarity on
tokenised argument strings to detect both identical and near-duplicate
submissions.

Scoring logic:
  - 3+ exact repeats in window → 0.9
  - 2 exact repeats            → 0.6
  - Near-duplicates > threshold → 0.4 * (count / window_size)
  - No echoes                   → 0.0
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

from app.db import mongodb as db_module

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class EchoResult:
    """Result of an echo detection check."""

    is_echo: bool
    exact_repeats: int
    near_duplicates: int
    max_similarity: float
    risk_score: float
    detail: str


class EchoDetector:
    """Detect repeated or near-duplicate tool call arguments in a session.

    Fetches recent audit history and compares the current tool call's
    arguments against previous calls to detect echo patterns.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.85,
        window_size: int = 20,
    ) -> None:
        self.similarity_threshold = similarity_threshold
        self.window_size = window_size

    async def check(
        self,
        session_id: str,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> EchoResult:
        """Check if the current tool call arguments echo recent calls.

        Args:
            session_id: Current session to scan.
            tool_name: The tool being called.
            tool_args: Arguments for the current call.

        Returns:
            EchoResult with repetition counts and risk score.
        """
        current_str = self._args_to_string(tool_args)
        current_hash = self._hash_args(current_str)

        recent_hashes, recent_args = await self._fetch_recent_args(
            session_id, self.window_size
        )

        # Exact repetition detection
        exact_repeats = self._detect_exact_repetition(current_hash, recent_hashes)

        # Near-duplicate detection
        similarities = self._detect_near_duplicates(current_str, recent_args)
        near_duplicates = len(similarities)
        max_similarity = max(similarities) if similarities else 0.0

        # Compute risk score
        risk_score = self._compute_risk_score(
            exact_repeats, near_duplicates, self.window_size
        )
        is_echo = risk_score > 0.0

        # Build detail string
        if exact_repeats >= 3:
            detail = f"High echo: {exact_repeats} exact repeats in last {self.window_size} calls"
        elif exact_repeats >= 2:
            detail = f"Echo detected: {exact_repeats} exact repeats in last {self.window_size} calls"
        elif near_duplicates > 0:
            detail = (
                f"Near-duplicate detected: {near_duplicates} similar args "
                f"(max similarity={max_similarity:.2f})"
            )
        else:
            detail = "No echo patterns detected"

        return EchoResult(
            is_echo=is_echo,
            exact_repeats=exact_repeats,
            near_duplicates=near_duplicates,
            max_similarity=max_similarity,
            risk_score=risk_score,
            detail=detail,
        )

    @staticmethod
    def _compute_risk_score(
        exact_repeats: int, near_duplicates: int, window_size: int
    ) -> float:
        """Map echo counts to a [0, 1] risk score."""
        if exact_repeats >= 3:
            return 0.9
        if exact_repeats >= 2:
            return 0.6
        if near_duplicates > 0 and window_size > 0:
            return min(0.4 * (near_duplicates / window_size), 0.4)
        return 0.0

    @staticmethod
    def _detect_exact_repetition(
        current_hash: str, recent_hashes: list[str]
    ) -> int:
        """Count how many recent calls have the exact same argument hash."""
        return sum(1 for h in recent_hashes if h == current_hash)

    def _detect_near_duplicates(
        self, current_args: str, recent_args: list[str]
    ) -> list[float]:
        """Return similarity scores for near-matches above threshold."""
        similarities: list[float] = []
        for past_args in recent_args:
            sim = self._compute_similarity(current_args, past_args)
            if sim >= self.similarity_threshold and sim < 1.0:
                similarities.append(sim)
        return similarities

    @staticmethod
    def _compute_similarity(args_a: str, args_b: str) -> float:
        """Compute Jaccard similarity between two argument strings.

        Tokenises each string by splitting on whitespace and punctuation,
        then computes |intersection| / |union|.
        """
        if not args_a or not args_b:
            return 0.0
        if args_a == args_b:
            return 1.0

        tokens_a = set(args_a.lower().split())
        tokens_b = set(args_b.lower().split())

        if not tokens_a or not tokens_b:
            return 0.0

        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union)

    @staticmethod
    def _args_to_string(args: dict[str, Any]) -> str:
        """Convert a tool_args dict to a canonical string for comparison."""
        try:
            return json.dumps(args, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return str(args)

    @staticmethod
    def _hash_args(args_str: str) -> str:
        """Compute SHA-256 hash of the canonical argument string."""
        return hashlib.sha256(args_str.encode("utf-8")).hexdigest()

    @staticmethod
    async def _fetch_recent_args(
        session_id: str,
        limit: int,
    ) -> tuple[list[str], list[str]]:
        """Fetch hashes and flattened args from recent audit decisions.

        Returns (list_of_hashes, list_of_arg_strings).
        """
        try:
            db = db_module.get_database()
            cursor = (
                db[db_module.AUDIT_DECISIONS]
                .find(
                    {"session_id": session_id},
                    {"tool_args_hash": 1, "tool_args": 1, "_id": 0},
                )
                .sort("timestamp", -1)
                .limit(limit)
            )
            hashes: list[str] = []
            arg_strings: list[str] = []
            async for doc in cursor:
                h = doc.get("tool_args_hash", "")
                if h:
                    hashes.append(h)
                args = doc.get("tool_args")
                if args:
                    try:
                        arg_strings.append(
                            json.dumps(args, sort_keys=True, default=str)
                        )
                    except (TypeError, ValueError):
                        arg_strings.append(str(args))
            return hashes, arg_strings
        except Exception:
            logger.warning(
                "Failed to fetch recent args for echo detection",
                exc_info=True,
            )
            return [], []


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

echo_detector = EchoDetector()
