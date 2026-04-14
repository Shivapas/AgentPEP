"""Subsequence Matching Engine — Sprint 49 (APEP-389).

Provides configurable subsequence matching algorithms for detecting
tool call chain patterns against session history.  Supports three
matching strategies:

  - EXACT:          Steps must appear consecutively with no gaps.
  - SUBSEQUENCE:    Steps must appear in order, with configurable max
                    gap between consecutive matched steps.
  - SLIDING_WINDOW: Steps must appear in order within a sliding time
                    window, allowing re-evaluation from multiple start
                    positions.

The engine is stateless — it receives tool history and patterns,
returning match results.
"""

from __future__ import annotations

import logging
import time
from fnmatch import fnmatch

from app.models.tool_call_chain import (
    ChainMatchedStep,
    ChainMatchResult,
    ChainMatchStrategy,
    ToolCallChainPattern,
)
from app.services.tool_combination_detector import ToolCallRecord

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Matching engine
# ---------------------------------------------------------------------------


class SubsequenceMatchingEngine:
    """Matches tool call history against chain patterns (APEP-389).

    Delegates to the appropriate matching strategy based on the pattern's
    ``match_strategy`` field.  All strategies respect the pattern's
    ``window_seconds`` time constraint.
    """

    def match(
        self,
        history: list[ToolCallRecord],
        pattern: ToolCallChainPattern,
    ) -> ChainMatchResult | None:
        """Attempt to match a pattern against tool call history.

        Returns a ChainMatchResult if the pattern matches, None otherwise.
        """
        if not history or not pattern.steps or not pattern.enabled:
            return None

        if pattern.match_strategy == ChainMatchStrategy.EXACT:
            return self._match_exact(history, pattern)
        elif pattern.match_strategy == ChainMatchStrategy.SLIDING_WINDOW:
            return self._match_sliding_window(history, pattern)
        else:
            # Default: SUBSEQUENCE
            return self._match_subsequence(history, pattern)

    def match_all(
        self,
        history: list[ToolCallRecord],
        patterns: list[ToolCallChainPattern],
    ) -> list[ChainMatchResult]:
        """Match all patterns against history, returning all matches."""
        results: list[ChainMatchResult] = []
        for pattern in patterns:
            result = self.match(history, pattern)
            if result is not None:
                results.append(result)
        return results

    # -- SUBSEQUENCE strategy (default) -----------------------------------

    def _match_subsequence(
        self,
        history: list[ToolCallRecord],
        pattern: ToolCallChainPattern,
    ) -> ChainMatchResult | None:
        """Match using subsequence strategy with gap constraints.

        Steps must appear in order within the time window.  Between
        consecutive matched steps, at most ``max_gap`` intervening
        (non-matching) tool calls are allowed.  Optional steps may be
        skipped.
        """
        required_steps = [s for s in pattern.steps if not s.optional]
        if not required_steps:
            return None

        for start_idx in range(len(history)):
            result = self._try_subsequence_from(history, pattern, start_idx)
            if result is not None:
                return result

        return None

    def _try_subsequence_from(
        self,
        history: list[ToolCallRecord],
        pattern: ToolCallChainPattern,
        start_idx: int,
    ) -> ChainMatchResult | None:
        """Try to match the pattern starting from a given history index."""
        steps = pattern.steps
        first_step = steps[0]

        if not fnmatch(history[start_idx].tool_name, first_step.tool_pattern):
            return None

        anchor_time = history[start_idx].timestamp
        matched: list[ChainMatchedStep] = [
            ChainMatchedStep(
                step_index=0,
                tool_name=history[start_idx].tool_name,
                tool_pattern=first_step.tool_pattern,
                timestamp=history[start_idx].timestamp,
                gap=0,
            )
        ]

        step_idx = 1
        gap_count = 0

        for hist_idx in range(start_idx + 1, len(history)):
            record = history[hist_idx]

            # Check time window
            if record.timestamp - anchor_time > pattern.window_seconds:
                break

            if step_idx >= len(steps):
                break

            current_step = steps[step_idx]

            if fnmatch(record.tool_name, current_step.tool_pattern):
                # Current history record matches the current step
                matched.append(
                    ChainMatchedStep(
                        step_index=step_idx,
                        tool_name=record.tool_name,
                        tool_pattern=current_step.tool_pattern,
                        timestamp=record.timestamp,
                        gap=gap_count,
                    )
                )
                step_idx += 1
                gap_count = 0
            else:
                # Current history record does NOT match the current step.
                # If the current step is optional, try skipping it and
                # checking if this record matches the NEXT step instead.
                skipped = False
                if current_step.optional:
                    peek_idx = step_idx + 1
                    while peek_idx < len(steps):
                        next_step = steps[peek_idx]
                        if fnmatch(record.tool_name, next_step.tool_pattern):
                            # Skip the optional step(s) and match here
                            matched.append(
                                ChainMatchedStep(
                                    step_index=peek_idx,
                                    tool_name=record.tool_name,
                                    tool_pattern=next_step.tool_pattern,
                                    timestamp=record.timestamp,
                                    gap=gap_count,
                                )
                            )
                            step_idx = peek_idx + 1
                            gap_count = 0
                            skipped = True
                            break
                        elif next_step.optional:
                            peek_idx += 1
                        else:
                            break

                if not skipped:
                    gap_count += 1
                    # Check max_gap for required steps
                    if not current_step.optional and gap_count > current_step.max_gap:
                        break

        # Check if remaining steps at end can be skipped (all optional)
        while step_idx < len(steps) and steps[step_idx].optional:
            step_idx += 1

        if step_idx < len(steps):
            return None

        # Build result
        chain_duration = (
            matched[-1].timestamp - matched[0].timestamp if len(matched) > 1 else 0.0
        )
        confidence = len(matched) / len(steps)

        return ChainMatchResult(
            pattern_id=pattern.pattern_id,
            pattern_name=pattern.name,
            category=pattern.category,
            severity=pattern.severity,
            action=pattern.action,
            risk_boost=pattern.risk_boost,
            matched_steps=matched,
            match_strategy=pattern.match_strategy,
            chain_duration_s=chain_duration,
            mitre_technique_id=pattern.mitre_technique_id,
            description=pattern.description,
            confidence=confidence,
        )

    # -- EXACT strategy ----------------------------------------------------

    def _match_exact(
        self,
        history: list[ToolCallRecord],
        pattern: ToolCallChainPattern,
    ) -> ChainMatchResult | None:
        """Match using exact strategy — steps must be consecutive.

        No gaps allowed between matched steps, optional steps are
        still skippable.
        """
        required_indices = [
            i for i, s in enumerate(pattern.steps) if not s.optional
        ]
        required_count = len(required_indices)

        for start_idx in range(len(history)):
            if not fnmatch(
                history[start_idx].tool_name, pattern.steps[0].tool_pattern
            ):
                continue

            anchor_time = history[start_idx].timestamp
            matched: list[ChainMatchedStep] = [
                ChainMatchedStep(
                    step_index=0,
                    tool_name=history[start_idx].tool_name,
                    tool_pattern=pattern.steps[0].tool_pattern,
                    timestamp=history[start_idx].timestamp,
                    gap=0,
                )
            ]

            step_idx = 1
            hist_idx = start_idx + 1

            while step_idx < len(pattern.steps) and hist_idx < len(history):
                record = history[hist_idx]

                if record.timestamp - anchor_time > pattern.window_seconds:
                    break

                current_step = pattern.steps[step_idx]
                if fnmatch(record.tool_name, current_step.tool_pattern):
                    matched.append(
                        ChainMatchedStep(
                            step_index=step_idx,
                            tool_name=record.tool_name,
                            tool_pattern=current_step.tool_pattern,
                            timestamp=record.timestamp,
                            gap=0,
                        )
                    )
                    step_idx += 1
                elif current_step.optional:
                    step_idx += 1
                    continue  # Don't advance hist_idx for skipped optional
                else:
                    break  # Gap not allowed in EXACT mode

                hist_idx += 1

            # Skip remaining optional steps
            while step_idx < len(pattern.steps) and pattern.steps[step_idx].optional:
                step_idx += 1

            if step_idx >= len(pattern.steps):
                chain_duration = (
                    matched[-1].timestamp - matched[0].timestamp
                    if len(matched) > 1
                    else 0.0
                )
                return ChainMatchResult(
                    pattern_id=pattern.pattern_id,
                    pattern_name=pattern.name,
                    category=pattern.category,
                    severity=pattern.severity,
                    action=pattern.action,
                    risk_boost=pattern.risk_boost,
                    matched_steps=matched,
                    match_strategy=ChainMatchStrategy.EXACT,
                    chain_duration_s=chain_duration,
                    mitre_technique_id=pattern.mitre_technique_id,
                    description=pattern.description,
                    confidence=1.0,
                )

        return None

    # -- SLIDING_WINDOW strategy -------------------------------------------

    def _match_sliding_window(
        self,
        history: list[ToolCallRecord],
        pattern: ToolCallChainPattern,
    ) -> ChainMatchResult | None:
        """Match using sliding window — re-evaluate from each start position.

        Similar to SUBSEQUENCE but tries all possible starting positions
        for the first step, allowing detection of chains that overlap
        with other activity.
        """
        best_result: ChainMatchResult | None = None
        best_confidence: float = 0.0

        for start_idx in range(len(history)):
            result = self._try_subsequence_from(history, pattern, start_idx)
            if result is not None and result.confidence > best_confidence:
                best_result = result
                best_confidence = result.confidence

        if best_result is not None:
            # Override the strategy in the result
            best_result = best_result.model_copy(
                update={"match_strategy": ChainMatchStrategy.SLIDING_WINDOW}
            )

        return best_result


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

subsequence_matcher = SubsequenceMatchingEngine()
