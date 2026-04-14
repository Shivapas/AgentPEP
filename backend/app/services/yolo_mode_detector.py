"""YOLO mode detector — detects agents running in unrestricted / YOLO mode.

Sprint 52 — APEP-417: Identifies when an AI agent or tool-use session is
operating in "YOLO mode" — i.e. executing tool calls without human approval,
policy checks, or safety guards.  Detection is based on:

  1. **Explicit flags** — session metadata or headers declaring YOLO / auto-approve.
  2. **Behavioural signals** — rapid-fire tool calls with zero human-in-the-loop
     latency, or calls that bypass the intercept endpoint entirely.
  3. **Prompt signals** — prompt content containing YOLO-mode keywords.

When YOLO mode is detected, the detector returns a :class:`YOLODetection`
result that can be used to:
  - Auto-escalate to STRICT scan mode in the ScanModeRouter.
  - Emit a Kafka event for audit/observability.
  - Log a CRITICAL-severity finding.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Detection result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class YOLODetection:
    """Result of a YOLO-mode detection check."""

    detected: bool
    signals: list[str]  # human-readable reasons
    severity: str = "CRITICAL"  # always CRITICAL when detected
    recommended_mode: str = "STRICT"


# ---------------------------------------------------------------------------
# Compiled prompt-level patterns
# ---------------------------------------------------------------------------

_YOLO_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?i)\byolo\s*mode\b"),
        "Explicit 'yolo mode' keyword in prompt",
    ),
    (
        re.compile(r"(?i)\bauto[-_\s]?approve\s+(all|every|any)\b"),
        "Auto-approve all directive detected",
    ),
    (
        re.compile(r"(?i)\b(skip|bypass|disable)\s+(all\s+)?(confirmation|approval|review|human)s?\b"),
        "Directive to skip human confirmation",
    ),
    (
        re.compile(r"(?i)\b(execute|run|do)\s+(everything|all|anything)\s+without\s+(asking|confirmation|approval|checking)\b"),
        "Execute-without-asking directive",
    ),
    (
        re.compile(r"(?i)\bno[-_\s]?(human|manual)[-_\s]?(in[-_\s]?the[-_\s]?loop|review|oversight|approval)\b"),
        "No-human-in-the-loop directive",
    ),
    (
        re.compile(r"(?i)\btrust\s+(all|every|any)\s+(tool|action|command|function)\s+(call|execution)s?\b"),
        "Blanket tool-trust directive",
    ),
    (
        re.compile(r"(?i)\b(fully\s+)?autonomous\s+mode\b"),
        "Autonomous mode activation keyword",
    ),
    (
        re.compile(r"(?i)\baccept[-_\s]?all[-_\s]?(risk|action|tool)s?\b"),
        "Accept-all-risks directive",
    ),
]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class YOLOModeDetector:
    """Detects YOLO / unrestricted mode operation.

    Parameters
    ----------
    rapid_call_threshold_s:
        Minimum inter-call latency (in seconds) below which tool calls are
        considered suspiciously fast (indicative of no human review).
        Default 0.5 s.
    rapid_call_window:
        Number of consecutive rapid calls required to trigger a behavioural
        detection.  Default 5.
    """

    def __init__(
        self,
        rapid_call_threshold_s: float = 0.5,
        rapid_call_window: int = 5,
    ) -> None:
        self._rapid_threshold = rapid_call_threshold_s
        self._rapid_window = rapid_call_window
        # Per-session timestamps of recent tool calls (session_id → list[float]).
        self._call_times: dict[str, list[float]] = {}

    # -- Public API ---------------------------------------------------------

    def check_prompt(self, text: str) -> YOLODetection:
        """Scan *text* for YOLO-mode prompt-level signals."""
        signals: list[str] = []
        for pattern, description in _YOLO_PATTERNS:
            if pattern.search(text):
                signals.append(description)
        return YOLODetection(
            detected=len(signals) > 0,
            signals=signals,
        )

    def check_metadata(self, metadata: dict[str, object]) -> YOLODetection:
        """Check session/request metadata for YOLO-mode flags.

        Looks for common flag names: ``yolo``, ``auto_approve``,
        ``skip_confirmation``, ``autonomous``, ``no_hitl``.
        """
        flag_keys = {"yolo", "auto_approve", "skip_confirmation", "autonomous", "no_hitl"}
        signals: list[str] = []
        for key in flag_keys:
            val = metadata.get(key)
            if val is True or val == "true" or val == "1" or val == 1:
                signals.append(f"Metadata flag '{key}' is enabled")
        return YOLODetection(
            detected=len(signals) > 0,
            signals=signals,
        )

    def record_tool_call(self, session_id: str) -> YOLODetection:
        """Record a tool call timestamp and check for rapid-fire behaviour.

        Call this each time a tool call is executed for a session.  If the
        last *rapid_call_window* calls all occurred within
        *rapid_call_threshold_s* of each other, YOLO mode is flagged.
        """
        now = time.monotonic()
        times = self._call_times.setdefault(session_id, [])
        times.append(now)

        # Only keep the last N+1 timestamps.
        if len(times) > self._rapid_window + 1:
            self._call_times[session_id] = times[-self._rapid_window - 1 :]
            times = self._call_times[session_id]

        if len(times) < self._rapid_window + 1:
            return YOLODetection(detected=False, signals=[])

        # Check that the last N inter-call gaps are all below threshold.
        recent = times[-self._rapid_window - 1 :]
        gaps = [recent[i + 1] - recent[i] for i in range(len(recent) - 1)]
        if all(g < self._rapid_threshold for g in gaps):
            return YOLODetection(
                detected=True,
                signals=[
                    f"{self._rapid_window} consecutive tool calls with "
                    f"<{self._rapid_threshold}s inter-call latency"
                ],
            )
        return YOLODetection(detected=False, signals=[])

    def check_all(
        self,
        text: str = "",
        metadata: dict[str, object] | None = None,
        session_id: str | None = None,
    ) -> YOLODetection:
        """Run all YOLO detection checks and merge results."""
        signals: list[str] = []

        if text:
            prompt_result = self.check_prompt(text)
            signals.extend(prompt_result.signals)

        if metadata:
            meta_result = self.check_metadata(metadata)
            signals.extend(meta_result.signals)

        if session_id:
            behaviour_result = self.record_tool_call(session_id)
            signals.extend(behaviour_result.signals)

        return YOLODetection(
            detected=len(signals) > 0,
            signals=signals,
        )

    def clear_session(self, session_id: str) -> None:
        """Remove recorded call times for a session."""
        self._call_times.pop(session_id, None)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

yolo_detector = YOLOModeDetector()
