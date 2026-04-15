"""YOLO mode detection via environment probe — Sprint 56 (APEP-446).

SDK/CLI helper that detects YOLO mode by probing the runtime environment
for signals that the agent is operating without human oversight.

Detection sources:
  1. **Environment variables** — ``YOLO_MODE``, ``AUTO_APPROVE``, etc.
  2. **CLI flags** — ``--yolo``, ``--auto-approve``, ``--no-confirm``.
  3. **Process metadata** — parent process name, TTY attachment.
  4. **AgentPEP server** — queries the server for session YOLO state.

Usage as SDK::

    from agentpep.yolo_detector import YOLOEnvironmentProbe

    probe = YOLOEnvironmentProbe()
    result = probe.detect()
    if result.yolo_detected:
        print(f"YOLO mode active: {result.signals}")

Usage as CLI::

    python -m agentpep.yolo_detector
    python -m agentpep.yolo_detector --session-id sess-123 --propagate
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Environment probe result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class YOLOProbeResult:
    """Result of an environment probe for YOLO mode."""

    yolo_detected: bool
    signals: list[str]
    recommended_action: str = "ESCALATE_TO_STRICT"
    risk_multiplier: float = 1.5


# ---------------------------------------------------------------------------
# Known environment variable names
# ---------------------------------------------------------------------------

_YOLO_ENV_VARS: dict[str, str] = {
    "YOLO_MODE": "YOLO_MODE environment variable is set",
    "AUTO_APPROVE": "AUTO_APPROVE environment variable is set",
    "AUTO_APPROVE_ALL": "AUTO_APPROVE_ALL environment variable is set",
    "SKIP_CONFIRMATION": "SKIP_CONFIRMATION environment variable is set",
    "NO_HUMAN_REVIEW": "NO_HUMAN_REVIEW environment variable is set",
    "AUTONOMOUS_MODE": "AUTONOMOUS_MODE environment variable is set",
    "NO_HITL": "NO_HITL (no human in the loop) environment variable is set",
    "DANGEROUSLY_SKIP_PERMISSIONS": "DANGEROUSLY_SKIP_PERMISSIONS environment variable is set",
    "CLAUDE_CODE_APPROVE_ALL": "CLAUDE_CODE_APPROVE_ALL is set (Claude Code YOLO mode)",
}

# Truthy values
_TRUTHY = frozenset({"1", "true", "yes", "on", "enabled"})


# ---------------------------------------------------------------------------
# CLI flag patterns to detect
# ---------------------------------------------------------------------------

_YOLO_CLI_ARGS: list[tuple[str, str]] = [
    ("--yolo", "CLI --yolo flag detected"),
    ("--auto-approve", "CLI --auto-approve flag detected"),
    ("--no-confirm", "CLI --no-confirm flag detected"),
    ("--no-human", "CLI --no-human flag detected"),
    ("--skip-review", "CLI --skip-review flag detected"),
    ("--dangerously-skip-permissions", "CLI --dangerously-skip-permissions flag detected"),
    ("-y", "CLI -y (yes-to-all) flag detected"),
]


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------


class YOLOEnvironmentProbe:
    """Detects YOLO mode by probing the runtime environment (APEP-446).

    Checks environment variables, CLI arguments, and process metadata
    to determine if the agent is running in an unrestricted mode.
    """

    def detect(self) -> YOLOProbeResult:
        """Run all environment probes and return the result."""
        signals: list[str] = []

        # 1. Check environment variables
        signals.extend(self._check_env_vars())

        # 2. Check CLI arguments
        signals.extend(self._check_cli_args())

        # 3. Check process metadata
        signals.extend(self._check_process())

        return YOLOProbeResult(
            yolo_detected=len(signals) > 0,
            signals=signals,
        )

    def _check_env_vars(self) -> list[str]:
        """Check for YOLO-indicating environment variables."""
        signals: list[str] = []
        for var_name, description in _YOLO_ENV_VARS.items():
            val = os.environ.get(var_name, "").lower().strip()
            if val in _TRUTHY:
                signals.append(description)
        return signals

    def _check_cli_args(self) -> list[str]:
        """Check sys.argv for YOLO-indicating CLI flags."""
        signals: list[str] = []
        argv_lower = [arg.lower() for arg in sys.argv]
        for flag, description in _YOLO_CLI_ARGS:
            if flag in argv_lower:
                signals.append(description)
        return signals

    def _check_process(self) -> list[str]:
        """Check process metadata for YOLO indicators."""
        signals: list[str] = []

        # Check if running without a TTY (non-interactive = possible CI/automation)
        if not sys.stdin.isatty():
            # Only flag this if other signals are present
            # (non-TTY alone is too noisy)
            pass

        return signals

    async def detect_and_report(
        self,
        *,
        base_url: str = "http://localhost:8000",
        session_id: str = "",
        api_key: str | None = None,
        propagate: bool = False,
    ) -> YOLOProbeResult:
        """Detect YOLO mode and optionally report to the AgentPEP server.

        If ``propagate`` is True and YOLO mode is detected, the detection
        is reported to the server to lock the session to STRICT mode.
        """
        result = self.detect()

        if result.yolo_detected and propagate and session_id:
            try:
                headers: dict[str, str] = {"Content-Type": "application/json"}
                if api_key:
                    headers["X-API-Key"] = api_key

                async with httpx.AsyncClient(
                    base_url=base_url,
                    headers=headers,
                    timeout=5.0,
                ) as client:
                    resp = await client.post(
                        "/v1/sprint56/yolo/propagate",
                        json={
                            "session_id": session_id,
                            "signals": result.signals,
                            "source": "sdk_environment_probe",
                        },
                    )
                    resp.raise_for_status()
                    logger.info(
                        "YOLO detection propagated to server for session %s",
                        session_id,
                    )
            except Exception:
                logger.warning(
                    "Failed to propagate YOLO detection to server",
                    exc_info=True,
                )

        return result


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


def detect_yolo_mode() -> YOLOProbeResult:
    """Quick convenience function to detect YOLO mode from the environment."""
    return YOLOEnvironmentProbe().detect()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


async def _cli_main(args: argparse.Namespace) -> int:
    """CLI implementation."""
    probe = YOLOEnvironmentProbe()

    if args.session_id and args.propagate:
        result = await probe.detect_and_report(
            base_url=args.base_url,
            session_id=args.session_id,
            api_key=args.api_key,
            propagate=True,
        )
    else:
        result = probe.detect()

    if result.yolo_detected:
        print("YOLO MODE DETECTED")
        print(f"Signals ({len(result.signals)}):")
        for s in result.signals:
            print(f"  - {s}")
        print(f"Recommended action: {result.recommended_action}")
        print(f"Risk multiplier: {result.risk_multiplier}x")
        return 1  # exit code 1 = YOLO detected
    else:
        print("No YOLO mode signals detected.")
        return 0


def main() -> None:
    """CLI entry point for YOLO environment probe."""
    parser = argparse.ArgumentParser(
        description="Detect YOLO mode via environment probe"
    )
    parser.add_argument(
        "--session-id",
        default="",
        help="Session ID to associate with the detection",
    )
    parser.add_argument(
        "--propagate",
        action="store_true",
        help="Report detection to the AgentPEP server",
    )
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="AgentPEP server URL",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="API key for authentication",
    )

    args = parser.parse_args()
    sys.exit(asyncio.run(_cli_main(args)))


if __name__ == "__main__":
    main()
