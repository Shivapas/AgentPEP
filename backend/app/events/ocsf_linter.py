"""OCSF schema linter — validates AgentPEP events against the TrustFabric OCSF Profile.

Used in two contexts:
  1. As a pytest fixture — called directly in test suites to validate emitted events.
  2. As a CI gate — ``python -m app.events.ocsf_linter <event.json>`` exits non-zero
     on any schema violation so the pipeline blocks on malformed events.

Required envelope fields (TrustFabric OCSF Profile v1.0):
  - class_uid       int    OCSF class identifier
  - class_name      str    Human-readable class name
  - category_uid    int    OCSF category identifier
  - category_name   str    Human-readable category name
  - activity_id     int    OCSF activity identifier
  - activity_name   str    Human-readable activity name
  - severity_id     int    Numeric severity (1=INFO .. 5=CRITICAL)
  - severity        str    Severity label
  - type_uid        int    Derived: class_uid * 100 + activity_id
  - time            int    Epoch milliseconds
  - metadata        dict   Product info; must include 'product.name' and 'version'
  - actor           dict   Must include 'agent_id' and 'session_id'
  - resources       list   Non-empty list of affected resources
  - decision        str    ALLOW | DENY | MODIFY

Sprint S-E07 (E07-T07)
"""

from __future__ import annotations

import json
import sys
from typing import Any

_REQUIRED_ENVELOPE = [
    "class_uid",
    "class_name",
    "category_uid",
    "category_name",
    "activity_id",
    "activity_name",
    "severity_id",
    "severity",
    "type_uid",
    "time",
    "metadata",
    "actor",
    "resources",
    "decision",
]

_VALID_DECISIONS = {"ALLOW", "DENY", "MODIFY"}

_VALID_SEVERITY_IDS = {1, 2, 3, 4, 5}
_SEVERITY_ID_TO_NAME = {
    1: "INFO",
    2: "LOW",
    3: "HIGH",
    4: "VERY_HIGH",
    5: "CRITICAL",
}


class OCSFLintError(Exception):
    """Raised when an event fails OCSF schema validation."""


def lint(event: dict[str, Any]) -> list[str]:
    """Validate an OCSF event against the TrustFabric OCSF Profile.

    Returns a list of violation strings.  An empty list means the event is
    valid.  Callers can check ``not lint(event)`` as a boolean pass/fail.
    """
    violations: list[str] = []

    # 1. Required top-level fields
    for field in _REQUIRED_ENVELOPE:
        if field not in event:
            violations.append(f"Missing required field: '{field}'")

    if violations:
        # Stop early — remaining checks assume the envelope is intact
        return violations

    # 2. Type checks
    if not isinstance(event["class_uid"], int):
        violations.append("'class_uid' must be an integer")
    if not isinstance(event["category_uid"], int):
        violations.append("'category_uid' must be an integer")
    if not isinstance(event["activity_id"], int):
        violations.append("'activity_id' must be an integer")
    if not isinstance(event["severity_id"], int):
        violations.append("'severity_id' must be an integer")
    if not isinstance(event["type_uid"], int):
        violations.append("'type_uid' must be an integer")
    if not isinstance(event["time"], int):
        violations.append("'time' must be an integer (epoch milliseconds)")
    if not isinstance(event["metadata"], dict):
        violations.append("'metadata' must be a dict")
    if not isinstance(event["actor"], dict):
        violations.append("'actor' must be a dict")
    if not isinstance(event["resources"], list):
        violations.append("'resources' must be a list")

    # 3. type_uid derivation: class_uid * 100 + activity_id
    if (
        isinstance(event["class_uid"], int)
        and isinstance(event["activity_id"], int)
        and isinstance(event["type_uid"], int)
    ):
        expected_type_uid = event["class_uid"] * 100 + event["activity_id"]
        if event["type_uid"] != expected_type_uid:
            violations.append(
                f"'type_uid' {event['type_uid']} does not match "
                f"class_uid({event['class_uid']}) * 100 + activity_id({event['activity_id']}) "
                f"= {expected_type_uid}"
            )

    # 4. severity_id range
    if isinstance(event["severity_id"], int):
        if event["severity_id"] not in _VALID_SEVERITY_IDS:
            violations.append(
                f"'severity_id' {event['severity_id']} not in valid range {sorted(_VALID_SEVERITY_IDS)}"
            )

    # 5. decision value
    if event["decision"] not in _VALID_DECISIONS:
        violations.append(
            f"'decision' '{event['decision']}' is not one of {sorted(_VALID_DECISIONS)}"
        )

    # 6. metadata.product.name must be "AgentPEP"
    if isinstance(event["metadata"], dict):
        product = event["metadata"].get("product", {})
        if not isinstance(product, dict):
            violations.append("metadata.product must be a dict")
        elif product.get("name") != "AgentPEP":
            violations.append(
                f"metadata.product.name must be 'AgentPEP', got '{product.get('name')}'"
            )
        if "version" not in event["metadata"]:
            violations.append("metadata.version is required")

    # 7. actor must have agent_id and session_id
    if isinstance(event["actor"], dict):
        for key in ("agent_id", "session_id"):
            if key not in event["actor"]:
                violations.append(f"actor.{key} is required")

    # 8. resources must be non-empty
    if isinstance(event["resources"], list) and len(event["resources"]) == 0:
        violations.append("'resources' list must be non-empty")

    # 9. time must be positive (basic epoch sanity check — after year 2000)
    if isinstance(event["time"], int) and event["time"] < 946_684_800_000:
        violations.append(
            f"'time' {event['time']} looks invalid (expected epoch milliseconds after year 2000)"
        )

    return violations


def assert_valid(event: dict[str, Any]) -> None:
    """Assert that an OCSF event is valid.  Raises OCSFLintError if not.

    Convenience wrapper for test suites.
    """
    violations = lint(event)
    if violations:
        details = "\n  ".join(violations)
        raise OCSFLintError(
            f"OCSF event failed schema validation ({len(violations)} violation(s)):\n  {details}"
        )


def _main() -> None:
    """CLI entry point: python -m app.events.ocsf_linter <event.json>"""
    if len(sys.argv) < 2:
        print("Usage: python -m app.events.ocsf_linter <event.json>", file=sys.stderr)
        sys.exit(2)

    path = sys.argv[1]
    try:
        with open(path) as fh:
            event = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: Could not read event file: {exc}", file=sys.stderr)
        sys.exit(2)

    violations = lint(event)
    if violations:
        print(f"FAIL — {len(violations)} OCSF violation(s) in {path}:")
        for v in violations:
            print(f"  • {v}")
        sys.exit(1)
    else:
        print(f"PASS — {path} is a valid TrustFabric OCSF event")
        sys.exit(0)


if __name__ == "__main__":
    _main()
