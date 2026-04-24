"""Parity test: RegoNativeEvaluator (old) vs FirstAAMPBundleEvaluator (AAPM v1).

Sprint S-E05 (E05-T04, E05-T05)

Validates that the first AAPM-compiled Rego bundle (agentpep-core-v1.0.0)
produces decisions that are 100% identical to the decommissioned
RegoNativeEvaluator stub for the defined parity test matrix.

Structure
---------
- PARITY_CASES: inputs on which both evaluators must agree (same ALLOW/DENY)
- EXPECTED_DIVERGENCE_CASES: inputs where divergence is expected and documented
  (these are raised with the AAPM team via E05-T05 divergence report)
- DivergenceReport: accumulates any unexpected divergences for root-cause analysis

Exit criteria (E05-T04):
  100% decision match on PARITY_CASES → imperative rules decommissioned (E05-T09).
  Any divergences in PARITY_CASES → root-cause in divergence report, raise with AAPM.

Tests do not require regopy or an OPA binary.  Both evaluators are pure Python.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from app.pdp.engine import FirstAAMPBundleEvaluator, RegoNativeEvaluator

# ---------------------------------------------------------------------------
# Evaluator fixtures
# ---------------------------------------------------------------------------

_STUB_MODULES: dict[str, bytes] = {}  # not used by native evaluators


@pytest.fixture(scope="module")
def old_evaluator() -> RegoNativeEvaluator:
    """The decommissioned stub — represents 'old' imperative rules."""
    return RegoNativeEvaluator()


@pytest.fixture(scope="module")
def new_evaluator() -> FirstAAMPBundleEvaluator:
    """The first AAPM-compiled bundle — represents 'new' Rego rules."""
    return FirstAAMPBundleEvaluator()


# ---------------------------------------------------------------------------
# Parity test matrix
# ---------------------------------------------------------------------------

# Each entry: (description, input_document, expected_allow)
# Both evaluators must produce the same ALLOW/DENY for all entries.
PARITY_CASES: list[tuple[str, dict[str, Any], bool]] = [
    # --- Read-only tools, HOMEGROWN tier, CLEAN taint → ALLOW ---
    (
        "read_file / HOMEGROWN / CLEAN / trust=1.0",
        {"tool_name": "read_file", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 1.0},
        True,
    ),
    (
        "list_dir / HOMEGROWN / CLEAN / trust=0.5",
        {"tool_name": "list_dir", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 0.5},
        True,
    ),
    (
        "search_code / HOMEGROWN / CLEAN / trust=0.01",
        {"tool_name": "search_code", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 0.01},
        True,
    ),
    (
        "get_file_contents / HOMEGROWN / CLEAN / trust=0.0",
        {"tool_name": "get_file_contents", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 0.0},
        True,
    ),
    (
        "list_files / HOMEGROWN / CLEAN / trust=0.99",
        {"tool_name": "list_files", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 0.99},
        True,
    ),
    # --- Tainted inputs → DENY regardless of tool/tier ---
    (
        "read_file / HOMEGROWN / TAINTED / trust=1.0 → DENY",
        {"tool_name": "read_file", "deployment_tier": "HOMEGROWN", "taint_level": "TAINTED", "trust_score": 1.0},
        False,
    ),
    (
        "read_file / HOMEGROWN / SENSITIVE / trust=1.0 → DENY",
        {"tool_name": "read_file", "deployment_tier": "HOMEGROWN", "taint_level": "SENSITIVE", "trust_score": 1.0},
        False,
    ),
    (
        "read_file / HOMEGROWN / QUARANTINE / trust=1.0 → DENY",
        {"tool_name": "read_file", "deployment_tier": "HOMEGROWN", "taint_level": "QUARANTINE", "trust_score": 1.0},
        False,
    ),
    (
        "write_file / HOMEGROWN / TAINTED / trust=1.0 → DENY",
        {"tool_name": "write_file", "deployment_tier": "HOMEGROWN", "taint_level": "TAINTED", "trust_score": 1.0},
        False,
    ),
    (
        "bash / ENTERPRISE / TAINTED / trust=0.9 → DENY",
        {"tool_name": "bash", "deployment_tier": "ENTERPRISE", "taint_level": "TAINTED", "trust_score": 0.9},
        False,
    ),
    # --- Non-read-only tools on HOMEGROWN → DENY ---
    (
        "write_file / HOMEGROWN / CLEAN / trust=1.0 → DENY",
        {"tool_name": "write_file", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 1.0},
        False,
    ),
    (
        "bash / HOMEGROWN / CLEAN / trust=1.0 → DENY",
        {"tool_name": "bash", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 1.0},
        False,
    ),
    (
        "delete_file / HOMEGROWN / CLEAN / trust=1.0 → DENY",
        {"tool_name": "delete_file", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 1.0},
        False,
    ),
    (
        "exec / HOMEGROWN / CLEAN / trust=1.0 → DENY",
        {"tool_name": "exec", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 1.0},
        False,
    ),
    # --- Read-only tools on non-HOMEGROWN tier → DENY (both evaluators) ---
    (
        "read_file / ENTERPRISE / CLEAN / trust=1.0 → DENY",
        {"tool_name": "read_file", "deployment_tier": "ENTERPRISE", "taint_level": "CLEAN", "trust_score": 1.0},
        False,
    ),
    (
        "read_file / MANAGED / CLEAN / trust=1.0 → DENY",
        {"tool_name": "read_file", "deployment_tier": "MANAGED", "taint_level": "CLEAN", "trust_score": 1.0},
        False,
    ),
    (
        "read_file / SOVEREIGN / CLEAN / trust=1.0 → DENY",
        {"tool_name": "read_file", "deployment_tier": "SOVEREIGN", "taint_level": "CLEAN", "trust_score": 1.0},
        False,
    ),
    # --- Insufficient trust score → DENY ---
    (
        "read_file / HOMEGROWN / CLEAN / trust=-0.1 → DENY",
        {"tool_name": "read_file", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": -0.1},
        False,
    ),
    (
        "read_file / HOMEGROWN / CLEAN / trust=-1.0 → DENY",
        {"tool_name": "read_file", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": -1.0},
        False,
    ),
    # --- Unknown / empty tool name → DENY ---
    (
        "unknown_tool / HOMEGROWN / CLEAN / trust=1.0 → DENY",
        {"tool_name": "unknown_tool", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 1.0},
        False,
    ),
    (
        "empty tool name / HOMEGROWN / CLEAN / trust=1.0 → DENY",
        {"tool_name": "", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 1.0},
        False,
    ),
    # --- Missing fields (defaults) → DENY ---
    (
        "missing tool_name → DENY",
        {"deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 1.0},
        False,
    ),
    (
        "missing taint_level → ALLOW (defaults to CLEAN in native evaluator)",
        {"tool_name": "read_file", "deployment_tier": "HOMEGROWN", "trust_score": 1.0},
        True,
    ),
    (
        "missing trust_score → ALLOW (defaults to 1.0 in native evaluator)",
        {"tool_name": "read_file", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN"},
        True,
    ),
]


# ---------------------------------------------------------------------------
# Divergence tracker
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class DivergenceRecord:
    """Documents a single decision divergence between old and new evaluators."""

    description: str
    input_document: dict[str, Any]
    old_allow: bool
    new_allow: bool
    old_reason: str
    new_reason: str

    @property
    def is_divergence(self) -> bool:
        return self.old_allow != self.new_allow

    def __str__(self) -> str:
        return (
            f"DIVERGENCE: {self.description!r}\n"
            f"  input: {self.input_document}\n"
            f"  old (RegoNativeEvaluator): allow={self.old_allow}, reason={self.old_reason!r}\n"
            f"  new (FirstAAMPBundleEvaluator): allow={self.new_allow}, reason={self.new_reason!r}"
        )


class DivergenceReport:
    """Accumulates divergences from parity runs for E05-T05 root-cause analysis."""

    def __init__(self) -> None:
        self._records: list[DivergenceRecord] = []

    def record(self, rec: DivergenceRecord) -> None:
        self._records.append(rec)

    @property
    def divergences(self) -> list[DivergenceRecord]:
        return [r for r in self._records if r.is_divergence]

    @property
    def parity_count(self) -> int:
        return sum(1 for r in self._records if not r.is_divergence)

    @property
    def divergence_count(self) -> int:
        return len(self.divergences)

    @property
    def total_count(self) -> int:
        return len(self._records)

    def summary(self) -> str:
        lines = [
            f"Parity Report: {self.parity_count}/{self.total_count} cases match "
            f"({self.divergence_count} divergences)"
        ]
        for div in self.divergences:
            lines.append(str(div))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Core parity tests (E05-T04)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("description,input_doc,expected_allow", PARITY_CASES, ids=[c[0] for c in PARITY_CASES])
def test_parity_decision_match(
    description: str,
    input_doc: dict[str, Any],
    expected_allow: bool,
    old_evaluator: RegoNativeEvaluator,
    new_evaluator: FirstAAMPBundleEvaluator,
) -> None:
    """Both evaluators must produce the same ALLOW/DENY decision and match expected."""
    old_result = old_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)
    new_result = new_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)

    old_allow = old_result["allow"]
    new_allow = new_result["allow"]

    assert old_allow == new_allow, (
        f"Parity failure for {description!r}:\n"
        f"  RegoNativeEvaluator: allow={old_allow}, reason={old_result.get('reason_code')!r}\n"
        f"  FirstAAMPBundleEvaluator: allow={new_allow}, reason={new_result.get('reason_code')!r}\n"
        f"  input: {input_doc}"
    )
    assert old_allow == expected_allow, (
        f"Unexpected decision for {description!r}: "
        f"expected allow={expected_allow}, got allow={old_allow}"
    )


def test_parity_reason_codes_match(
    old_evaluator: RegoNativeEvaluator,
    new_evaluator: FirstAAMPBundleEvaluator,
) -> None:
    """Reason codes must match between old and new evaluators on parity cases."""
    mismatches = []
    for description, input_doc, _ in PARITY_CASES:
        old_result = old_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)
        new_result = new_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)

        if old_result["reason_code"] != new_result["reason_code"]:
            mismatches.append(
                f"  {description!r}: "
                f"old={old_result['reason_code']!r}, new={new_result['reason_code']!r}"
            )

    assert not mismatches, (
        f"{len(mismatches)} reason-code mismatches:\n" + "\n".join(mismatches)
    )


def test_parity_deny_invariant(
    old_evaluator: RegoNativeEvaluator,
    new_evaluator: FirstAAMPBundleEvaluator,
) -> None:
    """For every case, allow XOR deny must equal True (no undefined state)."""
    for description, input_doc, _ in PARITY_CASES:
        for evaluator in (old_evaluator, new_evaluator):
            result = evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)
            assert result["allow"] != result["deny"], (
                f"allow and deny must be mutually exclusive for {description!r}: "
                f"allow={result['allow']}, deny={result['deny']}"
            )
            assert result["modify"] is False, (
                f"MODIFY not supported in v1-parity bundle; got modify=True for {description!r}"
            )


# ---------------------------------------------------------------------------
# Divergence report generation (E05-T05)
# ---------------------------------------------------------------------------


def test_full_parity_divergence_report(
    old_evaluator: RegoNativeEvaluator,
    new_evaluator: FirstAAMPBundleEvaluator,
) -> None:
    """Run all parity cases, collect divergences, assert zero divergences.

    This test is the formal parity gate: it must pass (zero divergences) before
    imperative rules can be decommissioned (E05-T09).  Any divergences are
    formatted as a root-cause report for the AAPM team (E05-T05).
    """
    report = DivergenceReport()

    for description, input_doc, _ in PARITY_CASES:
        old_result = old_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)
        new_result = new_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)

        report.record(
            DivergenceRecord(
                description=description,
                input_document=input_doc,
                old_allow=old_result["allow"],
                new_allow=new_result["allow"],
                old_reason=old_result.get("reason_code", ""),
                new_reason=new_result.get("reason_code", ""),
            )
        )

    assert report.divergence_count == 0, (
        f"Parity gate FAILED — {report.divergence_count} divergence(s) detected. "
        f"These must be corrected by the AAPM team before imperative rules can be "
        f"decommissioned (E05-T09).\n\n"
        + report.summary()
    )


# ---------------------------------------------------------------------------
# Evaluator identity tests
# ---------------------------------------------------------------------------


def test_new_evaluator_name() -> None:
    """FirstAAMPBundleEvaluator must identify itself in the decision dict."""
    ev = FirstAAMPBundleEvaluator()
    result = ev.evaluate(
        _STUB_MODULES,
        "data.agentpep.core.allow",
        {"tool_name": "read_file", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 1.0},
    )
    assert result["evaluator"] == "first_aapm_bundle_v1"


def test_old_evaluator_name() -> None:
    """RegoNativeEvaluator must identify itself as native_stub for traceability."""
    ev = RegoNativeEvaluator()
    result = ev.evaluate(
        _STUB_MODULES,
        "data.agentpep.core.allow",
        {"tool_name": "read_file", "deployment_tier": "HOMEGROWN", "taint_level": "CLEAN", "trust_score": 1.0},
    )
    assert result["evaluator"] == "native_stub"


# ---------------------------------------------------------------------------
# Adversarial boundary cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("trust_score", [-0.001, -0.5, -1.0, -100.0])
def test_parity_negative_trust_always_deny(
    trust_score: float,
    old_evaluator: RegoNativeEvaluator,
    new_evaluator: FirstAAMPBundleEvaluator,
) -> None:
    """Negative trust scores must DENY on both evaluators identically."""
    input_doc = {
        "tool_name": "read_file",
        "deployment_tier": "HOMEGROWN",
        "taint_level": "CLEAN",
        "trust_score": trust_score,
    }
    old_result = old_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)
    new_result = new_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)

    assert not old_result["allow"], f"Old evaluator must DENY trust_score={trust_score}"
    assert not new_result["allow"], f"New evaluator must DENY trust_score={trust_score}"
    assert old_result["allow"] == new_result["allow"]


@pytest.mark.parametrize("taint_level", ["TAINTED", "SENSITIVE", "QUARANTINE", "UNTRUSTED", "unknown"])
def test_parity_non_clean_taint_always_deny(
    taint_level: str,
    old_evaluator: RegoNativeEvaluator,
    new_evaluator: FirstAAMPBundleEvaluator,
) -> None:
    """Any non-CLEAN taint level must DENY on both evaluators identically."""
    input_doc = {
        "tool_name": "read_file",
        "deployment_tier": "HOMEGROWN",
        "taint_level": taint_level,
        "trust_score": 1.0,
    }
    old_result = old_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)
    new_result = new_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)

    assert not old_result["allow"], f"Old evaluator must DENY taint={taint_level!r}"
    assert not new_result["allow"], f"New evaluator must DENY taint={taint_level!r}"
    assert old_result["allow"] == new_result["allow"]


@pytest.mark.parametrize("tool_name", ["read_file", "list_dir", "search_code", "get_file_contents", "list_files"])
def test_parity_all_permitted_tools_allow_on_homegrown(
    tool_name: str,
    old_evaluator: RegoNativeEvaluator,
    new_evaluator: FirstAAMPBundleEvaluator,
) -> None:
    """All five permitted read-only tools must ALLOW on HOMEGROWN with CLEAN taint."""
    input_doc = {
        "tool_name": tool_name,
        "deployment_tier": "HOMEGROWN",
        "taint_level": "CLEAN",
        "trust_score": 1.0,
    }
    old_result = old_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)
    new_result = new_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)

    assert old_result["allow"], f"Old evaluator must ALLOW {tool_name!r} on HOMEGROWN"
    assert new_result["allow"], f"New evaluator must ALLOW {tool_name!r} on HOMEGROWN"
    assert old_result["allow"] == new_result["allow"]


@pytest.mark.parametrize("deployment_tier", ["ENTERPRISE", "MANAGED", "SOVEREIGN", "UNKNOWN", ""])
def test_parity_read_only_tools_denied_on_non_homegrown(
    deployment_tier: str,
    old_evaluator: RegoNativeEvaluator,
    new_evaluator: FirstAAMPBundleEvaluator,
) -> None:
    """v1-parity bundle: read-only tools on non-HOMEGROWN tiers are DENY (scope of v1)."""
    input_doc = {
        "tool_name": "read_file",
        "deployment_tier": deployment_tier,
        "taint_level": "CLEAN",
        "trust_score": 1.0,
    }
    old_result = old_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)
    new_result = new_evaluator.evaluate(_STUB_MODULES, "data.agentpep.core.allow", input_doc)

    assert not old_result["allow"], f"Old: must DENY read_file on tier={deployment_tier!r}"
    assert not new_result["allow"], f"New: must DENY read_file on tier={deployment_tier!r}"
