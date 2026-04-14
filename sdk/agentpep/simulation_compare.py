"""Simulation result comparison — diff two simulation runs.

Sprint 34 — APEP-272: Diff two simulation runs (before/after policy change)
with structured and visual output.

Compares the results of evaluating the same set of tool call requests against
two different policy versions, highlighting decision changes, risk score
shifts, and taint evaluation differences.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentpep.models import PolicyDecision, PolicyDecisionResponse
from agentpep.offline import OfflineEvaluator


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass
class SimulationRun:
    """Result of a single simulation run."""

    label: str
    results: list[PolicyDecisionResponse]

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "total": len(self.results),
            "allow_count": sum(
                1 for r in self.results if r.decision == PolicyDecision.ALLOW
            ),
            "deny_count": sum(
                1 for r in self.results if r.decision == PolicyDecision.DENY
            ),
            "escalate_count": sum(
                1 for r in self.results if r.decision == PolicyDecision.ESCALATE
            ),
        }


@dataclass
class ComparisonEntry:
    """Comparison of a single tool call across two runs."""

    index: int
    agent_id: str
    tool_name: str
    decision_a: str
    decision_b: str
    decision_changed: bool
    risk_score_a: float
    risk_score_b: float
    risk_changed: bool
    reason_a: str = ""
    reason_b: str = ""

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "index": self.index,
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "decision_a": self.decision_a,
            "decision_b": self.decision_b,
            "decision_changed": self.decision_changed,
            "risk_score_a": round(self.risk_score_a, 4),
            "risk_score_b": round(self.risk_score_b, 4),
            "risk_changed": self.risk_changed,
        }
        if self.decision_changed:
            result["reason_a"] = self.reason_a
            result["reason_b"] = self.reason_b
        return result


@dataclass
class ComparisonReport:
    """Full comparison report between two simulation runs (APEP-272)."""

    run_a: SimulationRun
    run_b: SimulationRun
    entries: list[ComparisonEntry] = field(default_factory=list)

    @property
    def total_compared(self) -> int:
        return len(self.entries)

    @property
    def decision_changes(self) -> int:
        return sum(1 for e in self.entries if e.decision_changed)

    @property
    def risk_changes(self) -> int:
        return sum(1 for e in self.entries if e.risk_changed)

    @property
    def regressions(self) -> list[ComparisonEntry]:
        """Entries where decision went from ALLOW -> DENY (potential regression)."""
        return [
            e for e in self.entries
            if e.decision_a == "ALLOW" and e.decision_b == "DENY"
        ]

    @property
    def relaxations(self) -> list[ComparisonEntry]:
        """Entries where decision went from DENY -> ALLOW (potential relaxation)."""
        return [
            e for e in self.entries
            if e.decision_a == "DENY" and e.decision_b == "ALLOW"
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "total_compared": self.total_compared,
                "decision_changes": self.decision_changes,
                "risk_changes": self.risk_changes,
                "regressions": len(self.regressions),
                "relaxations": len(self.relaxations),
            },
            "run_a": self.run_a.to_dict(),
            "run_b": self.run_b.to_dict(),
            "changed_entries": [
                e.to_dict() for e in self.entries if e.decision_changed or e.risk_changed
            ],
            "all_entries": [e.to_dict() for e in self.entries],
        }

    def format_visual(self) -> str:
        """Produce a human-readable visual comparison."""
        lines: list[str] = []
        lines.append(f"=== Simulation Comparison: '{self.run_a.label}' vs '{self.run_b.label}' ===")
        lines.append(f"Total compared: {self.total_compared}")
        lines.append(f"Decision changes: {self.decision_changes}")
        lines.append(f"Risk score changes: {self.risk_changes}")
        lines.append(f"Regressions (ALLOW->DENY): {len(self.regressions)}")
        lines.append(f"Relaxations (DENY->ALLOW): {len(self.relaxations)}")
        lines.append("")

        if self.decision_changes > 0:
            lines.append("--- Decision Changes ---")
            for e in self.entries:
                if e.decision_changed:
                    marker = "!" if e.decision_a == "ALLOW" and e.decision_b == "DENY" else "~"
                    lines.append(
                        f"  [{marker}] #{e.index} {e.agent_id}/{e.tool_name}: "
                        f"{e.decision_a} -> {e.decision_b}"
                    )
            lines.append("")

        if self.risk_changes > 0:
            lines.append("--- Risk Score Changes ---")
            for e in self.entries:
                if e.risk_changed:
                    delta = e.risk_score_b - e.risk_score_a
                    direction = "+" if delta > 0 else ""
                    lines.append(
                        f"  #{e.index} {e.agent_id}/{e.tool_name}: "
                        f"{e.risk_score_a:.4f} -> {e.risk_score_b:.4f} "
                        f"({direction}{delta:.4f})"
                    )

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Comparison engine
# ---------------------------------------------------------------------------


@dataclass
class ToolCallSpec:
    """Specification of a tool call to evaluate."""

    agent_id: str
    tool_name: str
    tool_args: dict[str, Any] = field(default_factory=dict)
    role: str = "*"
    taint_flags: list[str] | None = None
    delegation_chain: list[str] | None = None


class SimulationComparator:
    """Compare simulation results between two policy versions (APEP-272).

    Usage::

        comparator = SimulationComparator()
        report = comparator.compare(
            policy_a=Path("policy_v1.yaml"),
            policy_b=Path("policy_v2.yaml"),
            tool_calls=[
                ToolCallSpec(agent_id="bot", tool_name="file.read"),
                ToolCallSpec(agent_id="bot", tool_name="admin.delete"),
            ],
            label_a="v1.0",
            label_b="v2.0",
        )
        print(report.format_visual())
    """

    def compare(
        self,
        *,
        policy_a: Path,
        policy_b: Path,
        tool_calls: list[ToolCallSpec],
        label_a: str = "before",
        label_b: str = "after",
    ) -> ComparisonReport:
        """Run tool calls against two policies and compare results."""
        eval_a = self._load_evaluator(policy_a)
        eval_b = self._load_evaluator(policy_b)

        results_a: list[PolicyDecisionResponse] = []
        results_b: list[PolicyDecisionResponse] = []

        for spec in tool_calls:
            kwargs = {
                "agent_id": spec.agent_id,
                "tool_name": spec.tool_name,
                "tool_args": spec.tool_args,
                "role": spec.role,
                "taint_flags": spec.taint_flags,
                "delegation_chain": spec.delegation_chain,
            }
            results_a.append(eval_a.evaluate(**kwargs))
            results_b.append(eval_b.evaluate(**kwargs))

        run_a = SimulationRun(label=label_a, results=results_a)
        run_b = SimulationRun(label=label_b, results=results_b)

        entries: list[ComparisonEntry] = []
        for i, (ra, rb, spec) in enumerate(zip(results_a, results_b, tool_calls)):
            entries.append(ComparisonEntry(
                index=i,
                agent_id=spec.agent_id,
                tool_name=spec.tool_name,
                decision_a=ra.decision.value,
                decision_b=rb.decision.value,
                decision_changed=ra.decision != rb.decision,
                risk_score_a=ra.risk_score,
                risk_score_b=rb.risk_score,
                risk_changed=ra.risk_score != rb.risk_score,
                reason_a=ra.reason,
                reason_b=rb.reason,
            ))

        return ComparisonReport(run_a=run_a, run_b=run_b, entries=entries)

    def _load_evaluator(self, path: Path) -> OfflineEvaluator:
        if path.is_dir():
            return OfflineEvaluator.from_yaml_directory(path)
        return OfflineEvaluator.from_yaml_file(path)
