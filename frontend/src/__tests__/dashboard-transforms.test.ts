/**
 * APEP-135: Unit tests for dashboard data transformation logic.
 */

import { describe, expect, it } from "vitest";
import {
  anomalySeverity,
  buildHeatmapGrid,
  computeTrendTotals,
  formatBinLabel,
  formatTrendTimestamp,
  histogramMax,
  isAnomaly,
  riskScoreToColor,
} from "../lib/dashboard-transforms";
import type {
  AnomalyAgent,
  HeatmapCell,
  HistogramBin,
  TrendBucket,
} from "../types/dashboard";

// --- buildHeatmapGrid ---

describe("buildHeatmapGrid", () => {
  it("builds a correct agent × tool matrix from cells", () => {
    const cells: HeatmapCell[] = [
      { agent_id: "agent-a", tool_name: "tool-1", avg_risk_score: 0.3, count: 5 },
      { agent_id: "agent-a", tool_name: "tool-2", avg_risk_score: 0.8, count: 2 },
      { agent_id: "agent-b", tool_name: "tool-1", avg_risk_score: 0.1, count: 10 },
    ];
    const grid = buildHeatmapGrid(cells);

    expect(grid.agents).toEqual(["agent-a", "agent-b"]);
    expect(grid.tools).toEqual(["tool-1", "tool-2"]);

    // agent-a × tool-1
    expect(grid.matrix[0]![0]).toBe(0.3);
    expect(grid.counts[0]![0]).toBe(5);

    // agent-a × tool-2
    expect(grid.matrix[0]![1]).toBe(0.8);
    expect(grid.counts[0]![1]).toBe(2);

    // agent-b × tool-1
    expect(grid.matrix[1]![0]).toBe(0.1);
    expect(grid.counts[1]![0]).toBe(10);

    // agent-b × tool-2 — no data
    expect(grid.matrix[1]![1]).toBeNull();
    expect(grid.counts[1]![1]).toBeNull();
  });

  it("returns empty arrays for no data", () => {
    const grid = buildHeatmapGrid([]);
    expect(grid.agents).toEqual([]);
    expect(grid.tools).toEqual([]);
    expect(grid.matrix).toEqual([]);
  });

  it("sorts agents and tools alphabetically", () => {
    const cells: HeatmapCell[] = [
      { agent_id: "z-agent", tool_name: "b-tool", avg_risk_score: 0.5, count: 1 },
      { agent_id: "a-agent", tool_name: "a-tool", avg_risk_score: 0.2, count: 3 },
    ];
    const grid = buildHeatmapGrid(cells);
    expect(grid.agents).toEqual(["a-agent", "z-agent"]);
    expect(grid.tools).toEqual(["a-tool", "b-tool"]);
  });
});

// --- riskScoreToColor ---

describe("riskScoreToColor", () => {
  it("returns slate for null (empty cell)", () => {
    expect(riskScoreToColor(null)).toBe("#1e293b");
  });

  it("returns green for low risk (< 0.2)", () => {
    expect(riskScoreToColor(0.1)).toBe("#22c55e");
  });

  it("returns lime for moderate-low risk (0.2-0.4)", () => {
    expect(riskScoreToColor(0.3)).toBe("#84cc16");
  });

  it("returns yellow for medium risk (0.4-0.6)", () => {
    expect(riskScoreToColor(0.5)).toBe("#eab308");
  });

  it("returns orange for high risk (0.6-0.8)", () => {
    expect(riskScoreToColor(0.7)).toBe("#f97316");
  });

  it("returns red for critical risk (>= 0.8)", () => {
    expect(riskScoreToColor(0.9)).toBe("#ef4444");
  });

  it("handles boundary values correctly", () => {
    expect(riskScoreToColor(0.0)).toBe("#22c55e"); // green
    expect(riskScoreToColor(0.2)).toBe("#84cc16"); // lime
    expect(riskScoreToColor(0.4)).toBe("#eab308"); // yellow
    expect(riskScoreToColor(0.6)).toBe("#f97316"); // orange
    expect(riskScoreToColor(0.8)).toBe("#ef4444"); // red
    expect(riskScoreToColor(1.0)).toBe("#ef4444"); // red
  });
});

// --- Trend helpers ---

describe("formatTrendTimestamp", () => {
  it("formats ISO timestamp to HH:MM", () => {
    const result = formatTrendTimestamp("2024-01-15T14:30:00Z");
    // Result depends on locale, but should contain hour/minute
    expect(result).toBeTruthy();
    expect(typeof result).toBe("string");
  });
});

describe("computeTrendTotals", () => {
  it("sums all buckets correctly", () => {
    const trend: TrendBucket[] = [
      { timestamp: "2024-01-15T14:00:00Z", allow: 10, deny: 3, escalate: 1 },
      { timestamp: "2024-01-15T15:00:00Z", allow: 20, deny: 5, escalate: 2 },
      { timestamp: "2024-01-15T16:00:00Z", allow: 15, deny: 7, escalate: 0 },
    ];
    const totals = computeTrendTotals(trend);
    expect(totals.totalAllow).toBe(45);
    expect(totals.totalDeny).toBe(15);
    expect(totals.totalEscalate).toBe(3);
  });

  it("returns zeros for empty trend", () => {
    const totals = computeTrendTotals([]);
    expect(totals.totalAllow).toBe(0);
    expect(totals.totalDeny).toBe(0);
    expect(totals.totalEscalate).toBe(0);
  });
});

// --- Histogram helpers ---

describe("formatBinLabel", () => {
  it("formats bin range correctly", () => {
    const bin: HistogramBin = { bin_start: 0.0, bin_end: 0.1, count: 5 };
    expect(formatBinLabel(bin)).toBe("0.0-0.1");
  });

  it("handles mid-range bins", () => {
    const bin: HistogramBin = { bin_start: 0.4, bin_end: 0.5, count: 12 };
    expect(formatBinLabel(bin)).toBe("0.4-0.5");
  });
});

describe("histogramMax", () => {
  it("returns the max count", () => {
    const bins: HistogramBin[] = [
      { bin_start: 0.0, bin_end: 0.1, count: 5 },
      { bin_start: 0.1, bin_end: 0.2, count: 20 },
      { bin_start: 0.2, bin_end: 0.3, count: 3 },
    ];
    expect(histogramMax(bins)).toBe(20);
  });

  it("returns 1 for empty bins", () => {
    expect(histogramMax([])).toBe(1);
  });
});

// --- Anomaly helpers ---

describe("isAnomaly", () => {
  const makeAgent = (sigma: number): AnomalyAgent => ({
    agent_id: "test",
    deny_rate: 0.5,
    mean_deny_rate: 0.1,
    std_deny_rate: 0.05,
    sigma_distance: sigma,
    total_decisions: 100,
    deny_count: 50,
  });

  it("returns true for sigma > 2.0", () => {
    expect(isAnomaly(makeAgent(2.5))).toBe(true);
    expect(isAnomaly(makeAgent(3.0))).toBe(true);
  });

  it("returns false for sigma <= 2.0", () => {
    expect(isAnomaly(makeAgent(1.5))).toBe(false);
    expect(isAnomaly(makeAgent(2.0))).toBe(false);
  });
});

describe("anomalySeverity", () => {
  const makeAgent = (sigma: number): AnomalyAgent => ({
    agent_id: "test",
    deny_rate: 0.5,
    mean_deny_rate: 0.1,
    std_deny_rate: 0.05,
    sigma_distance: sigma,
    total_decisions: 100,
    deny_count: 50,
  });

  it("returns critical for sigma > 3.0", () => {
    expect(anomalySeverity(makeAgent(3.5))).toBe("critical");
  });

  it("returns warning for sigma > 2.0 and <= 3.0", () => {
    expect(anomalySeverity(makeAgent(2.5))).toBe("warning");
    expect(anomalySeverity(makeAgent(3.0))).toBe("warning");
  });

  it("returns normal for sigma <= 2.0", () => {
    expect(anomalySeverity(makeAgent(1.0))).toBe("normal");
    expect(anomalySeverity(makeAgent(2.0))).toBe("normal");
  });
});
