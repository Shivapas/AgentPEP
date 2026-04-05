/**
 * Sprint 16 — Pure data transformation functions for risk dashboard.
 * These are tested independently (APEP-135).
 */

import type {
  AnomalyAgent,
  HeatmapCell,
  HistogramBin,
  TrendBucket,
} from "../types/dashboard";

// --- Heatmap (APEP-128) ---

export interface HeatmapGrid {
  agents: string[];
  tools: string[];
  /** matrix[agentIdx][toolIdx] = avg_risk_score or null */
  matrix: (number | null)[][];
  counts: (number | null)[][];
}

export function buildHeatmapGrid(cells: HeatmapCell[]): HeatmapGrid {
  const agentSet = new Set<string>();
  const toolSet = new Set<string>();
  for (const c of cells) {
    agentSet.add(c.agent_id);
    toolSet.add(c.tool_name);
  }
  const agents = [...agentSet].sort();
  const tools = [...toolSet].sort();
  const agentIdx = new Map(agents.map((a, i) => [a, i]));
  const toolIdx = new Map(tools.map((t, i) => [t, i]));

  const matrix: (number | null)[][] = agents.map(() => tools.map(() => null));
  const counts: (number | null)[][] = agents.map(() => tools.map(() => null));

  for (const c of cells) {
    const ai = agentIdx.get(c.agent_id)!;
    const ti = toolIdx.get(c.tool_name)!;
    matrix[ai]![ti] = c.avg_risk_score;
    counts[ai]![ti] = c.count;
  }
  return { agents, tools, matrix, counts };
}

export function riskScoreToColor(score: number | null): string {
  if (score === null) return "#1e293b"; // slate-800 (empty cell)
  if (score < 0.2) return "#22c55e"; // green-500
  if (score < 0.4) return "#84cc16"; // lime-500
  if (score < 0.6) return "#eab308"; // yellow-500
  if (score < 0.8) return "#f97316"; // orange-500
  return "#ef4444"; // red-500
}

// --- Trend (APEP-129) ---

export function formatTrendTimestamp(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export function computeTrendTotals(trend: TrendBucket[]): {
  totalAllow: number;
  totalDeny: number;
  totalEscalate: number;
} {
  let totalAllow = 0;
  let totalDeny = 0;
  let totalEscalate = 0;
  for (const b of trend) {
    totalAllow += b.allow;
    totalDeny += b.deny;
    totalEscalate += b.escalate;
  }
  return { totalAllow, totalDeny, totalEscalate };
}

// --- Histogram (APEP-131) ---

export function formatBinLabel(bin: HistogramBin): string {
  return `${bin.bin_start.toFixed(1)}-${bin.bin_end.toFixed(1)}`;
}

export function histogramMax(bins: HistogramBin[]): number {
  return Math.max(...bins.map((b) => b.count), 1);
}

// --- Anomaly (APEP-134) ---

export function isAnomaly(agent: AnomalyAgent): boolean {
  return agent.sigma_distance > 2.0;
}

export function anomalySeverity(
  agent: AnomalyAgent,
): "critical" | "warning" | "normal" {
  if (agent.sigma_distance > 3.0) return "critical";
  if (agent.sigma_distance > 2.0) return "warning";
  return "normal";
}
