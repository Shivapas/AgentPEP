/** Sprint 16 — Risk Dashboard types matching backend response models. */

export type TimeWindow = "1h" | "6h" | "24h" | "7d" | "30d";

export const TIME_WINDOWS: { label: string; value: TimeWindow }[] = [
  { label: "1 hour", value: "1h" },
  { label: "6 hours", value: "6h" },
  { label: "24 hours", value: "24h" },
  { label: "7 days", value: "7d" },
  { label: "30 days", value: "30d" },
];

export interface HeatmapCell {
  agent_id: string;
  tool_name: string;
  avg_risk_score: number;
  count: number;
}

export interface TrendBucket {
  timestamp: string;
  allow: number;
  deny: number;
  escalate: number;
}

export interface BlockedTool {
  tool_name: string;
  deny_count: number;
  escalate_count: number;
  top_agents: string[];
}

export interface HistogramBin {
  bin_start: number;
  bin_end: number;
  count: number;
}

export interface AnomalyAgent {
  agent_id: string;
  deny_rate: number;
  mean_deny_rate: number;
  std_deny_rate: number;
  sigma_distance: number;
  total_decisions: number;
  deny_count: number;
}

export interface DashboardSummary {
  heatmap: HeatmapCell[];
  trend: TrendBucket[];
  top_blocked: BlockedTool[];
  histogram: HistogramBin[];
  anomalies: AnomalyAgent[];
  window: string;
  generated_at: string;
}
