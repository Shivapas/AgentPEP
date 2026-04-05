/** Sprint 16 — Risk Dashboard page combining all dashboard widgets. */

import { useState } from "react";
import type { TimeWindow } from "../types/dashboard";
import { useDashboard } from "../hooks/useDashboard";
import { TimeWindowSelector } from "./TimeWindowSelector";
import { RiskHeatmap } from "./RiskHeatmap";
import { DecisionTrendChart } from "./DecisionTrendChart";
import { TopBlockedTools } from "./TopBlockedTools";
import { RiskHistogram } from "./RiskHistogram";
import { AnomalyHighlight } from "./AnomalyHighlight";

function Card({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="mb-3 text-sm font-semibold text-card-foreground">
        {title}
      </h3>
      {children}
    </div>
  );
}

export function RiskDashboard() {
  const [window, setWindow] = useState<TimeWindow>("24h");
  const { data, loading, error, refresh } = useDashboard(window);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <h2 className="text-2xl font-bold">Risk Dashboard</h2>
        <div className="flex items-center gap-3">
          <TimeWindowSelector value={window} onChange={setWindow} />
          <button
            onClick={() => void refresh()}
            className="rounded-md border border-border px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-muted"
          >
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-destructive bg-destructive/10 p-3 text-sm text-destructive">
          Failed to load dashboard: {error}
        </div>
      )}

      {loading && !data && (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          Loading dashboard data...
        </div>
      )}

      {data && (
        <>
          {/* Anomaly alerts at the top for visibility */}
          {data.anomalies.length > 0 && (
            <Card title="Anomaly Alerts (DENY rate > 2σ)">
              <AnomalyHighlight data={data.anomalies} />
            </Card>
          )}

          {/* Decision trend chart */}
          <Card title="Decision Trend">
            <DecisionTrendChart data={data.trend} />
          </Card>

          {/* Two-column layout: heatmap + histogram */}
          <div className="grid gap-6 lg:grid-cols-2">
            <Card title="Risk Heatmap (Agent × Tool)">
              <RiskHeatmap data={data.heatmap} />
            </Card>
            <Card title="Risk Score Distribution">
              <RiskHistogram data={data.histogram} />
            </Card>
          </div>

          {/* Top blocked tools */}
          <Card title="Top Blocked Tools">
            <TopBlockedTools data={data.top_blocked} />
          </Card>

          {/* Footer with metadata */}
          <p className="text-xs text-muted-foreground">
            Window: {data.window} | Last updated:{" "}
            {new Date(data.generated_at).toLocaleString()}
          </p>
        </>
      )}
    </div>
  );
}
