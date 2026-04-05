/** APEP-134: Anomaly highlight — agents with DENY rate > 2σ from baseline flagged in red. */

import type { AnomalyAgent } from "../types/dashboard";
import { anomalySeverity } from "../lib/dashboard-transforms";

interface Props {
  data: AnomalyAgent[];
}

const SEVERITY_STYLES = {
  critical: "border-red-500 bg-red-500/10 text-red-400",
  warning: "border-amber-500 bg-amber-500/10 text-amber-400",
  normal: "border-border bg-card text-card-foreground",
};

export function AnomalyHighlight({ data }: Props) {
  if (data.length === 0) {
    return (
      <div className="flex h-24 items-center justify-center text-sm text-muted-foreground">
        No anomalous agents detected — all DENY rates within 2σ of baseline.
      </div>
    );
  }

  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {data.map((agent) => {
        const severity = anomalySeverity(agent);
        return (
          <div
            key={agent.agent_id}
            className={`rounded-lg border p-4 ${SEVERITY_STYLES[severity]}`}
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold">{agent.agent_id}</span>
              <span
                className={`rounded-full px-2 py-0.5 text-xs font-bold uppercase ${
                  severity === "critical"
                    ? "bg-red-500 text-white"
                    : "bg-amber-500 text-white"
                }`}
              >
                {agent.sigma_distance.toFixed(1)}σ
              </span>
            </div>
            <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
              <div>
                <span className="text-muted-foreground">DENY rate</span>
                <p className="font-mono text-sm font-bold">
                  {(agent.deny_rate * 100).toFixed(1)}%
                </p>
              </div>
              <div>
                <span className="text-muted-foreground">Baseline mean</span>
                <p className="font-mono text-sm">
                  {(agent.mean_deny_rate * 100).toFixed(1)}%
                </p>
              </div>
              <div>
                <span className="text-muted-foreground">Decisions</span>
                <p className="font-mono text-sm">{agent.total_decisions}</p>
              </div>
              <div>
                <span className="text-muted-foreground">Denied</span>
                <p className="font-mono text-sm">{agent.deny_count}</p>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
