/**
 * APEP-124 — Agent Activity Timeline
 * Last 100 decisions for selected agent.
 */
import { useEffect, useState, useCallback } from "react";
import { cn } from "@/lib/utils";
import { getActivity, type ActivityEntry } from "@/api/agents";

const DECISION_COLORS: Record<string, string> = {
  ALLOW: "bg-green-500/10 text-green-600",
  DENY: "bg-red-500/10 text-red-500",
  ESCALATE: "bg-yellow-500/10 text-yellow-600",
  DRY_RUN: "bg-blue-500/10 text-blue-500",
  TIMEOUT: "bg-gray-500/10 text-gray-500",
};

export function AgentActivityTimeline({ agentId }: { agentId: string }) {
  const [entries, setEntries] = useState<ActivityEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getActivity(agentId, 100);
      setEntries(res.entries);
      setTotal(res.total);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load activity");
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">Activity Timeline</h3>
        <span className="text-xs text-muted-foreground">{total} total decisions</span>
      </div>

      {error && (
        <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      {loading ? (
        <p className="text-sm text-muted-foreground">Loading activity...</p>
      ) : entries.length === 0 ? (
        <p className="text-sm text-muted-foreground">No activity yet.</p>
      ) : (
        <div className="space-y-2">
          {entries.map((entry) => (
            <div
              key={entry.decision_id}
              className="flex items-start gap-3 rounded-lg border border-border p-3"
            >
              {/* Decision badge */}
              <span
                className={cn(
                  "mt-0.5 inline-block shrink-0 rounded-full px-2 py-0.5 text-xs font-medium",
                  DECISION_COLORS[entry.decision] ?? "bg-muted text-muted-foreground",
                )}
              >
                {entry.decision}
              </span>

              {/* Details */}
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">{entry.tool_name}</p>
                <p className="text-xs text-muted-foreground">
                  Session: <span className="font-mono">{entry.session_id}</span>
                  {" | "}
                  Risk: {entry.risk_score.toFixed(2)}
                </p>
              </div>

              {/* Timestamp */}
              <span className="shrink-0 text-xs text-muted-foreground">
                {entry.timestamp}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
