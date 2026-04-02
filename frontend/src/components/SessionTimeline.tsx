/**
 * APEP-139 — Session timeline view.
 *
 * Shows all decisions in a session in chronological order with a
 * vertical timeline indicator.
 */

import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { fetchSessionTimeline, type AuditDecision } from "@/lib/api";
import { cn } from "@/lib/utils";

export function SessionTimeline() {
  const { sessionId } = useParams<{ sessionId: string }>();
  const [items, setItems] = useState<AuditDecision[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!sessionId) return;
    setLoading(true);
    setError(null);
    fetchSessionTimeline(sessionId)
      .then(setItems)
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : "Failed to load"),
      )
      .finally(() => setLoading(false));
  }, [sessionId]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Link
          to="/audit"
          className="text-sm text-muted-foreground hover:text-foreground"
        >
          Audit Explorer
        </Link>
        <span className="text-muted-foreground">/</span>
        <h2 className="text-2xl font-bold">Session Timeline</h2>
      </div>
      <p className="font-mono text-sm text-muted-foreground">{sessionId}</p>

      {loading && <p className="text-muted-foreground">Loading timeline...</p>}
      {error && <p className="text-destructive">{error}</p>}

      {!loading && items.length === 0 && (
        <p className="text-muted-foreground">No decisions found for this session.</p>
      )}

      <div className="relative ml-4 border-l-2 border-border pl-6">
        {items.map((item, idx) => (
          <TimelineEntry key={item.decision_id} item={item} index={idx} />
        ))}
      </div>
    </div>
  );
}

function TimelineEntry({
  item,
  index,
}: {
  item: AuditDecision;
  index: number;
}) {
  const dotColor = decisionDotColor(item.decision);

  return (
    <div className="relative mb-6 last:mb-0">
      {/* Timeline dot */}
      <div
        className={cn(
          "absolute -left-[31px] top-1 h-4 w-4 rounded-full border-2 border-background",
          dotColor,
        )}
      />

      <div className="rounded-lg border border-border bg-card p-4">
        <div className="mb-2 flex items-center justify-between">
          <span className="text-xs text-muted-foreground">
            #{index + 1} — {new Date(item.timestamp).toLocaleString()}
          </span>
          <span
            className={cn(
              "rounded px-2 py-0.5 text-xs font-medium",
              decisionBadge(item.decision),
            )}
          >
            {item.decision}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-2 text-sm">
          <div>
            <span className="text-muted-foreground">Tool: </span>
            <span className="font-medium">{item.tool_name}</span>
          </div>
          <div>
            <span className="text-muted-foreground">Agent: </span>
            <span className="font-medium">{item.agent_id}</span>
          </div>
          <div>
            <span className="text-muted-foreground">Risk: </span>
            <span className="font-medium">{item.risk_score.toFixed(2)}</span>
          </div>
          <div>
            <span className="text-muted-foreground">Latency: </span>
            <span className="font-medium">{item.latency_ms}ms</span>
          </div>
        </div>

        {item.taint_flags.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1">
            {item.taint_flags.map((f) => (
              <span
                key={f}
                className="rounded bg-yellow-100 px-1.5 py-0.5 text-xs text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
              >
                {f}
              </span>
            ))}
          </div>
        )}

        {item.delegation_chain.length > 0 && (
          <div className="mt-2 text-xs text-muted-foreground">
            Chain: {item.delegation_chain.join(" → ")}
          </div>
        )}

        <div className="mt-2 font-mono text-xs text-muted-foreground">
          {item.decision_id}
        </div>
      </div>
    </div>
  );
}

function decisionDotColor(d: string): string {
  switch (d) {
    case "ALLOW":
      return "bg-green-500";
    case "DENY":
      return "bg-red-500";
    case "ESCALATE":
      return "bg-yellow-500";
    case "TIMEOUT":
      return "bg-gray-500";
    default:
      return "bg-blue-500";
  }
}

function decisionBadge(d: string): string {
  switch (d) {
    case "ALLOW":
      return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200";
    case "DENY":
      return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200";
    case "ESCALATE":
      return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200";
    case "TIMEOUT":
      return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200";
    default:
      return "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200";
  }
}
