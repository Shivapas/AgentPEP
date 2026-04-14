import { useEffect, useState } from "react";
import { apiFetch } from "../../lib/api";

/**
 * Sprint 41 — APEP-329: Checkpoint History view for Escalation Queue.
 *
 * Displays a chronological list of checkpoint-triggered escalation records,
 * showing the matched pattern, agent, tool, human intent, and timestamp.
 * Intended to be embedded alongside the Escalation Queue screen.
 */

interface CheckpointEscalationRecord {
  record_id: string;
  plan_id: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  matched_pattern: string;
  match_reason: string;
  human_intent: string;
  created_at: string;
}

interface CheckpointHistoryResponse {
  records: CheckpointEscalationRecord[];
  total: number;
}

export function CheckpointHistory({ planId }: { planId?: string }) {
  const [records, setRecords] = useState<CheckpointEscalationRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    if (!planId) return;
    setLoading(true);
    setError(null);

    apiFetch(`/v1/plans/${planId}/checkpoints`)
      .then(async (res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data: CheckpointHistoryResponse = await res.json();
        setRecords(data.records);
      })
      .catch((err) =>
        setError(err instanceof Error ? err.message : "Failed to load"),
      )
      .finally(() => setLoading(false));
  }, [planId]);

  if (!planId) {
    return (
      <div className="rounded-lg border border-dashed border-border p-6 text-center text-sm text-muted-foreground">
        Select a plan to view checkpoint history.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-foreground">
          Checkpoint History
        </h3>
        <span className="text-xs text-muted-foreground">
          {records.length} record{records.length !== 1 ? "s" : ""}
        </span>
      </div>

      {loading && (
        <p className="text-sm text-muted-foreground">Loading...</p>
      )}
      {error && <p className="text-sm text-destructive">{error}</p>}

      {!loading && records.length === 0 && !error && (
        <p className="text-sm text-muted-foreground py-4 text-center">
          No checkpoint escalations for this plan.
        </p>
      )}

      <div className="space-y-2">
        {records.map((r) => (
          <button
            key={r.record_id}
            onClick={() =>
              setExpanded(expanded === r.record_id ? null : r.record_id)
            }
            className={`w-full text-left rounded-lg border p-4 transition-colors ${
              expanded === r.record_id
                ? "border-primary bg-primary/5"
                : "border-border bg-card hover:bg-muted/50"
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="font-medium text-foreground">
                {r.tool_name}
              </span>
              <span className="text-xs text-muted-foreground">
                {new Date(r.created_at).toLocaleString()}
              </span>
            </div>
            <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
              <span>Agent: {r.agent_id}</span>
              <span>Pattern: {r.matched_pattern}</span>
            </div>

            {/* Expanded detail */}
            {expanded === r.record_id && (
              <div className="mt-3 space-y-2 border-t border-border pt-3 text-sm">
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <p className="text-xs text-muted-foreground">Session</p>
                    <p className="break-all">{r.session_id}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">Plan ID</p>
                    <p className="break-all">{r.plan_id}</p>
                  </div>
                </div>

                {r.human_intent && (
                  <div>
                    <p className="text-xs text-muted-foreground">
                      Human Intent
                    </p>
                    <p className="text-foreground">{r.human_intent}</p>
                  </div>
                )}

                <div>
                  <p className="text-xs text-muted-foreground">Match Reason</p>
                  <p className="text-foreground">{r.match_reason}</p>
                </div>
              </div>
            )}
          </button>
        ))}
      </div>
    </div>
  );
}
