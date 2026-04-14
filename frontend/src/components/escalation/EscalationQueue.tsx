import { useState } from "react";
import type { EscalationTicket } from "../../types/escalation";
import { useEscalationWs } from "../../hooks/useEscalationWs";
import { SlaTimer } from "./SlaTimer";
import { EscalationDetailPanel } from "./EscalationDetailPanel";
import { BulkApproveDialog } from "./BulkApproveDialog";
import { CheckpointHistory } from "./CheckpointHistory";

type Tab = "queue" | "checkpoint_history";

/**
 * Real-time escalation queue view (APEP-143).
 * Shows pending tickets via WebSocket, SLA timers (APEP-147),
 * detail panel (APEP-144), actions (APEP-145), and bulk approve (APEP-146).
 * Sprint 41 — APEP-329: Adds Checkpoint History tab.
 */
export function EscalationQueue() {
  const { tickets, connected } = useEscalationWs();
  const [selected, setSelected] = useState<EscalationTicket | null>(null);
  const [showBulk, setShowBulk] = useState(false);
  const [activeTab, setActiveTab] = useState<Tab>("queue");
  const [checkpointPlanId, setCheckpointPlanId] = useState("");

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Escalation Queue</h2>
          <p className="text-sm text-muted-foreground">
            {connected ? (
              <span className="text-green-600">Connected</span>
            ) : (
              <span className="text-destructive">Disconnected — reconnecting...</span>
            )}
            {" · "}
            {tickets.length} pending
          </p>
        </div>
        <button
          onClick={() => setShowBulk(!showBulk)}
          className="rounded border border-border px-4 py-2 text-sm hover:bg-muted"
        >
          Bulk Approve
        </button>
      </div>

      {/* Bulk approve dialog (APEP-146) */}
      {showBulk && <BulkApproveDialog onDone={() => setShowBulk(false)} />}

      {/* Tab bar (Sprint 41 — APEP-329) */}
      <div className="flex gap-1 border-b border-border">
        <button
          onClick={() => setActiveTab("queue")}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === "queue"
              ? "border-b-2 border-primary text-primary"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Queue
        </button>
        <button
          onClick={() => setActiveTab("checkpoint_history")}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === "checkpoint_history"
              ? "border-b-2 border-primary text-primary"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          Checkpoint History
        </button>
      </div>

      {/* Queue tab */}
      {activeTab === "queue" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Ticket list */}
          <div className="space-y-2">
            {tickets.length === 0 && (
              <p className="text-muted-foreground py-8 text-center">
                No pending escalations.
              </p>
            )}
            {tickets.map((t) => (
              <button
                key={t.ticket_id}
                onClick={() => setSelected(t)}
                className={`w-full text-left rounded-lg border p-4 transition-colors ${
                  selected?.ticket_id === t.ticket_id
                    ? "border-primary bg-primary/5"
                    : "border-border bg-card hover:bg-muted/50"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium text-foreground">
                    {t.tool_name}
                  </span>
                  <SlaTimer deadline={t.sla_deadline} />
                </div>
                <div className="mt-1 flex items-center gap-3 text-xs text-muted-foreground">
                  <span>Agent: {t.agent_id}</span>
                  <span>Risk: {t.risk_score.toFixed(2)}</span>
                  {t.taint_flags.length > 0 && (
                    <span className="text-destructive">
                      {t.taint_flags.length} taint flag(s)
                    </span>
                  )}
                </div>
                {t.reason && (
                  <p className="mt-1 text-xs text-muted-foreground truncate">
                    {t.reason}
                  </p>
                )}
              </button>
            ))}
          </div>

          {/* Detail panel (APEP-144 / APEP-145) */}
          <div>
            {selected ? (
              <EscalationDetailPanel
                ticket={selected}
                onResolved={() => setSelected(null)}
                onClose={() => setSelected(null)}
              />
            ) : (
              <div className="flex h-48 items-center justify-center rounded-lg border border-dashed border-border">
                <p className="text-muted-foreground text-sm">
                  Select a ticket to view details
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Checkpoint History tab (Sprint 41 — APEP-329) */}
      {activeTab === "checkpoint_history" && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={checkpointPlanId}
              onChange={(e) => setCheckpointPlanId(e.target.value)}
              placeholder="Enter Plan ID to view checkpoint history..."
              className="flex-1 rounded border border-border bg-background px-3 py-2 text-sm"
            />
          </div>
          <CheckpointHistory
            planId={checkpointPlanId || undefined}
          />
        </div>
      )}
    </div>
  );
}
