/**
 * Escalation queue view — real-time list of PENDING tickets via WebSocket (APEP-143).
 * Integrates detail panel (APEP-144), actions (APEP-145), bulk approve (APEP-146), SLA timer (APEP-147).
 */
import { useMemo, useState } from "react";
import { useEscalationQueue } from "../hooks/useEscalationQueue";
import type { EscalationTicket } from "../types/escalation";
import { BulkApprove } from "./BulkApprove";
import { EscalationDetail } from "./EscalationDetail";
import { SlaTimer } from "./SlaTimer";

function riskColor(score: number): string {
  if (score >= 0.8) return "text-red-600 font-semibold";
  if (score >= 0.5) return "text-amber-500 font-medium";
  return "text-muted-foreground";
}

export function EscalationQueue() {
  const { tickets, connected, refresh } = useEscalationQueue();
  const [selected, setSelected] = useState<EscalationTicket | null>(null);
  const [bulkTool, setBulkTool] = useState<string | null>(null);

  const pendingTickets = useMemo(
    () => tickets.filter((t) => t.status === "PENDING"),
    [tickets]
  );

  // Group by tool_name for bulk actions
  const toolGroups = useMemo(() => {
    const groups: Record<string, number> = {};
    for (const t of pendingTickets) {
      groups[t.tool_name] = (groups[t.tool_name] || 0) + 1;
    }
    return groups;
  }, [pendingTickets]);

  const bulkMatchCount = bulkTool ? toolGroups[bulkTool] || 0 : 0;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h2 className="text-2xl font-bold">Escalation Queue</h2>
          <span
            className={`h-2.5 w-2.5 rounded-full ${connected ? "bg-green-500" : "bg-red-500"}`}
            title={connected ? "WebSocket connected" : "Disconnected"}
          />
          <span className="rounded-full bg-muted px-2.5 py-0.5 text-xs font-medium">
            {pendingTickets.length} pending
          </span>
        </div>
        <button
          onClick={refresh}
          className="rounded border border-border px-3 py-1.5 text-sm hover:bg-muted"
        >
          Refresh
        </button>
      </div>

      {/* Bulk approve bar */}
      {Object.entries(toolGroups)
        .filter(([, count]) => count >= 2)
        .map(([tool, count]) => (
          <button
            key={tool}
            onClick={() => setBulkTool(tool)}
            className="mr-2 rounded border border-amber-300 bg-amber-50 px-3 py-1 text-xs font-medium text-amber-800 hover:bg-amber-100"
          >
            Bulk approve {count}x {tool}
          </button>
        ))}

      {bulkTool && (
        <BulkApprove
          toolPattern={bulkTool}
          matchCount={bulkMatchCount}
          onComplete={() => {
            setBulkTool(null);
            refresh();
          }}
          onCancel={() => setBulkTool(null)}
        />
      )}

      {/* Queue table */}
      {pendingTickets.length === 0 ? (
        <p className="text-muted-foreground">No pending escalations.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-muted/50">
              <tr>
                <th className="px-4 py-2 text-left font-medium">Tool</th>
                <th className="px-4 py-2 text-left font-medium">Agent</th>
                <th className="px-4 py-2 text-left font-medium">Risk</th>
                <th className="px-4 py-2 text-left font-medium">Taint</th>
                <th className="px-4 py-2 text-left font-medium">SLA</th>
                <th className="px-4 py-2 text-left font-medium">Reason</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {pendingTickets.map((ticket) => (
                <tr
                  key={ticket.escalation_id}
                  className="cursor-pointer hover:bg-muted/30"
                  onClick={() => setSelected(ticket)}
                >
                  <td className="px-4 py-2 font-mono text-xs">
                    {ticket.tool_name}
                  </td>
                  <td className="px-4 py-2">{ticket.agent_id}</td>
                  <td className={`px-4 py-2 ${riskColor(ticket.risk_score)}`}>
                    {(ticket.risk_score * 100).toFixed(0)}%
                  </td>
                  <td className="px-4 py-2">
                    {ticket.taint_flags.length > 0 ? (
                      <span className="rounded bg-amber-100 px-1.5 py-0.5 text-xs text-amber-800">
                        {ticket.taint_flags.length} flags
                      </span>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="px-4 py-2">
                    <SlaTimer
                      deadline={ticket.sla_deadline}
                      autoDecision={ticket.auto_decision}
                    />
                  </td>
                  <td className="max-w-xs truncate px-4 py-2 text-muted-foreground">
                    {ticket.reason || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Detail panel */}
      {selected && (
        <EscalationDetail
          ticket={selected}
          onClose={() => setSelected(null)}
          onResolved={() => {
            setSelected(null);
            refresh();
          }}
        />
      )}
    </div>
  );
}
