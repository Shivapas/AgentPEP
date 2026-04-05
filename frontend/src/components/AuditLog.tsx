import { useState, useEffect } from "react";
import { apiFetch } from "@/lib/api";

interface AuditEntry {
  decision_id: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  decision: string;
  risk_score: number;
  taint_flags: string[];
  latency_ms: number;
  timestamp: string;
  matched_rule_id: string | null;
}

export function AuditLog() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [decisionFilter, setDecisionFilter] = useState<string>("ALL");

  useEffect(() => {
    const load = async () => {
      try {
        const params = new URLSearchParams({ limit: "50" });
        if (decisionFilter !== "ALL") {
          params.set("decision", decisionFilter);
        }
        const resp = await apiFetch(`/v1/audit?${params.toString()}`);
        if (!resp.ok) return;
        const data = (await resp.json()) as { items: AuditEntry[] };
        setEntries(data.items ?? []);
      } catch {
        /* non-critical */
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, [decisionFilter]);

  const decisionColor = (d: string) => {
    switch (d) {
      case "ALLOW": return "text-green-600";
      case "DENY": return "text-red-600";
      case "ESCALATE": return "text-yellow-600";
      case "DRY_RUN": return "text-blue-600";
      default: return "text-muted-foreground";
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Audit Log</h2>
        <select
          value={decisionFilter}
          onChange={(e) => setDecisionFilter(e.target.value)}
          className="rounded-md border border-border bg-background px-3 py-1.5 text-sm"
        >
          <option value="ALL">All Decisions</option>
          <option value="ALLOW">ALLOW</option>
          <option value="DENY">DENY</option>
          <option value="ESCALATE">ESCALATE</option>
          <option value="DRY_RUN">DRY_RUN</option>
        </select>
      </div>

      {loading ? (
        <p className="text-muted-foreground">Loading audit log...</p>
      ) : entries.length === 0 ? (
        <p className="text-muted-foreground">No audit entries found</p>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-muted">
              <tr>
                <th className="px-3 py-2 text-left font-medium">Time</th>
                <th className="px-3 py-2 text-left font-medium">Decision</th>
                <th className="px-3 py-2 text-left font-medium">Agent</th>
                <th className="px-3 py-2 text-left font-medium">Tool</th>
                <th className="px-3 py-2 text-left font-medium">Risk</th>
                <th className="px-3 py-2 text-left font-medium">Taint</th>
                <th className="px-3 py-2 text-left font-medium">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {entries.map((e) => (
                <tr key={e.decision_id} className="hover:bg-muted/50">
                  <td className="px-3 py-2 text-xs text-muted-foreground">
                    {new Date(e.timestamp).toLocaleString()}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`font-mono font-semibold ${decisionColor(e.decision)}`}>
                      {e.decision}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono">{e.agent_id}</td>
                  <td className="px-3 py-2">{e.tool_name}</td>
                  <td className="px-3 py-2">
                    <RiskBadge score={e.risk_score} />
                  </td>
                  <td className="px-3 py-2">
                    {e.taint_flags.length > 0 ? (
                      <span className="text-xs text-yellow-600">
                        {e.taint_flags.join(", ")}
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">none</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-xs">{e.latency_ms}ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function RiskBadge({ score }: { score: number }) {
  let color = "bg-green-100 text-green-800";
  if (score > 0.7) color = "bg-red-100 text-red-800";
  else if (score > 0.4) color = "bg-yellow-100 text-yellow-800";

  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-mono ${color}`}>
      {score.toFixed(2)}
    </span>
  );
}
