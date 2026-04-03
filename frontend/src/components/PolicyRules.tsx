import { useState, useEffect } from "react";

interface PolicyRule {
  rule_id: string;
  name: string;
  agent_role: string[];
  tool_pattern: string;
  action: string;
  priority: number;
  enabled: boolean;
  taint_check: boolean;
  risk_threshold: number;
}

export function PolicyRules() {
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    const load = async () => {
      try {
        const resp = await fetch("/api/v1/rules");
        if (!resp.ok) return;
        const data = (await resp.json()) as { items: PolicyRule[] };
        setRules(data.items ?? []);
      } catch {
        /* non-critical */
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, []);

  const filtered = rules.filter(
    (r) =>
      r.name.toLowerCase().includes(filter.toLowerCase()) ||
      r.tool_pattern.toLowerCase().includes(filter.toLowerCase()),
  );

  const actionBadge = (action: string) => {
    const colors: Record<string, string> = {
      ALLOW: "bg-green-100 text-green-800",
      DENY: "bg-red-100 text-red-800",
      ESCALATE: "bg-yellow-100 text-yellow-800",
      DRY_RUN: "bg-blue-100 text-blue-800",
    };
    return colors[action] ?? "bg-gray-100 text-gray-800";
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Policy Rules</h2>
        <input
          type="text"
          placeholder="Filter rules..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="rounded-md border border-border bg-background px-3 py-1.5 text-sm"
        />
      </div>

      {loading ? (
        <p className="text-muted-foreground">Loading rules...</p>
      ) : filtered.length === 0 ? (
        <p className="text-muted-foreground">No policy rules found</p>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <table className="w-full text-sm">
            <thead className="bg-muted">
              <tr>
                <th className="px-4 py-2 text-left font-medium">Priority</th>
                <th className="px-4 py-2 text-left font-medium">Name</th>
                <th className="px-4 py-2 text-left font-medium">Tool Pattern</th>
                <th className="px-4 py-2 text-left font-medium">Roles</th>
                <th className="px-4 py-2 text-left font-medium">Action</th>
                <th className="px-4 py-2 text-left font-medium">Taint</th>
                <th className="px-4 py-2 text-left font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((rule) => (
                <tr key={rule.rule_id} className="hover:bg-muted/50">
                  <td className="px-4 py-2 font-mono">{rule.priority}</td>
                  <td className="px-4 py-2 font-medium">{rule.name}</td>
                  <td className="px-4 py-2 font-mono text-muted-foreground">
                    {rule.tool_pattern}
                  </td>
                  <td className="px-4 py-2">
                    {rule.agent_role.join(", ")}
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={`inline-block rounded-full px-2 py-0.5 text-xs font-semibold ${actionBadge(rule.action)}`}
                    >
                      {rule.action}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    {rule.taint_check ? "Yes" : "No"}
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={`inline-block h-2 w-2 rounded-full ${rule.enabled ? "bg-green-500" : "bg-gray-400"}`}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
