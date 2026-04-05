import { useState, useEffect } from "react";
import { apiFetch } from "@/lib/api";

interface AgentProfile {
  agent_id: string;
  name: string;
  roles: string[];
  allowed_tools: string[];
  risk_budget: number;
  max_delegation_depth: number;
  enabled: boolean;
}

export function AgentProfiles() {
  const [agents, setAgents] = useState<AgentProfile[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const resp = await apiFetch("/v1/console/agents");
        if (!resp.ok) return;
        const data = (await resp.json()) as { items: AgentProfile[] };
        setAgents(data.items ?? []);
      } catch {
        /* non-critical */
      } finally {
        setLoading(false);
      }
    };
    void load();
  }, []);

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Agent Profiles</h2>

      {loading ? (
        <p className="text-muted-foreground">Loading agents...</p>
      ) : agents.length === 0 ? (
        <p className="text-muted-foreground">No agent profiles found</p>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {agents.map((agent) => (
            <div
              key={agent.agent_id}
              className="rounded-lg border border-border bg-card p-4"
            >
              <div className="flex items-center justify-between">
                <h3 className="font-semibold text-card-foreground">
                  {agent.name}
                </h3>
                <span
                  className={`inline-block h-2 w-2 rounded-full ${agent.enabled ? "bg-green-500" : "bg-gray-400"}`}
                />
              </div>
              <p className="mt-1 font-mono text-xs text-muted-foreground">
                {agent.agent_id}
              </p>
              <div className="mt-3 space-y-1 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Roles</span>
                  <span>{agent.roles.join(", ") || "none"}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Risk Budget</span>
                  <span>{(agent.risk_budget * 100).toFixed(0)}%</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Max Delegation</span>
                  <span>{agent.max_delegation_depth}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Allowed Tools</span>
                  <span className="text-right font-mono text-xs">
                    {agent.allowed_tools.length > 0
                      ? agent.allowed_tools.slice(0, 3).join(", ") +
                        (agent.allowed_tools.length > 3 ? "..." : "")
                      : "none"}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
