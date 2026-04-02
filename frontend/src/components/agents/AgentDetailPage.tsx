/**
 * Agent Detail Page — combines profile view, API keys, activity timeline,
 * and delegation chain viewer for a single agent.
 */
import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getAgent, type Agent } from "@/api/agents";
import { APIKeyManager } from "./APIKeyManager";
import { AgentActivityTimeline } from "./AgentActivityTimeline";
import { DelegationChainViewer } from "./DelegationChainViewer";

type Tab = "keys" | "activity" | "delegations";

export function AgentDetailPage() {
  const { agentId } = useParams<{ agentId: string }>();
  const navigate = useNavigate();
  const [agent, setAgent] = useState<Agent | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("activity");

  useEffect(() => {
    if (!agentId) return;
    setLoading(true);
    getAgent(agentId)
      .then(setAgent)
      .catch((e) => setError(e instanceof Error ? e.message : "Load failed"))
      .finally(() => setLoading(false));
  }, [agentId]);

  if (loading) return <p className="text-muted-foreground">Loading...</p>;
  if (error) {
    return (
      <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
        {error}
      </div>
    );
  }
  if (!agent || !agentId) return <p>Agent not found.</p>;

  const tabs: { key: Tab; label: string }[] = [
    { key: "activity", label: "Activity" },
    { key: "keys", label: "API Keys" },
    { key: "delegations", label: "Delegations" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">{agent.name}</h2>
          <p className="font-mono text-sm text-muted-foreground">{agent.agent_id}</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => navigate(`/agents/${agentId}/edit`)}
            className="rounded bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:opacity-90"
          >
            Edit
          </button>
          <button
            onClick={() => navigate("/agents")}
            className="rounded border border-border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Back
          </button>
        </div>
      </div>

      {/* Profile summary cards */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <SummaryCard label="Status" value={agent.enabled ? "Active" : "Disabled"} />
        <SummaryCard label="Roles" value={agent.roles.join(", ") || "none"} />
        <SummaryCard label="Risk Budget" value={agent.risk_budget.toFixed(2)} />
        <SummaryCard label="Decisions" value={String(agent.decision_count)} />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-4 py-2 text-sm font-medium ${
              tab === t.key
                ? "border-b-2 border-primary text-primary"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "activity" && <AgentActivityTimeline agentId={agentId} />}
      {tab === "keys" && <APIKeyManager agentId={agentId} />}
      {tab === "delegations" && <DelegationChainViewer agentId={agentId} />}
    </div>
  );
}

function SummaryCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-lg font-semibold text-card-foreground">{value}</p>
    </div>
  );
}
