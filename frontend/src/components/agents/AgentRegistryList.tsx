/**
 * APEP-121 — Agent Registry List View
 * Sortable table with role, status, and decision counts.
 */
import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { cn } from "@/lib/utils";
import {
  listAgents,
  deleteAgent,
  type Agent,
  type AgentListResponse,
} from "@/api/agents";

type SortField = "agent_id" | "name" | "enabled" | "risk_budget" | "decision_count";

export function AgentRegistryList() {
  const navigate = useNavigate();
  const [data, setData] = useState<AgentListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<SortField>("agent_id");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listAgents({ sort_by: sortBy, sort_dir: sortDir });
      setData(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load agents");
    } finally {
      setLoading(false);
    }
  }, [sortBy, sortDir]);

  useEffect(() => {
    void load();
  }, [load]);

  function toggleSort(field: SortField) {
    if (sortBy === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(field);
      setSortDir("asc");
    }
  }

  function toggleSelect(agentId: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(agentId)) next.delete(agentId);
      else next.add(agentId);
      return next;
    });
  }

  function toggleAll() {
    if (!data) return;
    if (selected.size === data.agents.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(data.agents.map((a) => a.agent_id)));
    }
  }

  async function handleDelete(agentId: string) {
    if (!confirm(`Delete agent "${agentId}"?`)) return;
    try {
      await deleteAgent(agentId);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed");
    }
  }

  const sortArrow = (field: SortField) =>
    sortBy === field ? (sortDir === "asc" ? " \u2191" : " \u2193") : "";

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Agent Registry</h2>
        <div className="flex gap-2">
          {selected.size > 0 && (
            <button
              onClick={() => navigate("/agents/bulk-roles", { state: { agentIds: [...selected] } })}
              className="rounded bg-secondary px-3 py-1.5 text-sm font-medium text-secondary-foreground hover:opacity-90"
            >
              Assign Roles ({selected.size})
            </button>
          )}
          <button
            onClick={() => navigate("/agents/new")}
            className="rounded bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:opacity-90"
          >
            + Register Agent
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      {loading ? (
        <p className="text-muted-foreground">Loading agents...</p>
      ) : !data || data.agents.length === 0 ? (
        <p className="text-muted-foreground">No agents registered yet.</p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-border bg-muted/50">
                <tr>
                  <th className="px-3 py-2">
                    <input
                      type="checkbox"
                      checked={selected.size === data.agents.length}
                      onChange={toggleAll}
                      className="accent-primary"
                    />
                  </th>
                  <Th field="agent_id" label="Agent ID" sortBy={sortBy} sortArrow={sortArrow} onClick={toggleSort} />
                  <Th field="name" label="Name" sortBy={sortBy} sortArrow={sortArrow} onClick={toggleSort} />
                  <th className="px-3 py-2 font-medium text-muted-foreground">Roles</th>
                  <Th field="enabled" label="Status" sortBy={sortBy} sortArrow={sortArrow} onClick={toggleSort} />
                  <Th field="risk_budget" label="Risk Budget" sortBy={sortBy} sortArrow={sortArrow} onClick={toggleSort} />
                  <Th field="decision_count" label="Decisions" sortBy={sortBy} sortArrow={sortArrow} onClick={toggleSort} />
                  <th className="px-3 py-2 font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.agents.map((agent) => (
                  <AgentRow
                    key={agent.agent_id}
                    agent={agent}
                    selected={selected.has(agent.agent_id)}
                    onToggle={() => toggleSelect(agent.agent_id)}
                    onView={() => navigate(`/agents/${agent.agent_id}`)}
                    onDelete={() => handleDelete(agent.agent_id)}
                  />
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-muted-foreground">{data.total} agent(s) total</p>
        </>
      )}
    </div>
  );
}

function Th({
  field,
  label,
  sortBy,
  sortArrow,
  onClick,
}: {
  field: SortField;
  label: string;
  sortBy: SortField;
  sortArrow: (f: SortField) => string;
  onClick: (f: SortField) => void;
}) {
  return (
    <th
      className={cn(
        "cursor-pointer select-none px-3 py-2 font-medium text-muted-foreground hover:text-foreground",
        sortBy === field && "text-foreground",
      )}
      onClick={() => onClick(field)}
    >
      {label}
      {sortArrow(field)}
    </th>
  );
}

function AgentRow({
  agent,
  selected,
  onToggle,
  onView,
  onDelete,
}: {
  agent: Agent;
  selected: boolean;
  onToggle: () => void;
  onView: () => void;
  onDelete: () => void;
}) {
  return (
    <tr className="border-b border-border last:border-0 hover:bg-muted/30">
      <td className="px-3 py-2">
        <input
          type="checkbox"
          checked={selected}
          onChange={onToggle}
          className="accent-primary"
        />
      </td>
      <td className="px-3 py-2 font-mono text-xs">{agent.agent_id}</td>
      <td className="px-3 py-2">{agent.name}</td>
      <td className="px-3 py-2">
        <div className="flex flex-wrap gap-1">
          {agent.roles.length > 0
            ? agent.roles.map((r) => (
                <span
                  key={r}
                  className="rounded bg-primary/10 px-1.5 py-0.5 text-xs text-primary"
                >
                  {r}
                </span>
              ))
            : <span className="text-xs text-muted-foreground">none</span>}
        </div>
      </td>
      <td className="px-3 py-2">
        <span
          className={cn(
            "inline-block rounded-full px-2 py-0.5 text-xs font-medium",
            agent.enabled
              ? "bg-green-500/10 text-green-600"
              : "bg-red-500/10 text-red-500",
          )}
        >
          {agent.enabled ? "Active" : "Disabled"}
        </span>
      </td>
      <td className="px-3 py-2 text-center">{agent.risk_budget.toFixed(2)}</td>
      <td className="px-3 py-2 text-center">{agent.decision_count}</td>
      <td className="px-3 py-2">
        <div className="flex gap-1">
          <button
            onClick={onView}
            className="rounded px-2 py-1 text-xs text-primary hover:bg-primary/10"
          >
            View
          </button>
          <button
            onClick={onDelete}
            className="rounded px-2 py-1 text-xs text-destructive hover:bg-destructive/10"
          >
            Delete
          </button>
        </div>
      </td>
    </tr>
  );
}
