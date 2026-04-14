/**
 * APEP-136 / APEP-137 — Audit Explorer main view.
 *
 * Paginated decision table with column filters and full-text search.
 */

import { useCallback, useEffect, useState } from "react";
import {
  fetchDecisions,
  type AuditDecision,
  type DecisionFilters,
  type PaginatedResponse,
} from "@/lib/api";
import { DecisionDetailPanel } from "./DecisionDetailPanel";
import { AuditExportBar } from "./AuditExportBar";
import { HashChainIndicator } from "./HashChainIndicator";
import { cn } from "@/lib/utils";

const DECISIONS = ["", "ALLOW", "DENY", "ESCALATE", "DRY_RUN", "TIMEOUT"];

export function AuditExplorer() {
  const [data, setData] = useState<PaginatedResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Filters
  const [filters, setFilters] = useState<DecisionFilters>({
    page: 1,
    page_size: 25,
    sort_field: "timestamp",
    sort_order: "desc",
  });
  const [search, setSearch] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const f: DecisionFilters = { ...filters };
      if (search) f.search = search;
      const result = await fetchDecisions(f);
      setData(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, [filters, search]);

  useEffect(() => {
    void load();
  }, [load]);

  const updateFilter = (key: keyof DecisionFilters, value: string) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value || undefined,
      page: 1,
    }));
  };

  const setPage = (page: number) => {
    setFilters((prev) => ({ ...prev, page }));
  };

  const toggleSort = (field: string) => {
    setFilters((prev) => ({
      ...prev,
      sort_field: field,
      sort_order:
        prev.sort_field === field && prev.sort_order === "asc" ? "desc" : "asc",
    }));
  };

  const sortIndicator = (field: string) => {
    if (filters.sort_field !== field) return "";
    return filters.sort_order === "asc" ? " ↑" : " ↓";
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Audit Explorer</h2>
        <HashChainIndicator filters={filters} search={search} />
      </div>

      {/* Search + filters */}
      <div className="flex flex-wrap gap-2">
        <input
          type="text"
          placeholder="Search decisions..."
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setFilters((p) => ({ ...p, page: 1 }));
          }}
          className="rounded border border-border bg-background px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
        />
        <input
          type="text"
          placeholder="Session ID"
          onChange={(e) => updateFilter("session_id", e.target.value)}
          className="rounded border border-border bg-background px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
        />
        <input
          type="text"
          placeholder="Agent ID"
          onChange={(e) => updateFilter("agent_id", e.target.value)}
          className="rounded border border-border bg-background px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
        />
        <input
          type="text"
          placeholder="Tool name"
          onChange={(e) => updateFilter("tool_name", e.target.value)}
          className="rounded border border-border bg-background px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
        />
        <input
          type="text"
          placeholder="Plan ID"
          onChange={(e) => updateFilter("plan_id", e.target.value)}
          className="rounded border border-border bg-background px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
        />
        <select
          onChange={(e) => updateFilter("decision", e.target.value)}
          className="rounded border border-border bg-background px-3 py-1.5 text-sm text-foreground"
        >
          {DECISIONS.map((d) => (
            <option key={d} value={d}>
              {d || "All decisions"}
            </option>
          ))}
        </select>
        <input
          type="number"
          placeholder="Risk min"
          min={0}
          max={1}
          step={0.1}
          onChange={(e) => updateFilter("risk_min", e.target.value)}
          className="w-24 rounded border border-border bg-background px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
        />
        <input
          type="number"
          placeholder="Risk max"
          min={0}
          max={1}
          step={0.1}
          onChange={(e) => updateFilter("risk_max", e.target.value)}
          className="w-24 rounded border border-border bg-background px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
        />
      </div>

      {/* Export bar */}
      <AuditExportBar filters={filters} search={search} />

      {error && (
        <p className="text-sm text-destructive">{error}</p>
      )}

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-sm">
          <thead className="border-b border-border bg-muted/50">
            <tr>
              {[
                { key: "timestamp", label: "Time" },
                { key: "session_id", label: "Session" },
                { key: "agent_id", label: "Agent" },
                { key: "tool_name", label: "Tool" },
                { key: "decision", label: "Decision" },
                { key: "risk_score", label: "Risk" },
                { key: "latency_ms", label: "Latency" },
              ].map(({ key, label }) => (
                <th
                  key={key}
                  onClick={() => toggleSort(key)}
                  className="cursor-pointer px-3 py-2 text-left font-medium text-muted-foreground hover:text-foreground"
                >
                  {label}
                  {sortIndicator(key)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={7} className="px-3 py-8 text-center text-muted-foreground">
                  Loading...
                </td>
              </tr>
            )}
            {!loading && data?.items.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-8 text-center text-muted-foreground">
                  No audit decisions found.
                </td>
              </tr>
            )}
            {!loading &&
              data?.items.map((item) => (
                <DecisionRow
                  key={item.decision_id}
                  item={item}
                  selected={selectedId === item.decision_id}
                  onSelect={() =>
                    setSelectedId(
                      selectedId === item.decision_id ? null : item.decision_id,
                    )
                  }
                />
              ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {data && data.total_pages > 1 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">
            {data.total} records — page {data.page} of {data.total_pages}
          </span>
          <div className="flex gap-1">
            <button
              disabled={data.page <= 1}
              onClick={() => setPage(data.page - 1)}
              className="rounded border border-border px-3 py-1 hover:bg-muted disabled:opacity-40"
            >
              Prev
            </button>
            <button
              disabled={data.page >= data.total_pages}
              onClick={() => setPage(data.page + 1)}
              className="rounded border border-border px-3 py-1 hover:bg-muted disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      )}

      {/* Side panel */}
      {selectedId && (
        <DecisionDetailPanel
          decisionId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}

function DecisionRow({
  item,
  selected,
  onSelect,
}: {
  item: AuditDecision;
  selected: boolean;
  onSelect: () => void;
}) {
  const badge = decisionBadge(item.decision);
  return (
    <tr
      onClick={onSelect}
      className={cn(
        "cursor-pointer border-b border-border hover:bg-muted/50",
        selected && "bg-muted",
      )}
    >
      <td className="whitespace-nowrap px-3 py-2">
        {new Date(item.timestamp).toLocaleString()}
      </td>
      <td className="max-w-[120px] truncate px-3 py-2" title={item.session_id}>
        {item.session_id}
      </td>
      <td className="px-3 py-2">{item.agent_id}</td>
      <td className="px-3 py-2">{item.tool_name}</td>
      <td className="px-3 py-2">
        <span className={cn("rounded px-2 py-0.5 text-xs font-medium", badge)}>
          {item.decision}
        </span>
      </td>
      <td className="px-3 py-2">{item.risk_score.toFixed(2)}</td>
      <td className="px-3 py-2">{item.latency_ms}ms</td>
    </tr>
  );
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
