/**
 * APEP-332 — Plan Management List Screen
 * Sortable table with status, issuer, budget info, and actions.
 */
import { useEffect, useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { cn } from "@/lib/utils";
import { listPlans, revokePlan } from "@/api/plans";
import type { PlanDetail, PlanListResponse } from "@/types/plans";

type SortField = "issued_at" | "action" | "issuer" | "status";

const STATUS_OPTIONS = ["", "ACTIVE", "EXPIRED", "REVOKED"];

export function PlanManagementList() {
  const navigate = useNavigate();
  const [data, setData] = useState<PlanListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<SortField>("issued_at");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [statusFilter, setStatusFilter] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listPlans({
        sort_by: sortBy,
        sort_dir: sortDir,
        status: statusFilter || undefined,
      });
      setData(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load plans");
    } finally {
      setLoading(false);
    }
  }, [sortBy, sortDir, statusFilter]);

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

  function toggleSelect(planId: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(planId)) next.delete(planId);
      else next.add(planId);
      return next;
    });
  }

  function toggleAll() {
    if (!data) return;
    if (selected.size === data.plans.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(data.plans.map((p) => p.plan_id)));
    }
  }

  async function handleRevoke(planId: string) {
    if (!confirm(`Revoke plan "${planId}"?`)) return;
    try {
      await revokePlan(planId);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Revoke failed");
    }
  }

  const sortArrow = (field: SortField) =>
    sortBy === field ? (sortDir === "asc" ? " \u2191" : " \u2193") : "";

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Plan Management</h2>
        <div className="flex gap-2">
          {selected.size > 0 && (
            <span className="rounded bg-secondary px-3 py-1.5 text-sm font-medium text-secondary-foreground">
              {selected.size} selected
            </span>
          )}
          <button
            onClick={() => navigate("/plans/new")}
            className="rounded bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:opacity-90"
          >
            + Issue Plan
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded border border-border bg-background px-3 py-1.5 text-sm text-foreground"
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s || "All statuses"}
            </option>
          ))}
        </select>
      </div>

      {error && (
        <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      {loading ? (
        <p className="text-muted-foreground">Loading plans...</p>
      ) : !data || data.plans.length === 0 ? (
        <p className="text-muted-foreground">No plans found.</p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-border bg-muted/50">
                <tr>
                  <th className="px-3 py-2">
                    <input
                      type="checkbox"
                      checked={selected.size === data.plans.length}
                      onChange={toggleAll}
                      className="accent-primary"
                    />
                  </th>
                  <Th field="action" label="Action" sortBy={sortBy} sortArrow={sortArrow} onClick={toggleSort} />
                  <Th field="issuer" label="Issuer" sortBy={sortBy} sortArrow={sortArrow} onClick={toggleSort} />
                  <Th field="status" label="Status" sortBy={sortBy} sortArrow={sortArrow} onClick={toggleSort} />
                  <th className="px-3 py-2 font-medium text-muted-foreground">Budget</th>
                  <th className="px-3 py-2 font-medium text-muted-foreground">Delegations</th>
                  <Th field="issued_at" label="Issued" sortBy={sortBy} sortArrow={sortArrow} onClick={toggleSort} />
                  <th className="px-3 py-2 font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.plans.map((plan) => (
                  <PlanRow
                    key={plan.plan_id}
                    plan={plan}
                    selected={selected.has(plan.plan_id)}
                    onToggle={() => toggleSelect(plan.plan_id)}
                    onView={() => navigate(`/plans/${plan.plan_id}`)}
                    onExplore={() => navigate(`/plans/${plan.plan_id}/explorer`)}
                    onRevoke={() => handleRevoke(plan.plan_id)}
                  />
                ))}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-muted-foreground">{data.total} plan(s) total</p>
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

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "ACTIVE"
      ? "bg-green-500/10 text-green-600"
      : status === "EXPIRED"
        ? "bg-yellow-500/10 text-yellow-600"
        : "bg-red-500/10 text-red-500";
  return (
    <span className={cn("inline-block rounded-full px-2 py-0.5 text-xs font-medium", cls)}>
      {status}
    </span>
  );
}

function PlanRow({
  plan,
  selected,
  onToggle,
  onView,
  onExplore,
  onRevoke,
}: {
  plan: PlanDetail;
  selected: boolean;
  onToggle: () => void;
  onView: () => void;
  onExplore: () => void;
  onRevoke: () => void;
}) {
  const budgetLabel = formatBudget(plan);
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
      <td className="max-w-[200px] truncate px-3 py-2 font-medium" title={plan.action}>
        {plan.action}
      </td>
      <td className="px-3 py-2">{plan.issuer}</td>
      <td className="px-3 py-2">
        <StatusBadge status={plan.status} />
      </td>
      <td className="px-3 py-2 text-xs text-muted-foreground">{budgetLabel}</td>
      <td className="px-3 py-2 text-center">{plan.delegation_count}</td>
      <td className="whitespace-nowrap px-3 py-2 text-xs">
        {new Date(plan.issued_at).toLocaleString()}
      </td>
      <td className="px-3 py-2">
        <div className="flex gap-1">
          <button
            onClick={onView}
            className="rounded px-2 py-1 text-xs text-primary hover:bg-primary/10"
          >
            View
          </button>
          <button
            onClick={onExplore}
            className="rounded px-2 py-1 text-xs text-primary hover:bg-primary/10"
          >
            Explorer
          </button>
          {plan.status === "ACTIVE" && (
            <button
              onClick={onRevoke}
              className="rounded px-2 py-1 text-xs text-destructive hover:bg-destructive/10"
            >
              Revoke
            </button>
          )}
        </div>
      </td>
    </tr>
  );
}

function formatBudget(plan: PlanDetail): string {
  const parts: string[] = [];
  if (plan.budget.max_delegations != null)
    parts.push(`${plan.delegation_count}/${plan.budget.max_delegations} del`);
  if (plan.budget.max_risk_total != null)
    parts.push(`${plan.accumulated_risk.toFixed(2)}/${plan.budget.max_risk_total} risk`);
  if (plan.budget.ttl_seconds != null)
    parts.push(`TTL ${plan.budget.ttl_seconds}s`);
  return parts.length > 0 ? parts.join(", ") : "Unlimited";
}
