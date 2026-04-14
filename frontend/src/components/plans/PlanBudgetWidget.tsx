/**
 * APEP-337 — Plan Budget Widget for Risk Dashboard
 * Shows active plan budget utilisation as a compact card.
 */
import { useEffect, useState, useCallback } from "react";
import { listPlans, getBudgetStatus } from "@/api/plans";
import type { BudgetStatusResponse } from "@/types/plans";
import { cn } from "@/lib/utils";

interface PlanBudgetSummary {
  plan_id: string;
  action: string;
  status: string;
  delegation_pct: number | null;
  risk_pct: number | null;
  ttl_pct: number | null;
  exhausted_dimensions: string[];
}

export function PlanBudgetWidget() {
  const [plans, setPlans] = useState<PlanBudgetSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listPlans({ status: "ACTIVE", limit: 10 });
      const summaries: PlanBudgetSummary[] = [];

      // Fetch budget status for each active plan
      const budgets = await Promise.allSettled(
        res.plans.map((p) => getBudgetStatus(p.plan_id)),
      );

      for (let i = 0; i < res.plans.length; i++) {
        const plan = res.plans[i]!;
        const result = budgets[i]!;
        const budget: BudgetStatusResponse | null =
          result.status === "fulfilled" ? (result as PromiseFulfilledResult<BudgetStatusResponse>).value : null;

        summaries.push({
          plan_id: plan.plan_id,
          action: plan.action,
          status: budget?.status ?? plan.status,
          delegation_pct: budget?.budget_utilization?.delegation_pct ?? null,
          risk_pct: budget?.budget_utilization?.risk_pct ?? null,
          ttl_pct: budget?.budget_utilization?.ttl_pct ?? null,
          exhausted_dimensions: budget?.exhausted_dimensions ?? [],
        });
      }

      setPlans(summaries);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load plan budgets");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading) {
    return <p className="text-sm text-muted-foreground">Loading plan budgets...</p>;
  }

  if (error) {
    return <p className="text-sm text-destructive">{error}</p>;
  }

  if (plans.length === 0) {
    return <p className="text-sm text-muted-foreground">No active plans.</p>;
  }

  return (
    <div className="space-y-3">
      {plans.map((p) => (
        <PlanBudgetRow key={p.plan_id} plan={p} />
      ))}
    </div>
  );
}

function PlanBudgetRow({ plan }: { plan: PlanBudgetSummary }) {
  const hasExhausted = plan.exhausted_dimensions.length > 0;

  return (
    <div className={cn(
      "rounded-lg border p-3",
      hasExhausted ? "border-yellow-500 bg-yellow-500/5" : "border-border bg-card",
    )}>
      <div className="mb-2 flex items-center justify-between">
        <span className="max-w-[200px] truncate text-sm font-medium" title={plan.action}>
          {plan.action}
        </span>
        <span className="font-mono text-xs text-muted-foreground">
          {plan.plan_id.slice(0, 8)}...
        </span>
      </div>

      <div className="flex gap-3">
        {plan.delegation_pct != null && (
          <MiniBar label="Del" pct={plan.delegation_pct} />
        )}
        {plan.risk_pct != null && (
          <MiniBar label="Risk" pct={plan.risk_pct} />
        )}
        {plan.ttl_pct != null && (
          <MiniBar label="TTL" pct={plan.ttl_pct} />
        )}
        {plan.delegation_pct == null && plan.risk_pct == null && plan.ttl_pct == null && (
          <span className="text-xs text-muted-foreground">Unlimited budget</span>
        )}
      </div>

      {hasExhausted && (
        <p className="mt-1 text-xs text-yellow-600">
          Exhausted: {plan.exhausted_dimensions.join(", ")}
        </p>
      )}
    </div>
  );
}

function MiniBar({ label, pct }: { label: string; pct: number }) {
  const color =
    pct >= 90 ? "bg-red-500" : pct >= 70 ? "bg-yellow-500" : "bg-green-500";

  return (
    <div className="flex-1">
      <div className="mb-0.5 flex items-center justify-between text-xs text-muted-foreground">
        <span>{label}</span>
        <span>{Math.round(pct)}%</span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-muted">
        <div
          className={cn("h-1.5 rounded-full transition-all", color)}
          style={{ width: `${Math.min(pct, 100)}%` }}
        />
      </div>
    </div>
  );
}
