/**
 * APEP-334 — Plan Detail Screen
 * View plan metadata, budget status, receipt chain summary, and approval history.
 */
import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getPlan, getBudgetStatus, getPlanReceiptsSummary, revokePlan } from "@/api/plans";
import type { PlanDetail, BudgetStatusResponse, ReceiptChainSummary } from "@/types/plans";
import { cn } from "@/lib/utils";

type Tab = "budget" | "receipts" | "scope";

export function PlanDetailPage() {
  const { planId } = useParams<{ planId: string }>();
  const navigate = useNavigate();
  const [plan, setPlan] = useState<PlanDetail | null>(null);
  const [budget, setBudget] = useState<BudgetStatusResponse | null>(null);
  const [summary, setSummary] = useState<ReceiptChainSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("budget");

  useEffect(() => {
    if (!planId) return;
    setLoading(true);
    Promise.all([
      getPlan(planId),
      getBudgetStatus(planId),
      getPlanReceiptsSummary(planId),
    ])
      .then(([p, b, s]) => {
        setPlan(p);
        setBudget(b);
        setSummary(s);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Load failed"))
      .finally(() => setLoading(false));
  }, [planId]);

  async function handleRevoke() {
    if (!planId || !confirm("Revoke this plan?")) return;
    try {
      await revokePlan(planId);
      const p = await getPlan(planId);
      setPlan(p);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Revoke failed");
    }
  }

  if (loading) return <p className="text-muted-foreground">Loading...</p>;
  if (error) {
    return (
      <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
        {error}
      </div>
    );
  }
  if (!plan || !planId) return <p>Plan not found.</p>;

  const statusColor =
    plan.status === "ACTIVE"
      ? "bg-green-500/10 text-green-600"
      : plan.status === "EXPIRED"
        ? "bg-yellow-500/10 text-yellow-600"
        : "bg-red-500/10 text-red-500";

  const tabs: { key: Tab; label: string }[] = [
    { key: "budget", label: "Budget" },
    { key: "receipts", label: "Receipts" },
    { key: "scope", label: "Scope & Config" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">{plan.action}</h2>
          <p className="font-mono text-sm text-muted-foreground">{plan.plan_id}</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => navigate(`/plans/${planId}/explorer`)}
            className="rounded bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:opacity-90"
          >
            Explorer
          </button>
          {plan.status === "ACTIVE" && (
            <button
              onClick={handleRevoke}
              className="rounded bg-destructive px-3 py-1.5 text-sm font-medium text-destructive-foreground hover:opacity-90"
            >
              Revoke
            </button>
          )}
          <button
            onClick={() => navigate("/plans")}
            className="rounded border border-border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Back
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <SummaryCard label="Status">
          <span className={cn("rounded-full px-2 py-0.5 text-xs font-medium", statusColor)}>
            {plan.status}
          </span>
        </SummaryCard>
        <SummaryCard label="Issuer" value={plan.issuer} />
        <SummaryCard label="Delegations" value={String(plan.delegation_count)} />
        <SummaryCard label="Risk Accumulated" value={plan.accumulated_risk.toFixed(2)} />
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
      {tab === "budget" && <BudgetTab budget={budget} />}
      {tab === "receipts" && <ReceiptsTab summary={summary} />}
      {tab === "scope" && <ScopeTab plan={plan} />}
    </div>
  );
}

function SummaryCard({ label, value, children }: { label: string; value?: string; children?: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <p className="text-xs text-muted-foreground">{label}</p>
      {children ?? <p className="text-lg font-semibold text-card-foreground">{value}</p>}
    </div>
  );
}

function BudgetTab({ budget }: { budget: BudgetStatusResponse | null }) {
  if (!budget) return <p className="text-muted-foreground">No budget data available.</p>;

  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-3">
        <BudgetMeter
          label="Delegations"
          current={budget.delegation_count}
          max={budget.max_delegations}
          pct={budget.budget_utilization?.delegation_pct}
        />
        <BudgetMeter
          label="Risk Total"
          current={budget.accumulated_risk}
          max={budget.max_risk_total}
          pct={budget.budget_utilization?.risk_pct}
        />
        <div className="rounded-lg border border-border bg-card p-4">
          <p className="text-xs text-muted-foreground">TTL</p>
          {budget.ttl_seconds != null ? (
            <>
              <p className="text-lg font-semibold text-card-foreground">
                {budget.ttl_remaining_seconds != null
                  ? `${budget.ttl_remaining_seconds}s remaining`
                  : "Expired"}
              </p>
              <p className="text-xs text-muted-foreground">of {budget.ttl_seconds}s</p>
            </>
          ) : (
            <p className="text-lg font-semibold text-card-foreground">Unlimited</p>
          )}
        </div>
      </div>

      {budget.exhausted_dimensions.length > 0 && (
        <div className="rounded border border-yellow-500 bg-yellow-500/10 px-4 py-2 text-sm text-yellow-700">
          Exhausted dimensions: {budget.exhausted_dimensions.join(", ")}
        </div>
      )}

      <div className="text-xs text-muted-foreground">
        Issued: {new Date(budget.issued_at).toLocaleString()}
        {budget.expires_at && <> | Expires: {new Date(budget.expires_at).toLocaleString()}</>}
      </div>
    </div>
  );
}

function BudgetMeter({
  label,
  current,
  max,
  pct,
}: {
  label: string;
  current: number;
  max: number | null;
  pct: number | null | undefined;
}) {
  const percentage = pct ?? (max != null && max > 0 ? (current / max) * 100 : 0);
  const barColor = percentage >= 90 ? "bg-red-500" : percentage >= 70 ? "bg-yellow-500" : "bg-green-500";

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-lg font-semibold text-card-foreground">
        {typeof current === "number" && current % 1 !== 0 ? current.toFixed(2) : current}
        {max != null && <span className="text-sm text-muted-foreground"> / {max}</span>}
      </p>
      {max != null && (
        <div className="mt-2 h-2 w-full rounded-full bg-muted">
          <div
            className={cn("h-2 rounded-full transition-all", barColor)}
            style={{ width: `${Math.min(percentage, 100)}%` }}
          />
        </div>
      )}
      {max == null && <p className="text-xs text-muted-foreground">Unlimited</p>}
    </div>
  );
}

function ReceiptsTab({ summary }: { summary: ReceiptChainSummary | null }) {
  if (!summary) return <p className="text-muted-foreground">No receipt data available.</p>;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <SummaryCard label="Total Receipts" value={String(summary.total_receipts)} />
        <SummaryCard label="Chain Depth" value={String(summary.chain_depth)} />
        <SummaryCard label="Total Risk" value={summary.total_risk.toFixed(4)} />
        <SummaryCard label="Chain Valid">
          <span
            className={cn(
              "rounded-full px-2 py-0.5 text-xs font-medium",
              summary.chain_valid ? "bg-green-500/10 text-green-600" : "bg-red-500/10 text-red-500",
            )}
          >
            {summary.chain_valid ? "Valid" : "Tampered"}
          </span>
        </SummaryCard>
      </div>

      {/* Decision breakdown */}
      {Object.keys(summary.decision_counts).length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4">
          <h4 className="mb-2 text-sm font-semibold">Decision Breakdown</h4>
          <div className="flex flex-wrap gap-3">
            {Object.entries(summary.decision_counts).map(([d, count]) => (
              <span key={d} className="rounded bg-muted px-2 py-1 text-xs font-medium">
                {d}: {count}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Agents & tools */}
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="rounded-lg border border-border bg-card p-4">
          <h4 className="mb-2 text-sm font-semibold">Unique Agents ({summary.unique_agents.length})</h4>
          <div className="flex flex-wrap gap-1">
            {summary.unique_agents.map((a) => (
              <span key={a} className="rounded bg-primary/10 px-1.5 py-0.5 text-xs text-primary">
                {a}
              </span>
            ))}
            {summary.unique_agents.length === 0 && (
              <span className="text-xs text-muted-foreground">none</span>
            )}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <h4 className="mb-2 text-sm font-semibold">Unique Tools ({summary.unique_tools.length})</h4>
          <div className="flex flex-wrap gap-1">
            {summary.unique_tools.map((t) => (
              <span key={t} className="rounded bg-secondary/50 px-1.5 py-0.5 text-xs">
                {t}
              </span>
            ))}
            {summary.unique_tools.length === 0 && (
              <span className="text-xs text-muted-foreground">none</span>
            )}
          </div>
        </div>
      </div>

      {summary.first_timestamp && (
        <p className="text-xs text-muted-foreground">
          First receipt: {new Date(summary.first_timestamp).toLocaleString()} | Last:{" "}
          {summary.last_timestamp ? new Date(summary.last_timestamp).toLocaleString() : "—"}
        </p>
      )}
    </div>
  );
}

function ScopeTab({ plan }: { plan: PlanDetail }) {
  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-border bg-card p-4">
        <h4 className="mb-2 text-sm font-semibold">Scope Patterns</h4>
        {plan.scope.length > 0 ? (
          <ul className="list-inside list-disc space-y-1 text-sm">
            {plan.scope.map((s, i) => (
              <li key={i} className="font-mono text-xs">
                {s}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">No scope restrictions</p>
        )}
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <h4 className="mb-2 text-sm font-semibold">Requires Checkpoint</h4>
        {plan.requires_checkpoint.length > 0 ? (
          <ul className="list-inside list-disc space-y-1 text-sm">
            {plan.requires_checkpoint.map((c, i) => (
              <li key={i} className="font-mono text-xs">
                {c}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">No checkpoint requirements</p>
        )}
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <h4 className="mb-2 text-sm font-semibold">Delegates To</h4>
        {plan.delegates_to.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {plan.delegates_to.map((d) => (
              <span key={d} className="rounded bg-primary/10 px-1.5 py-0.5 text-xs text-primary">
                {d}
              </span>
            ))}
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">No delegation restrictions</p>
        )}
      </div>

      {plan.human_intent && (
        <div className="rounded-lg border border-border bg-card p-4">
          <h4 className="mb-2 text-sm font-semibold">Human Intent</h4>
          <p className="text-sm">{plan.human_intent}</p>
        </div>
      )}

      <div className="rounded-lg border border-border bg-card p-4">
        <h4 className="mb-2 text-sm font-semibold">Signature</h4>
        <p className="break-all font-mono text-xs text-muted-foreground">
          {plan.signature || "unsigned"}
        </p>
      </div>
    </div>
  );
}
