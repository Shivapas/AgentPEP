/**
 * APEP-333 — Plan Issuance Form
 * Create a new MissionPlan with scope, budget, checkpoints, and delegation.
 */
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { createPlan } from "@/api/plans";
import type { CreatePlanRequest } from "@/types/plans";

export function PlanIssuanceForm() {
  const navigate = useNavigate();

  const [action, setAction] = useState("");
  const [issuer, setIssuer] = useState("");
  const [humanIntent, setHumanIntent] = useState("");
  const [scopeInput, setScopeInput] = useState("");
  const [checkpointsInput, setCheckpointsInput] = useState("");
  const [delegatesInput, setDelegatesInput] = useState("");

  const [maxDelegations, setMaxDelegations] = useState<string>("");
  const [maxRiskTotal, setMaxRiskTotal] = useState<string>("");
  const [ttlSeconds, setTtlSeconds] = useState<string>("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  function parseList(input: string): string[] {
    return input
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(false);
    setLoading(true);

    const body: CreatePlanRequest = {
      action,
      issuer,
      human_intent: humanIntent,
      scope: parseList(scopeInput),
      requires_checkpoint: parseList(checkpointsInput),
      delegates_to: parseList(delegatesInput),
      budget: {
        max_delegations: maxDelegations ? parseInt(maxDelegations, 10) : null,
        max_risk_total: maxRiskTotal ? parseFloat(maxRiskTotal) : null,
        ttl_seconds: ttlSeconds ? parseInt(ttlSeconds, 10) : null,
      },
    };

    try {
      await createPlan(body);
      setSuccess(true);
      setTimeout(() => navigate("/plans"), 600);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create plan");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl space-y-4">
      <h2 className="text-2xl font-bold">Issue New Plan</h2>

      {error && (
        <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
          {error}
        </div>
      )}
      {success && (
        <div className="rounded border border-green-500 bg-green-500/10 px-4 py-2 text-sm text-green-600">
          Plan issued successfully.
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <Field label="Action (intent description)">
          <input
            type="text"
            required
            value={action}
            onChange={(e) => setAction(e.target.value)}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            placeholder="e.g. Analyze Q3 finance reports"
          />
        </Field>

        <Field label="Issuer (email / SSO subject)">
          <input
            type="text"
            required
            value={issuer}
            onChange={(e) => setIssuer(e.target.value)}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            placeholder="e.g. admin@company.com"
          />
        </Field>

        <Field label="Human Intent">
          <textarea
            value={humanIntent}
            onChange={(e) => setHumanIntent(e.target.value)}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            rows={2}
            placeholder="Explicit human intent to propagate through the pipeline"
          />
        </Field>

        <Field label="Scope (comma-separated verb:namespace:resource patterns)">
          <input
            type="text"
            value={scopeInput}
            onChange={(e) => setScopeInput(e.target.value)}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            placeholder="read:finance:*, write:reports:quarterly"
          />
        </Field>

        <Field label="Requires Checkpoint (comma-separated action patterns)">
          <input
            type="text"
            value={checkpointsInput}
            onChange={(e) => setCheckpointsInput(e.target.value)}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            placeholder="delete_*, publish_*"
          />
        </Field>

        <Field label="Delegates To (comma-separated agent IDs)">
          <input
            type="text"
            value={delegatesInput}
            onChange={(e) => setDelegatesInput(e.target.value)}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            placeholder="research-agent-01, analysis-agent-02"
          />
        </Field>

        <div className="rounded-lg border border-border p-4">
          <h3 className="mb-3 text-sm font-semibold">Budget Constraints</h3>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Max Delegations">
              <input
                type="number"
                min={1}
                value={maxDelegations}
                onChange={(e) => setMaxDelegations(e.target.value)}
                className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
                placeholder="Unlimited"
              />
            </Field>
            <Field label="Max Risk Total">
              <input
                type="number"
                min={0}
                step={0.1}
                value={maxRiskTotal}
                onChange={(e) => setMaxRiskTotal(e.target.value)}
                className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
                placeholder="Unlimited"
              />
            </Field>
            <Field label="TTL (seconds)">
              <input
                type="number"
                min={1}
                value={ttlSeconds}
                onChange={(e) => setTtlSeconds(e.target.value)}
                className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
                placeholder="No expiry"
              />
            </Field>
          </div>
        </div>

        <div className="flex gap-2 pt-2">
          <button
            type="submit"
            disabled={loading}
            className="rounded bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            {loading ? "Issuing..." : "Issue Plan"}
          </button>
          <button
            type="button"
            onClick={() => navigate("/plans")}
            className="rounded border border-border px-4 py-2 text-sm hover:bg-muted"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1">
      <label className="text-sm font-medium text-foreground">{label}</label>
      {children}
    </div>
  );
}
