/**
 * APEP-340 -- Scope Simulator UI
 *
 * Interactive console component for simulating tool calls against
 * scope patterns.  Users enter scope patterns, checkpoint patterns,
 * and one or more tool names, then see the effective decision
 * (ALLOW / DENY / ESCALATE) with match details.
 */
import { useState, useCallback } from "react";
import { simulateScopeBatch } from "@/api/scope";
import type { BatchSimulateResponse, ScopeSimulateResult } from "@/types/scope";
import { cn } from "@/lib/utils";

const DECISION_STYLES: Record<string, string> = {
  ALLOW: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300",
  DENY: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300",
  ESCALATE: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300",
};

function ResultCard({ result }: { result: ScopeSimulateResult }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span
            className={cn(
              "inline-block rounded px-2 py-0.5 text-xs font-semibold",
              DECISION_STYLES[result.effective_decision] ?? "bg-muted text-muted-foreground",
            )}
          >
            {result.effective_decision}
          </span>
          <span className="font-mono text-sm">{result.tool_name}</span>
        </div>
        <button
          onClick={() => setExpanded(!expanded)}
          className="text-xs text-muted-foreground hover:text-foreground"
        >
          {expanded ? "Hide details" : "Details"}
        </button>
      </div>

      {expanded && (
        <div className="mt-3 space-y-2 text-sm">
          <div>
            <span className="font-medium">Scope allowed:</span>{" "}
            {result.scope_allowed ? "Yes" : "No"}
            {result.scope_matched_pattern && (
              <span className="ml-2 font-mono text-xs text-muted-foreground">
                matched: {result.scope_matched_pattern}
              </span>
            )}
          </div>
          <div className="text-xs text-muted-foreground">{result.scope_reason}</div>
          <div>
            <span className="font-medium">Checkpoint triggered:</span>{" "}
            {result.checkpoint_triggered ? "Yes" : "No"}
            {result.checkpoint_matched_pattern && (
              <span className="ml-2 font-mono text-xs text-muted-foreground">
                matched: {result.checkpoint_matched_pattern}
              </span>
            )}
          </div>
          <div className="text-xs text-muted-foreground">{result.checkpoint_reason}</div>
          {result.compiled_rbac_patterns.length > 0 && (
            <div>
              <span className="font-medium">RBAC patterns:</span>
              <ul className="mt-1 list-inside list-disc text-xs font-mono text-muted-foreground">
                {result.compiled_rbac_patterns.map((p, i) => (
                  <li key={i}>{p}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function ScopeSimulator() {
  const [scopeInput, setScopeInput] = useState("read:public:*");
  const [checkpointInput, setCheckpointInput] = useState("");
  const [toolNamesInput, setToolNamesInput] = useState("file.read.public.report");
  const [actionInput, setActionInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [response, setResponse] = useState<BatchSimulateResponse | null>(null);

  const handleSimulate = useCallback(async () => {
    setError(null);
    setResponse(null);

    const scope = scopeInput
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const requires_checkpoint = checkpointInput
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const tool_names = toolNamesInput
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);

    if (scope.length === 0) {
      setError("At least one scope pattern is required.");
      return;
    }
    if (tool_names.length === 0) {
      setError("At least one tool name is required.");
      return;
    }

    setLoading(true);
    try {
      const result = await simulateScopeBatch({
        scope,
        requires_checkpoint,
        tool_names,
        action: actionInput,
      });
      setResponse(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Simulation failed");
    } finally {
      setLoading(false);
    }
  }, [scopeInput, checkpointInput, toolNamesInput, actionInput]);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Scope Simulator</h2>
        <p className="text-sm text-muted-foreground">
          Test tool calls against scope patterns to preview ALLOW / DENY / ESCALATE decisions.
        </p>
      </div>

      {/* Input form */}
      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <label className="mb-1 block text-sm font-medium">
            Scope patterns <span className="text-muted-foreground">(one per line)</span>
          </label>
          <textarea
            value={scopeInput}
            onChange={(e) => setScopeInput(e.target.value)}
            rows={4}
            className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm"
            placeholder="read:public:*&#10;write:internal:*"
          />
        </div>
        <div>
          <label className="mb-1 block text-sm font-medium">
            Checkpoint patterns <span className="text-muted-foreground">(optional, one per line)</span>
          </label>
          <textarea
            value={checkpointInput}
            onChange={(e) => setCheckpointInput(e.target.value)}
            rows={4}
            className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm"
            placeholder="delete:*:*&#10;execute:secret:*"
          />
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <div>
          <label className="mb-1 block text-sm font-medium">
            Tool names to simulate <span className="text-muted-foreground">(one per line)</span>
          </label>
          <textarea
            value={toolNamesInput}
            onChange={(e) => setToolNamesInput(e.target.value)}
            rows={4}
            className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-sm"
            placeholder="file.read.public.report&#10;db.delete.internal.users"
          />
        </div>
        <div>
          <label className="mb-1 block text-sm font-medium">
            Action description <span className="text-muted-foreground">(optional)</span>
          </label>
          <input
            type="text"
            value={actionInput}
            onChange={(e) => setActionInput(e.target.value)}
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
            placeholder="Describe the simulated action..."
          />
          <div className="mt-4">
            <button
              onClick={handleSimulate}
              disabled={loading}
              className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {loading ? "Simulating..." : "Run Simulation"}
            </button>
          </div>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      {/* Results */}
      {response && (
        <div className="space-y-4">
          {/* Summary bar */}
          <div className="flex items-center gap-4 rounded-lg border border-border bg-card px-4 py-3">
            <span className="text-sm font-medium">Results:</span>
            <span className="text-sm">
              <span className="font-mono">{response.summary.total}</span> total
            </span>
            {response.summary.allowed > 0 && (
              <span className={cn("rounded px-2 py-0.5 text-xs font-semibold", DECISION_STYLES.ALLOW)}>
                {response.summary.allowed} ALLOW
              </span>
            )}
            {response.summary.denied > 0 && (
              <span className={cn("rounded px-2 py-0.5 text-xs font-semibold", DECISION_STYLES.DENY)}>
                {response.summary.denied} DENY
              </span>
            )}
            {response.summary.escalated > 0 && (
              <span className={cn("rounded px-2 py-0.5 text-xs font-semibold", DECISION_STYLES.ESCALATE)}>
                {response.summary.escalated} ESCALATE
              </span>
            )}
          </div>

          {/* Individual results */}
          <div className="space-y-2">
            {response.results.map((r, i) => (
              <ResultCard key={i} result={r} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
