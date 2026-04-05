/**
 * SimulationCompare — run same request against two policy versions and diff.
 *
 * Sprint 19: APEP-154.
 */

import { useState } from "react";

const API_BASE =
  (import.meta.env.VITE_API_URL as string | undefined) ??
  `http://${window.location.hostname}:8000`;

interface PolicyRule {
  name: string;
  agent_role: string[];
  tool_pattern: string;
  action: string;
  priority: number;
  enabled: boolean;
  taint_check?: boolean;
  risk_threshold?: number;
}

interface SimulationStep {
  step: string;
  passed: boolean;
  detail: string;
}

interface SimulateResult {
  request_id: string;
  decision: string;
  matched_rule_id: string | null;
  matched_rule_name: string;
  risk_score: number;
  resolved_roles: string[];
  steps: SimulationStep[];
  reason: string;
  latency_ms: number;
  policy_version: string;
}

interface CompareResult {
  decision_changed: boolean;
  matched_rule_changed: boolean;
  risk_score_changed: boolean;
  version_a: SimulateResult;
  version_b: SimulateResult;
  changes: Array<{ field: string; from: unknown; to: unknown }>;
}

const DEFAULT_RULES = JSON.stringify(
  [
    {
      name: "allow-read",
      agent_role: ["*"],
      tool_pattern: "file.read",
      action: "ALLOW",
      priority: 10,
      enabled: true,
    },
  ],
  null,
  2,
);

export function SimulationCompare() {
  const [agentId, setAgentId] = useState("agent-assistant");
  const [toolName, setToolName] = useState("file.read");
  const [toolArgs, setToolArgs] = useState('{"path": "/data/report.csv"}');
  const [rulesA, setRulesA] = useState(DEFAULT_RULES);
  const [rulesB, setRulesB] = useState(DEFAULT_RULES);
  const [labelA, setLabelA] = useState("version_a");
  const [labelB, setLabelB] = useState("version_b");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CompareResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function runComparison() {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const parsedArgs = JSON.parse(toolArgs);
      const parsedA: PolicyRule[] = JSON.parse(rulesA);
      const parsedB: PolicyRule[] = JSON.parse(rulesB);

      const response = await fetch(`${API_BASE}/v1/simulate/compare`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          agent_id: agentId,
          tool_name: toolName,
          tool_args: parsedArgs,
          version_a_label: labelA,
          version_a_rules: parsedA,
          version_b_label: labelB,
          version_b_rules: parsedB,
        }),
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`HTTP ${response.status}: ${text}`);
      }

      const data: CompareResult = await response.json();
      setResult(data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Invalid JSON in rules or args",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Policy Comparison</h2>
      <p className="text-muted-foreground">
        Run the same tool call against two different policy configurations and
        compare the results.
      </p>

      {/* Request fields */}
      <div className="rounded-lg border border-border bg-card p-6 space-y-4">
        <h3 className="text-lg font-semibold">Request</h3>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div>
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Agent ID
            </label>
            <input
              type="text"
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
              className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Tool Name
            </label>
            <input
              type="text"
              value={toolName}
              onChange={(e) => setToolName(e.target.value)}
              className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            />
          </div>
        </div>
        <div>
          <label className="block text-sm font-medium text-muted-foreground mb-1">
            Tool Arguments (JSON)
          </label>
          <textarea
            value={toolArgs}
            onChange={(e) => setToolArgs(e.target.value)}
            rows={3}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm font-mono"
          />
        </div>
      </div>

      {/* Policy versions side by side */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-card p-4 space-y-3">
          <div>
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Version A Label
            </label>
            <input
              type="text"
              value={labelA}
              onChange={(e) => setLabelA(e.target.value)}
              className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Version A Rules (JSON)
            </label>
            <textarea
              value={rulesA}
              onChange={(e) => setRulesA(e.target.value)}
              rows={10}
              className="w-full rounded border border-border bg-background px-3 py-2 text-sm font-mono"
            />
          </div>
        </div>
        <div className="rounded-lg border border-border bg-card p-4 space-y-3">
          <div>
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Version B Label
            </label>
            <input
              type="text"
              value={labelB}
              onChange={(e) => setLabelB(e.target.value)}
              className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Version B Rules (JSON)
            </label>
            <textarea
              value={rulesB}
              onChange={(e) => setRulesB(e.target.value)}
              rows={10}
              className="w-full rounded border border-border bg-background px-3 py-2 text-sm font-mono"
            />
          </div>
        </div>
      </div>

      <button
        onClick={runComparison}
        disabled={loading}
        className="rounded bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
      >
        {loading ? "Comparing..." : "Compare Policies"}
      </button>

      {error && (
        <div className="rounded-lg border border-red-300 bg-red-50 p-4 text-red-800 text-sm">
          {error}
        </div>
      )}

      {result && <CompareResultView result={result} />}
    </div>
  );
}

function CompareResultView({ result }: { result: CompareResult }) {
  const hasChanges = result.changes.length > 0;

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div
        className={`rounded-lg border p-4 ${hasChanges ? "border-yellow-300 bg-yellow-50" : "border-green-300 bg-green-50"}`}
      >
        <h3 className="text-lg font-semibold">
          {hasChanges ? "Differences Detected" : "No Differences"}
        </h3>
        <div className="mt-2 grid grid-cols-3 gap-4 text-sm">
          <div>
            <span className="text-muted-foreground">Decision changed:</span>{" "}
            <span className="font-medium">
              {result.decision_changed ? "Yes" : "No"}
            </span>
          </div>
          <div>
            <span className="text-muted-foreground">Rule changed:</span>{" "}
            <span className="font-medium">
              {result.matched_rule_changed ? "Yes" : "No"}
            </span>
          </div>
          <div>
            <span className="text-muted-foreground">Risk changed:</span>{" "}
            <span className="font-medium">
              {result.risk_score_changed ? "Yes" : "No"}
            </span>
          </div>
        </div>
      </div>

      {/* Changes list */}
      {result.changes.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4">
          <h4 className="text-sm font-semibold mb-3">Changes</h4>
          <div className="space-y-2">
            {result.changes.map((change, i) => (
              <div key={i} className="flex items-center gap-4 text-sm">
                <span className="font-mono font-medium">{change.field}</span>
                <span className="text-red-600 line-through">
                  {JSON.stringify(change.from)}
                </span>
                <span className="text-muted-foreground">→</span>
                <span className="text-green-600">
                  {JSON.stringify(change.to)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Side-by-side results */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <VersionResult
          label={result.version_a.policy_version}
          result={result.version_a}
        />
        <VersionResult
          label={result.version_b.policy_version}
          result={result.version_b}
        />
      </div>
    </div>
  );
}

function VersionResult({
  label,
  result,
}: {
  label: string;
  result: SimulateResult;
}) {
  const decisionColor: Record<string, string> = {
    ALLOW: "text-green-600",
    DENY: "text-red-600",
    ESCALATE: "text-yellow-600",
    DRY_RUN: "text-blue-600",
    TIMEOUT: "text-gray-600",
  };

  return (
    <div className="rounded-lg border border-border bg-card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold">{label}</h4>
        <span
          className={`text-lg font-bold ${decisionColor[result.decision] ?? ""}`}
        >
          {result.decision}
        </span>
      </div>
      {result.matched_rule_name && (
        <p className="text-xs text-muted-foreground">
          Rule: {result.matched_rule_name}
        </p>
      )}
      <p className="text-xs text-muted-foreground">
        Risk: {result.risk_score.toFixed(2)} | Latency: {result.latency_ms}ms
      </p>
      <div className="space-y-1">
        {result.steps.map((step, i) => (
          <div key={i} className="flex items-center gap-2 text-xs">
            <span
              className={`inline-block h-2 w-2 rounded-full ${step.passed ? "bg-green-500" : "bg-red-500"}`}
            />
            <span className="font-mono">{step.step}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
