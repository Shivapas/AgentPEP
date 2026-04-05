/**
 * SimulationBuilder — construct tool call requests and run against any policy version.
 *
 * Sprint 19: APEP-153.
 */

import { useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

interface SimulationStep {
  step: string;
  passed: boolean;
  detail: string;
}

interface SimulationResult {
  request_id: string;
  decision: string;
  matched_rule_id: string | null;
  matched_rule_name: string;
  risk_score: number;
  taint_eval: Record<string, unknown>;
  chain_result: Record<string, unknown>;
  resolved_roles: string[];
  steps: SimulationStep[];
  reason: string;
  latency_ms: number;
  policy_version: string;
}

export function SimulationBuilder() {
  const [agentId, setAgentId] = useState("agent-assistant");
  const [toolName, setToolName] = useState("file.read");
  const [toolArgs, setToolArgs] = useState('{"path": "/data/report.csv"}');
  const [sessionId, setSessionId] = useState("sim-session");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function runSimulation() {
    setLoading(true);
    setError(null);
    setResult(null);

    let parsedArgs: Record<string, unknown> = {};
    try {
      parsedArgs = JSON.parse(toolArgs);
    } catch {
      setError("Invalid JSON in tool arguments");
      setLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/v1/simulate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: sessionId,
          agent_id: agentId,
          tool_name: toolName,
          tool_args: parsedArgs,
        }),
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`HTTP ${response.status}: ${text}`);
      }

      const data: SimulationResult = await response.json();
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Simulation Builder</h2>
      <p className="text-muted-foreground">
        Construct tool call requests and run them against the policy stack
        without enforcement.
      </p>

      {/* Request Builder Form */}
      <div className="rounded-lg border border-border bg-card p-6 space-y-4">
        <h3 className="text-lg font-semibold">Request</h3>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div>
            <label className="block text-sm font-medium text-muted-foreground mb-1">
              Session ID
            </label>
            <input
              type="text"
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            />
          </div>
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

        <div>
          <label className="block text-sm font-medium text-muted-foreground mb-1">
            Tool Arguments (JSON)
          </label>
          <textarea
            value={toolArgs}
            onChange={(e) => setToolArgs(e.target.value)}
            rows={4}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm font-mono"
          />
        </div>

        <button
          onClick={runSimulation}
          disabled={loading}
          className="rounded bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          {loading ? "Running..." : "Run Simulation"}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-lg border border-red-300 bg-red-50 p-4 text-red-800 text-sm">
          {error}
        </div>
      )}

      {/* Result */}
      {result && <SimulationResultView result={result} />}
    </div>
  );
}

function SimulationResultView({ result }: { result: SimulationResult }) {
  const decisionColor: Record<string, string> = {
    ALLOW: "text-green-600 bg-green-50 border-green-200",
    DENY: "text-red-600 bg-red-50 border-red-200",
    ESCALATE: "text-yellow-600 bg-yellow-50 border-yellow-200",
    DRY_RUN: "text-blue-600 bg-blue-50 border-blue-200",
    TIMEOUT: "text-gray-600 bg-gray-50 border-gray-200",
  };

  return (
    <div className="space-y-4">
      {/* Decision Banner */}
      <div
        className={`rounded-lg border p-4 ${decisionColor[result.decision] ?? "border-border"}`}
      >
        <div className="flex items-center justify-between">
          <div>
            <span className="text-xs font-medium uppercase tracking-wider">
              Decision
            </span>
            <p className="text-2xl font-bold">{result.decision}</p>
          </div>
          <div className="text-right text-sm">
            <p>Latency: {result.latency_ms}ms</p>
            {result.matched_rule_name && (
              <p>Rule: {result.matched_rule_name}</p>
            )}
            <p>Risk: {result.risk_score.toFixed(2)}</p>
          </div>
        </div>
        {result.reason && (
          <p className="mt-2 text-sm opacity-80">{result.reason}</p>
        )}
      </div>

      {/* Resolved Roles */}
      {result.resolved_roles.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4">
          <h4 className="text-sm font-semibold mb-2">Resolved Roles</h4>
          <div className="flex flex-wrap gap-2">
            {result.resolved_roles.map((role) => (
              <span
                key={role}
                className="rounded-full bg-muted px-3 py-1 text-xs font-medium"
              >
                {role}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Evaluation Steps */}
      <div className="rounded-lg border border-border bg-card p-4">
        <h4 className="text-sm font-semibold mb-3">Evaluation Trace</h4>
        <div className="space-y-2">
          {result.steps.map((step, i) => (
            <div
              key={i}
              className="flex items-start gap-3 rounded border border-border p-3 text-sm"
            >
              <span
                className={`mt-0.5 inline-block h-4 w-4 rounded-full ${step.passed ? "bg-green-500" : "bg-red-500"}`}
              />
              <div>
                <p className="font-medium font-mono">{step.step}</p>
                <p className="text-muted-foreground">{step.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Taint & Chain Details */}
      {(Object.keys(result.taint_eval).length > 0 ||
        Object.keys(result.chain_result).length > 0) && (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {Object.keys(result.taint_eval).length > 0 && (
            <div className="rounded-lg border border-border bg-card p-4">
              <h4 className="text-sm font-semibold mb-2">Taint Evaluation</h4>
              <pre className="text-xs font-mono overflow-auto">
                {JSON.stringify(result.taint_eval, null, 2)}
              </pre>
            </div>
          )}
          {Object.keys(result.chain_result).length > 0 && (
            <div className="rounded-lg border border-border bg-card p-4">
              <h4 className="text-sm font-semibold mb-2">
                Delegation Chain Result
              </h4>
              <pre className="text-xs font-mono overflow-auto">
                {JSON.stringify(result.chain_result, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
