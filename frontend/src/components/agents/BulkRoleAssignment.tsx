/**
 * APEP-125 — Bulk Role Assignment
 * Assign roles to multiple agents at once.
 */
import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { bulkAssignRoles } from "@/api/agents";

export function BulkRoleAssignment() {
  const navigate = useNavigate();
  const location = useLocation();
  const preselected: string[] =
    (location.state as { agentIds?: string[] } | null)?.agentIds ?? [];

  const [agentIdsInput, setAgentIdsInput] = useState(preselected.join(", "));
  const [rolesInput, setRolesInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ updated: number } | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);

    const agentIds = agentIdsInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const roles = rolesInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    if (agentIds.length === 0 || roles.length === 0) {
      setError("Please provide at least one agent ID and one role.");
      return;
    }

    setLoading(true);
    try {
      const res = await bulkAssignRoles(agentIds, roles);
      setResult({ updated: res.updated });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Bulk assignment failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-2xl space-y-4">
      <h2 className="text-2xl font-bold">Bulk Role Assignment</h2>

      {error && (
        <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      {result && (
        <div className="rounded border border-green-500 bg-green-500/10 px-4 py-2 text-sm text-green-600">
          Updated {result.updated} agent(s).
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-1">
          <label className="text-sm font-medium">Agent IDs (comma-separated)</label>
          <textarea
            rows={3}
            value={agentIdsInput}
            onChange={(e) => setAgentIdsInput(e.target.value)}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm font-mono"
            placeholder="agent-01, agent-02, agent-03"
          />
        </div>

        <div className="space-y-1">
          <label className="text-sm font-medium">Roles to Assign (comma-separated)</label>
          <input
            type="text"
            value={rolesInput}
            onChange={(e) => setRolesInput(e.target.value)}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            placeholder="reader, analyst"
          />
        </div>

        <div className="flex gap-2">
          <button
            type="submit"
            disabled={loading}
            className="rounded bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            {loading ? "Assigning..." : "Assign Roles"}
          </button>
          <button
            type="button"
            onClick={() => navigate("/agents")}
            className="rounded border border-border px-4 py-2 text-sm hover:bg-muted"
          >
            Back
          </button>
        </div>
      </form>
    </div>
  );
}
