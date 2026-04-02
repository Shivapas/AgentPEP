/**
 * APEP-122 — Agent Profile Form
 * Create / edit agent: name, role assignment, session limits, risk budget, tool allowlist.
 */
import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  createAgent,
  getAgent,
  updateAgent,
  type AgentCreateRequest,
} from "@/api/agents";

export function AgentProfileForm() {
  const { agentId } = useParams<{ agentId: string }>();
  const navigate = useNavigate();
  const isEdit = Boolean(agentId);

  const [form, setForm] = useState<AgentCreateRequest>({
    agent_id: "",
    name: "",
    roles: [],
    allowed_tools: [],
    risk_budget: 1.0,
    max_delegation_depth: 5,
    session_limit: 100,
  });
  const [enabled, setEnabled] = useState(true);
  const [rolesInput, setRolesInput] = useState("");
  const [toolsInput, setToolsInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (isEdit && agentId) {
      setLoading(true);
      getAgent(agentId)
        .then((a) => {
          setForm({
            agent_id: a.agent_id,
            name: a.name,
            roles: a.roles,
            allowed_tools: a.allowed_tools,
            risk_budget: a.risk_budget,
            max_delegation_depth: a.max_delegation_depth,
            session_limit: a.session_limit,
          });
          setEnabled(a.enabled);
          setRolesInput(a.roles.join(", "));
          setToolsInput(a.allowed_tools.join(", "));
        })
        .catch((e) => setError(e instanceof Error ? e.message : "Load failed"))
        .finally(() => setLoading(false));
    }
  }, [agentId, isEdit]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(false);
    setLoading(true);

    const roles = rolesInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    const tools = toolsInput
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    try {
      if (isEdit && agentId) {
        await updateAgent(agentId, {
          name: form.name,
          roles,
          allowed_tools: tools,
          risk_budget: form.risk_budget,
          max_delegation_depth: form.max_delegation_depth,
          session_limit: form.session_limit,
          enabled,
        });
      } else {
        await createAgent({ ...form, roles, allowed_tools: tools });
      }
      setSuccess(true);
      setTimeout(() => navigate("/agents"), 600);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setLoading(false);
    }
  }

  if (loading && isEdit && !form.agent_id) {
    return <p className="text-muted-foreground">Loading agent...</p>;
  }

  return (
    <div className="max-w-2xl space-y-4">
      <h2 className="text-2xl font-bold">
        {isEdit ? `Edit Agent: ${agentId}` : "Register New Agent"}
      </h2>

      {error && (
        <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
          {error}
        </div>
      )}
      {success && (
        <div className="rounded border border-green-500 bg-green-500/10 px-4 py-2 text-sm text-green-600">
          {isEdit ? "Agent updated." : "Agent registered."}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Agent ID */}
        <Field label="Agent ID">
          <input
            type="text"
            required
            disabled={isEdit}
            value={form.agent_id}
            onChange={(e) => setForm((f) => ({ ...f, agent_id: e.target.value }))}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm disabled:opacity-50"
            placeholder="e.g. research-agent-01"
          />
        </Field>

        {/* Name */}
        <Field label="Name">
          <input
            type="text"
            required
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            placeholder="Research Agent"
          />
        </Field>

        {/* Roles */}
        <Field label="Roles (comma-separated)">
          <input
            type="text"
            value={rolesInput}
            onChange={(e) => setRolesInput(e.target.value)}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            placeholder="reader, analyst"
          />
        </Field>

        {/* Tool Allowlist */}
        <Field label="Tool Allowlist (comma-separated glob patterns)">
          <input
            type="text"
            value={toolsInput}
            onChange={(e) => setToolsInput(e.target.value)}
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
            placeholder="read_*, search_web, calculate"
          />
        </Field>

        {/* Risk Budget */}
        <Field label={`Risk Budget: ${form.risk_budget.toFixed(2)}`}>
          <input
            type="range"
            min={0}
            max={1}
            step={0.01}
            value={form.risk_budget}
            onChange={(e) =>
              setForm((f) => ({ ...f, risk_budget: parseFloat(e.target.value) }))
            }
            className="w-full"
          />
        </Field>

        {/* Session Limit */}
        <Field label="Session Limit">
          <input
            type="number"
            min={1}
            value={form.session_limit}
            onChange={(e) =>
              setForm((f) => ({
                ...f,
                session_limit: parseInt(e.target.value, 10) || 1,
              }))
            }
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
          />
        </Field>

        {/* Max Delegation Depth */}
        <Field label="Max Delegation Depth">
          <input
            type="number"
            min={1}
            value={form.max_delegation_depth}
            onChange={(e) =>
              setForm((f) => ({
                ...f,
                max_delegation_depth: parseInt(e.target.value, 10) || 1,
              }))
            }
            className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
          />
        </Field>

        {/* Enabled (edit only) */}
        {isEdit && (
          <Field label="Status">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(e) => setEnabled(e.target.checked)}
                className="accent-primary"
              />
              Enabled
            </label>
          </Field>
        )}

        <div className="flex gap-2 pt-2">
          <button
            type="submit"
            disabled={loading}
            className="rounded bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            {loading ? "Saving..." : isEdit ? "Update Agent" : "Register Agent"}
          </button>
          <button
            type="button"
            onClick={() => navigate("/agents")}
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
