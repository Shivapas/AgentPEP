/**
 * APEP-126 — Delegation Chain Viewer
 * Visualise configured delegation grants per agent.
 */
import { useEffect, useState, useCallback } from "react";
import { getDelegations, type DelegationGrant } from "@/api/agents";

export function DelegationChainViewer({ agentId }: { agentId: string }) {
  const [grants, setGrants] = useState<DelegationGrant[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await getDelegations(agentId);
      setGrants(res.grants);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load delegations");
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-semibold">Delegation Grants</h3>

      {error && (
        <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      {loading ? (
        <p className="text-sm text-muted-foreground">Loading delegations...</p>
      ) : grants.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No delegation grants found for this agent.
        </p>
      ) : (
        <div className="space-y-3">
          {/* Visual chain representation */}
          <div className="flex flex-col gap-2">
            {grants.map((grant, idx) => (
              <div key={idx} className="flex items-start gap-3">
                {/* Connector line */}
                <div className="flex flex-col items-center pt-1">
                  <div className="h-3 w-3 rounded-full border-2 border-primary bg-background" />
                  {idx < grants.length - 1 && (
                    <div className="h-8 w-0.5 bg-border" />
                  )}
                </div>

                {/* Grant card */}
                <div className="flex-1 rounded-lg border border-border p-3">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-medium text-primary">
                      {agentId}
                    </span>
                    <span className="text-muted-foreground">&rarr;</span>
                    <span className="font-mono text-sm font-medium">
                      {grant.target_agent_id}
                    </span>
                  </div>

                  <div className="mt-2 flex flex-wrap gap-1">
                    {grant.granted_tools.length > 0 ? (
                      grant.granted_tools.map((tool) => (
                        <span
                          key={tool}
                          className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs"
                        >
                          {tool}
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-muted-foreground">
                        (no tools recorded)
                      </span>
                    )}
                  </div>

                  <p className="mt-1 text-xs text-muted-foreground">
                    Authority: {grant.authority_source}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
