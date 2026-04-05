import { useState, useEffect, useCallback } from "react";
import { apiFetch } from "../lib/api";

interface DashboardStats {
  policy_rules: number;
  decisions_today: number;
  active_agents: number;
  deny_rate: number;
  avg_latency_ms: number;
  escalations_pending: number;
}

const EMPTY_STATS: DashboardStats = {
  policy_rules: 0,
  decisions_today: 0,
  active_agents: 0,
  deny_rate: 0,
  avg_latency_ms: 0,
  escalations_pending: 0,
};

export function Dashboard() {
  const [stats, setStats] = useState<DashboardStats>(EMPTY_STATS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStats = useCallback(async () => {
    try {
      const resp = await apiFetch("/v1/stats");
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const data = (await resp.json()) as DashboardStats;
      setStats(data);
      setError(null);
    } catch {
      setError("Unable to load dashboard stats");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchStats();
    const interval = setInterval(() => void fetchStats(), 15000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Dashboard</h2>
        {error && (
          <span className="text-sm text-destructive">{error}</span>
        )}
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3 lg:grid-cols-6">
        <StatusCard
          title="Policy Rules"
          value={loading ? "..." : String(stats.policy_rules)}
        />
        <StatusCard
          title="Decisions Today"
          value={loading ? "..." : String(stats.decisions_today)}
        />
        <StatusCard
          title="Active Agents"
          value={loading ? "..." : String(stats.active_agents)}
        />
        <StatusCard
          title="Deny Rate"
          value={loading ? "..." : `${(stats.deny_rate * 100).toFixed(1)}%`}
          variant={stats.deny_rate > 0.3 ? "warning" : "default"}
        />
        <StatusCard
          title="Avg Latency"
          value={loading ? "..." : `${stats.avg_latency_ms}ms`}
          variant={stats.avg_latency_ms > 100 ? "warning" : "default"}
        />
        <StatusCard
          title="Escalations"
          value={loading ? "..." : String(stats.escalations_pending)}
          variant={stats.escalations_pending > 0 ? "warning" : "default"}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <RecentDecisions />
        <QuickActions />
      </div>
    </div>
  );
}

function StatusCard({
  title,
  value,
  variant = "default",
}: {
  title: string;
  value: string;
  variant?: "default" | "warning";
}) {
  const borderClass =
    variant === "warning"
      ? "border-destructive/50"
      : "border-border";

  return (
    <div className={`rounded-lg border ${borderClass} bg-card p-4`}>
      <p className="text-xs text-muted-foreground">{title}</p>
      <p className="mt-1 text-2xl font-bold text-card-foreground">{value}</p>
    </div>
  );
}

interface AuditEntry {
  decision_id: string;
  agent_id: string;
  tool_name: string;
  decision: string;
  timestamp: string;
  latency_ms: number;
}

function RecentDecisions() {
  const [decisions, setDecisions] = useState<AuditEntry[]>([]);

  useEffect(() => {
    const load = async () => {
      try {
        const resp = await apiFetch("/v1/audit?limit=10");
        if (!resp.ok) return;
        const data = (await resp.json()) as { items: AuditEntry[] };
        setDecisions(data.items ?? []);
      } catch {
        /* polling failure is non-critical */
      }
    };
    void load();
    const interval = setInterval(() => void load(), 15000);
    return () => clearInterval(interval);
  }, []);

  const decisionColor = (d: string) => {
    switch (d) {
      case "ALLOW": return "text-green-600";
      case "DENY": return "text-red-600";
      case "ESCALATE": return "text-yellow-600";
      default: return "text-muted-foreground";
    }
  };

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="mb-3 text-sm font-semibold text-card-foreground">
        Recent Decisions
      </h3>
      {decisions.length === 0 ? (
        <p className="text-sm text-muted-foreground">No decisions yet</p>
      ) : (
        <div className="space-y-2">
          {decisions.map((d) => (
            <div
              key={d.decision_id}
              className="flex items-center justify-between text-sm"
            >
              <div className="flex items-center gap-2">
                <span className={`font-mono font-semibold ${decisionColor(d.decision)}`}>
                  {d.decision}
                </span>
                <span className="text-card-foreground">{d.tool_name}</span>
                <span className="text-muted-foreground">({d.agent_id})</span>
              </div>
              <span className="text-xs text-muted-foreground">
                {d.latency_ms}ms
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function QuickActions() {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="mb-3 text-sm font-semibold text-card-foreground">
        Quick Actions
      </h3>
      <div className="grid grid-cols-2 gap-2">
        <ActionButton href="/rules" label="Manage Rules" />
        <ActionButton href="/audit" label="View Audit Log" />
        <ActionButton href="/agents" label="Agent Profiles" />
        <ActionButton href="/ux-survey" label="UX Feedback" />
      </div>
    </div>
  );
}

function ActionButton({ href, label }: { href: string; label: string }) {
  return (
    <a
      href={href}
      className="flex items-center justify-center rounded-md border border-border bg-secondary px-3 py-2 text-sm font-medium text-secondary-foreground transition-colors hover:bg-accent"
    >
      {label}
    </a>
  );
}
