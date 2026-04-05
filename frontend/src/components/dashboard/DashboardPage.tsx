/** Homepage dashboard with KPI cards (APEP-110). */

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../../lib/api";
import { useToast } from "../../contexts/ToastContext";

interface KPIs {
  decisions_per_hour: number;
  decisions_today: number;
  deny_rate: number;
  pending_escalations: number;
  active_agents: number;
  total_rules: number;
  security_alerts_24h: number;
}

export function DashboardPage() {
  const [kpis, setKpis] = useState<KPIs | null>(null);
  const [loading, setLoading] = useState(true);
  const { addToast } = useToast();

  const fetchKpis = useCallback(async () => {
    try {
      const res = await apiFetch("/v1/console/dashboard/kpis");
      if (res.ok) {
        setKpis(await res.json());
      } else {
        addToast("Failed to load dashboard data", "error");
      }
    } catch {
      addToast("Network error loading dashboard", "error");
    } finally {
      setLoading(false);
    }
  }, [addToast]);

  useEffect(() => {
    fetchKpis();
    const interval = setInterval(fetchKpis, 30_000);
    return () => clearInterval(interval);
  }, [fetchKpis]);

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-foreground">Dashboard</h2>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          title="Decisions / hr"
          value={loading ? "--" : String(kpis?.decisions_per_hour ?? 0)}
          subtitle="Last 60 minutes"
        />
        <KpiCard
          title="DENY Rate"
          value={loading ? "--" : `${kpis?.deny_rate ?? 0}%`}
          subtitle="Today"
          highlight={kpis && kpis.deny_rate > 25}
        />
        <KpiCard
          title="Pending Escalations"
          value={loading ? "--" : String(kpis?.pending_escalations ?? 0)}
          subtitle="Awaiting review"
          highlight={kpis && (kpis.pending_escalations ?? 0) > 0}
        />
        <KpiCard
          title="Active Agents"
          value={loading ? "--" : String(kpis?.active_agents ?? 0)}
          subtitle="Last 24 hours"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <KpiCard
          title="Policy Rules"
          value={loading ? "--" : String(kpis?.total_rules ?? 0)}
          subtitle="Enabled"
        />
        <KpiCard
          title="Decisions Today"
          value={loading ? "--" : String(kpis?.decisions_today ?? 0)}
          subtitle="Total"
        />
        <KpiCard
          title="Security Alerts"
          value={loading ? "--" : String(kpis?.security_alerts_24h ?? 0)}
          subtitle="Last 24 hours"
          highlight={kpis && (kpis.security_alerts_24h ?? 0) > 0}
        />
      </div>
    </div>
  );
}

function KpiCard({
  title,
  value,
  subtitle,
  highlight,
}: {
  title: string;
  value: string;
  subtitle?: string;
  highlight?: boolean | null;
}) {
  return (
    <div
      className={`rounded-lg border bg-card p-6 ${
        highlight
          ? "border-destructive/50 shadow-sm"
          : "border-border"
      }`}
    >
      <p className="text-sm text-muted-foreground">{title}</p>
      <p
        className={`mt-1 text-3xl font-bold ${
          highlight ? "text-destructive" : "text-card-foreground"
        }`}
      >
        {value}
      </p>
      {subtitle && (
        <p className="mt-1 text-xs text-muted-foreground">{subtitle}</p>
      )}
    </div>
  );
}
