/**
 * Sprint 56 (APEP-447) — CIS Dashboard Widget for Policy Console.
 *
 * Displays a summary dashboard of Content Ingestion Security status:
 *   - Scan mode distribution (STRICT / STANDARD / LENIENT)
 *   - YOLO-mode session count and active flags
 *   - Severity breakdown across recent findings
 *   - Scanner tier performance (Tier 0 regex vs Tier 1 ONNX)
 *   - Recent findings timeline
 *   - Compliance export quick actions
 */

import { useCallback, useEffect, useState } from "react";
import type { CISSeverity } from "../types/cis";
import { apiFetch } from "../lib/api";

/* ---------- Types ---------- */

interface CISDashboardData {
  summary: {
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  yolo_sessions: {
    active_count: number;
    sessions: Array<{
      session_id: string;
      risk_multiplier: number;
      signals: string[];
      detected_at: string;
    }>;
  };
  scan_mode_distribution: Record<string, number>;
  scanner_breakdown: Record<string, number>;
  recent_findings: Array<{
    finding_id: string;
    severity: CISSeverity;
    scanner: string;
    rule_id: string;
    description: string;
    timestamp: string;
  }>;
}

/* ---------- Severity helpers ---------- */

const severityColor: Record<CISSeverity, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-blue-400 text-white",
  INFO: "bg-gray-400 text-white",
};

function SeverityBadge({ severity }: { severity: CISSeverity }) {
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${severityColor[severity] ?? "bg-gray-300 text-black"}`}
    >
      {severity}
    </span>
  );
}

/* ---------- Stat card ---------- */

function StatCard({
  label,
  value,
  color = "text-foreground",
  subtext,
}: {
  label: string;
  value: string | number;
  color?: string;
  subtext?: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <p className="text-xs text-muted-foreground uppercase tracking-wide">
        {label}
      </p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      {subtext && (
        <p className="text-xs text-muted-foreground mt-1">{subtext}</p>
      )}
    </div>
  );
}

/* ---------- YOLO alert banner ---------- */

function YOLOAlertBanner({
  count,
}: {
  count: number;
}) {
  if (count === 0) return null;

  return (
    <div className="rounded-lg border border-red-500 bg-red-50 dark:bg-red-950 p-4 flex items-center gap-3">
      <span className="text-red-600 text-2xl font-bold">!</span>
      <div>
        <p className="font-semibold text-red-700 dark:text-red-300">
          YOLO Mode Active
        </p>
        <p className="text-sm text-red-600 dark:text-red-400">
          {count} session{count !== 1 ? "s" : ""} running in YOLO mode with
          elevated risk multiplier. Scan mode locked to STRICT.
        </p>
      </div>
    </div>
  );
}

/* ---------- Scan mode distribution ---------- */

function ScanModeDistribution({
  distribution,
}: {
  distribution: Record<string, number>;
}) {
  const total = Object.values(distribution).reduce((a, b) => a + b, 0);
  const modes = [
    { key: "STRICT", color: "bg-red-500" },
    { key: "STANDARD", color: "bg-yellow-500" },
    { key: "LENIENT", color: "bg-green-500" },
  ];

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="text-sm font-semibold mb-3">Scan Mode Distribution</h3>
      {total === 0 ? (
        <p className="text-xs text-muted-foreground">No scan data yet</p>
      ) : (
        <div className="space-y-2">
          {modes.map(({ key, color }) => {
            const count = distribution[key] ?? 0;
            const pct = total > 0 ? (count / total) * 100 : 0;
            return (
              <div key={key} className="flex items-center gap-2">
                <span className="w-20 text-xs font-medium">{key}</span>
                <div className="flex-1 h-4 bg-muted rounded overflow-hidden">
                  <div
                    className={`h-full ${color} rounded`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="text-xs w-12 text-right">{count}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/* ---------- Scanner breakdown ---------- */

function ScannerBreakdown({
  breakdown,
}: {
  breakdown: Record<string, number>;
}) {
  const entries = Object.entries(breakdown);

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="text-sm font-semibold mb-3">Findings by Scanner</h3>
      {entries.length === 0 ? (
        <p className="text-xs text-muted-foreground">No findings recorded</p>
      ) : (
        <div className="space-y-2">
          {entries.map(([scanner, count]) => (
            <div key={scanner} className="flex items-center justify-between">
              <span className="text-xs">
                {scanner === "InjectionSignatureLibrary"
                  ? "Tier 0 (Regex)"
                  : scanner === "ONNXSemanticClassifier"
                    ? "Tier 1 (ONNX)"
                    : scanner}
              </span>
              <span className="text-sm font-semibold">{count}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---------- Recent findings table ---------- */

function RecentFindings({
  findings,
}: {
  findings: CISDashboardData["recent_findings"];
}) {
  return (
    <div className="rounded-lg border border-border bg-card">
      <div className="px-4 py-3 border-b border-border">
        <h3 className="text-sm font-semibold">Recent Findings</h3>
      </div>
      {findings.length === 0 ? (
        <div className="p-4 text-sm text-muted-foreground text-center">
          No recent findings — all scans clean.
        </div>
      ) : (
        <div className="divide-y divide-border">
          {findings.slice(0, 10).map((f) => (
            <div
              key={f.finding_id}
              className="flex items-center gap-3 px-4 py-2 text-sm"
            >
              <SeverityBadge severity={f.severity} />
              <span className="flex-1 truncate">
                {f.rule_id} — {f.description || "No description"}
              </span>
              <span className="text-xs text-muted-foreground">
                {f.scanner === "ONNXSemanticClassifier" ? "ONNX" : "Regex"}
              </span>
              {f.timestamp && (
                <span className="text-xs text-muted-foreground">
                  {new Date(f.timestamp).toLocaleTimeString()}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---------- Main Dashboard Widget ---------- */

export function CISDashboardWidget() {
  const [data, setData] = useState<CISDashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await apiFetch("/v1/sprint56/cis-dashboard");
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const json = await resp.json();
      setData(json as CISDashboardData);
    } catch (e) {
      setError(
        e instanceof Error ? e.message : "Failed to load CIS dashboard data"
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) {
    return (
      <div className="p-8 text-center text-muted-foreground">
        Loading CIS dashboard...
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-8 text-center text-red-600">
        Error: {error}
      </div>
    );
  }

  if (!data) return null;

  const { summary, yolo_sessions, scan_mode_distribution, scanner_breakdown, recent_findings } = data;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold">CIS Dashboard</h2>
          <p className="text-sm text-muted-foreground">
            Content Ingestion Security overview
          </p>
        </div>
        <button
          type="button"
          className="rounded bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          onClick={load}
        >
          Refresh
        </button>
      </div>

      {/* YOLO alert */}
      <YOLOAlertBanner count={yolo_sessions.active_count} />

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <StatCard
          label="Total Findings"
          value={summary.total_findings}
        />
        <StatCard
          label="Critical"
          value={summary.critical}
          color={summary.critical > 0 ? "text-red-600" : "text-foreground"}
        />
        <StatCard
          label="High"
          value={summary.high}
          color={summary.high > 0 ? "text-orange-500" : "text-foreground"}
        />
        <StatCard
          label="Medium"
          value={summary.medium}
        />
        <StatCard
          label="YOLO Sessions"
          value={yolo_sessions.active_count}
          color={yolo_sessions.active_count > 0 ? "text-red-600" : "text-green-600"}
          subtext={yolo_sessions.active_count > 0 ? "1.5x risk multiplier" : "None active"}
        />
        <StatCard
          label="Low / Info"
          value={summary.low + summary.info}
        />
      </div>

      {/* Distribution widgets */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <ScanModeDistribution distribution={scan_mode_distribution} />
        <ScannerBreakdown breakdown={scanner_breakdown} />
      </div>

      {/* Recent findings */}
      <RecentFindings findings={recent_findings} />
    </div>
  );
}
