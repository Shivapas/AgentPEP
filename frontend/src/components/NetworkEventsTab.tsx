/**
 * Sprint 51 (APEP-409) — Network Events Tab for the Policy Console.
 *
 * Displays TFN network events, security assessment results, loaded
 * rule bundles, and MITRE ATT&CK technique coverage.  This component
 * is the primary UI surface for the TrustFabric Network module.
 */

import { useCallback, useEffect, useState } from "react";
import type {
  AssessmentFinding,
  AssessmentGrade,
  RuleBundle,
  SecurityAssessmentResult,
} from "../types/network";
import {
  fetchMitreStats,
  fetchRuleBundles,
  fetchSecurityAssessment,
} from "../api/network";

/* ---------- Severity badge colours ---------- */

const severityColor: Record<string, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-blue-400 text-white",
  INFO: "bg-gray-400 text-white",
  PASS: "bg-green-500 text-white",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${severityColor[severity] ?? "bg-gray-300 text-black"}`}
    >
      {severity}
    </span>
  );
}

/* ---------- Grade indicator ---------- */

const gradeColor: Record<AssessmentGrade, string> = {
  A: "text-green-600",
  B: "text-blue-600",
  C: "text-yellow-600",
  D: "text-orange-600",
  F: "text-red-600",
};

function GradeIndicator({
  grade,
  score,
}: {
  grade: AssessmentGrade;
  score: number;
}) {
  return (
    <div className="flex items-baseline gap-2">
      <span className={`text-5xl font-black ${gradeColor[grade]}`}>
        {grade}
      </span>
      <span className="text-2xl font-semibold text-muted-foreground">
        {score.toFixed(1)}%
      </span>
    </div>
  );
}

/* ---------- Assessment Summary Card ---------- */

function AssessmentSummaryCard({
  result,
}: {
  result: SecurityAssessmentResult;
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-5">
      <div className="mb-4 flex items-start justify-between">
        <div>
          <h3 className="text-lg font-semibold text-card-foreground">
            Security Assessment
          </h3>
          <p className="text-xs text-muted-foreground">
            {result.phases_run.join(", ")} | {result.latency_ms}ms
          </p>
        </div>
        <GradeIndicator
          grade={result.grade as AssessmentGrade}
          score={result.overall_score}
        />
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Stat label="Total Checks" value={result.total_checks} />
        <Stat label="Passed" value={result.passed_checks} color="text-green-600" />
        <Stat label="Failed" value={result.failed_checks} color="text-red-600" />
        <Stat label="Critical" value={result.critical_findings} color="text-red-700" />
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color?: string;
}) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={`text-xl font-bold ${color ?? "text-card-foreground"}`}>
        {value}
      </p>
    </div>
  );
}

/* ---------- Findings Table ---------- */

function FindingsTable({ findings }: { findings: AssessmentFinding[] }) {
  if (findings.length === 0) {
    return (
      <p className="py-4 text-center text-sm text-muted-foreground">
        No findings to display.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-border text-xs uppercase text-muted-foreground">
            <th className="px-3 py-2">Status</th>
            <th className="px-3 py-2">Category</th>
            <th className="px-3 py-2">Title</th>
            <th className="px-3 py-2">Severity</th>
            <th className="px-3 py-2">Phase</th>
            <th className="px-3 py-2">MITRE</th>
            <th className="px-3 py-2">Recommendation</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr
              key={f.finding_id}
              className="border-b border-border last:border-0 hover:bg-muted/50"
            >
              <td className="px-3 py-2">
                {f.passed ? (
                  <span className="text-green-600 font-bold">PASS</span>
                ) : (
                  <span className="text-red-600 font-bold">FAIL</span>
                )}
              </td>
              <td className="px-3 py-2 whitespace-nowrap">
                {f.category.replace(/_/g, " ")}
              </td>
              <td className="px-3 py-2">{f.title}</td>
              <td className="px-3 py-2">
                <SeverityBadge severity={f.severity} />
              </td>
              <td className="px-3 py-2 whitespace-nowrap text-xs">
                {f.phase.replace(/_/g, " ")}
              </td>
              <td className="px-3 py-2 font-mono text-xs">
                {f.mitre_technique_id || "-"}
              </td>
              <td className="px-3 py-2 text-xs text-muted-foreground">
                {f.recommendation || "-"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ---------- Rule Bundles Card ---------- */

function RuleBundlesCard({ bundles }: { bundles: RuleBundle[] }) {
  if (bundles.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="mb-2 text-sm font-semibold text-card-foreground">
          Rule Bundles
        </h3>
        <p className="text-sm text-muted-foreground">No bundles loaded.</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="mb-3 text-sm font-semibold text-card-foreground">
        Rule Bundles ({bundles.length})
      </h3>
      <div className="space-y-2">
        {bundles.map((b) => (
          <div
            key={b.bundle_id}
            className="flex items-center justify-between rounded border border-border p-3"
          >
            <div>
              <p className="font-medium text-sm">{b.manifest.name}</p>
              <p className="text-xs text-muted-foreground">
                v{b.manifest.version} by {b.manifest.author || "unknown"} |{" "}
                {b.rules.length} rules
              </p>
            </div>
            <div className="flex items-center gap-2">
              {b.verified && (
                <span className="rounded bg-green-100 px-2 py-0.5 text-xs font-semibold text-green-700">
                  Verified
                </span>
              )}
              <span
                className={`rounded px-2 py-0.5 text-xs font-semibold ${
                  b.status === "ACTIVE"
                    ? "bg-green-100 text-green-700"
                    : b.status === "INACTIVE"
                      ? "bg-gray-100 text-gray-600"
                      : b.status === "INVALID"
                        ? "bg-red-100 text-red-600"
                        : "bg-yellow-100 text-yellow-700"
                }`}
              >
                {b.status}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------- MITRE Coverage Card ---------- */

function MitreCoverageCard({
  stats,
}: {
  stats: { techniques: number; event_type_mappings: number; rule_id_mappings: number } | null;
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <h3 className="mb-3 text-sm font-semibold text-card-foreground">
        MITRE ATT&CK Coverage
      </h3>
      {stats ? (
        <div className="grid grid-cols-3 gap-4">
          <Stat label="Techniques" value={stats.techniques} />
          <Stat label="Event Mappings" value={stats.event_type_mappings} />
          <Stat label="Rule Mappings" value={stats.rule_id_mappings} />
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">Loading...</p>
      )}
    </div>
  );
}

/* ---------- Main NetworkEventsTab Component ---------- */

export function NetworkEventsTab() {
  const [assessment, setAssessment] = useState<SecurityAssessmentResult | null>(
    null,
  );
  const [bundles, setBundles] = useState<RuleBundle[]>([]);
  const [mitreStats, setMitreStats] = useState<{
    techniques: number;
    event_type_mappings: number;
    rule_id_mappings: number;
  } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showPassed, setShowPassed] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [assessResult, bundleResult, mitre] = await Promise.all([
        fetchSecurityAssessment(showPassed),
        fetchRuleBundles(),
        fetchMitreStats(),
      ]);
      setAssessment(assessResult);
      setBundles(bundleResult.bundles);
      setMitreStats(mitre);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, [showPassed]);

  useEffect(() => {
    void load();
  }, [load]);

  const filteredFindings = assessment
    ? showPassed
      ? assessment.findings
      : assessment.findings.filter((f) => !f.passed)
    : [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold">Network Events</h2>
          <p className="text-sm text-muted-foreground">
            TrustFabric Network security assessment, rule bundles, and MITRE
            ATT&CK coverage
          </p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-sm text-muted-foreground">
            <input
              type="checkbox"
              checked={showPassed}
              onChange={(e) => setShowPassed(e.target.checked)}
              className="rounded"
            />
            Show passed
          </label>
          <button
            onClick={() => void load()}
            className="rounded-md border border-border px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-muted"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Error banner */}
      {error && (
        <div className="rounded-lg border border-destructive bg-destructive/10 p-3 text-sm text-destructive">
          Failed to load network events: {error}
        </div>
      )}

      {/* Loading state */}
      {loading && !assessment && (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          Running security assessment...
        </div>
      )}

      {/* Content */}
      {assessment && (
        <>
          {/* Assessment summary */}
          <AssessmentSummaryCard result={assessment} />

          {/* Two-column: Bundles + MITRE */}
          <div className="grid gap-6 lg:grid-cols-2">
            <RuleBundlesCard bundles={bundles} />
            <MitreCoverageCard stats={mitreStats} />
          </div>

          {/* Findings table */}
          <div className="rounded-lg border border-border bg-card p-4">
            <h3 className="mb-3 text-sm font-semibold text-card-foreground">
              Assessment Findings ({filteredFindings.length})
            </h3>
            <FindingsTable findings={filteredFindings} />
          </div>

          {/* Footer metadata */}
          <p className="text-xs text-muted-foreground">
            Assessment ID: {assessment.assessment_id} | Completed:{" "}
            {assessment.completed_at
              ? new Date(assessment.completed_at).toLocaleString()
              : "N/A"}
          </p>
        </>
      )}
    </div>
  );
}
