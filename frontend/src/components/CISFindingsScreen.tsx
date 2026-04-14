/**
 * Sprint 54 (APEP-433) — CIS Findings Screen for the Policy Console.
 *
 * Displays Content Ingestion Security findings, including:
 *   - Finding severity breakdown (CRITICAL / HIGH / MEDIUM / LOW)
 *   - Scanner source (InjectionSignatureLibrary, ONNXSemanticClassifier)
 *   - File paths for repo-scan findings
 *   - Instruction file indicators
 *   - Session and taint context
 *   - Filtering by severity, scanner, and session
 */

import { useCallback, useEffect, useState } from "react";
import type {
  CISFinding,
  CISFindingsResponse,
  CISSeverity,
} from "../types/cis";
import { fetchCISFindings } from "../api/cis";

/* ---------- Severity badge colours ---------- */

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

/* ---------- Verdict indicator ---------- */

function VerdictIndicator({ allowed }: { allowed: boolean }) {
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${
        allowed ? "bg-green-500 text-white" : "bg-red-600 text-white"
      }`}
    >
      {allowed ? "ALLOWED" : "BLOCKED"}
    </span>
  );
}

/* ---------- Scanner badge ---------- */

function ScannerBadge({ scanner }: { scanner: string }) {
  const color =
    scanner === "ONNXSemanticClassifier"
      ? "bg-purple-500 text-white"
      : "bg-indigo-500 text-white";
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${color}`}>
      {scanner}
    </span>
  );
}

/* ---------- Instruction file badge ---------- */

function InstructionFileBadge() {
  return (
    <span className="inline-block rounded bg-amber-500 px-2 py-0.5 text-xs font-semibold text-white">
      INSTRUCTION FILE
    </span>
  );
}

/* ---------- Finding row ---------- */

function FindingRow({ finding }: { finding: CISFinding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border-b border-border last:border-b-0">
      <button
        type="button"
        className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-muted/50"
        onClick={() => setExpanded(!expanded)}
      >
        <SeverityBadge severity={finding.severity} />
        <ScannerBadge scanner={finding.scanner} />
        <span className="flex-1 truncate text-sm font-medium">
          {finding.rule_id} — {finding.description || "No description"}
        </span>
        {finding.file_path && (
          <span className="text-xs text-muted-foreground truncate max-w-[200px]">
            {finding.file_path}
          </span>
        )}
        <span className="text-xs text-muted-foreground">
          {expanded ? "▲" : "▼"}
        </span>
      </button>

      {expanded && (
        <div className="bg-muted/30 px-4 py-3 text-sm space-y-2">
          <div className="grid grid-cols-2 gap-2 text-xs">
            <div>
              <span className="font-semibold">Rule ID: </span>
              {finding.rule_id}
            </div>
            <div>
              <span className="font-semibold">Scanner: </span>
              {finding.scanner}
            </div>
            {finding.file_path && (
              <div>
                <span className="font-semibold">File: </span>
                {finding.file_path}
                {finding.line_number != null && `:${finding.line_number}`}
              </div>
            )}
            {finding.session_id && (
              <div>
                <span className="font-semibold">Session: </span>
                {finding.session_id}
              </div>
            )}
          </div>
          {finding.matched_text && (
            <div className="mt-2">
              <span className="text-xs font-semibold">Matched text:</span>
              <pre className="mt-1 rounded bg-muted p-2 text-xs overflow-x-auto">
                {finding.matched_text}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ---------- Severity summary bar ---------- */

function SeveritySummary({
  findings,
}: {
  findings: CISFinding[];
}) {
  const counts: Record<CISSeverity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  }

  return (
    <div className="flex items-center gap-4">
      {(Object.keys(counts) as CISSeverity[]).map((sev) => (
        <div key={sev} className="flex items-center gap-1">
          <SeverityBadge severity={sev} />
          <span className="text-sm font-semibold">{counts[sev]}</span>
        </div>
      ))}
    </div>
  );
}

/* ---------- Filter bar ---------- */

function FilterBar({
  severity,
  setSeverity,
  scanner,
  setScanner,
  sessionId,
  setSessionId,
}: {
  severity: string;
  setSeverity: (v: string) => void;
  scanner: string;
  setScanner: (v: string) => void;
  sessionId: string;
  setSessionId: (v: string) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-3 text-sm">
      <select
        className="rounded border border-border bg-background px-2 py-1"
        value={severity}
        onChange={(e) => setSeverity(e.target.value)}
      >
        <option value="">All severities</option>
        <option value="CRITICAL">CRITICAL</option>
        <option value="HIGH">HIGH</option>
        <option value="MEDIUM">MEDIUM</option>
        <option value="LOW">LOW</option>
        <option value="INFO">INFO</option>
      </select>

      <select
        className="rounded border border-border bg-background px-2 py-1"
        value={scanner}
        onChange={(e) => setScanner(e.target.value)}
      >
        <option value="">All scanners</option>
        <option value="InjectionSignatureLibrary">Regex (Tier 0)</option>
        <option value="ONNXSemanticClassifier">ONNX (Tier 1)</option>
      </select>

      <input
        type="text"
        placeholder="Session ID..."
        className="rounded border border-border bg-background px-2 py-1 w-48"
        value={sessionId}
        onChange={(e) => setSessionId(e.target.value)}
      />
    </div>
  );
}

/* ---------- Main component ---------- */

export function CISFindingsScreen() {
  const [findings, setFindings] = useState<CISFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [severity, setSeverity] = useState("");
  const [scanner, setScanner] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 50;

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp: CISFindingsResponse = await fetchCISFindings({
        severity: severity || undefined,
        scanner: scanner || undefined,
        session_id: sessionId || undefined,
        limit: pageSize,
        offset: page * pageSize,
      });
      setFindings(resp.findings);
      setTotal(resp.total);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load findings");
    } finally {
      setLoading(false);
    }
  }, [severity, scanner, sessionId, page]);

  useEffect(() => {
    load();
  }, [load]);

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold">CIS Findings</h2>
          <p className="text-sm text-muted-foreground">
            Content Ingestion Security scan results
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

      {/* Severity summary */}
      {findings.length > 0 && <SeveritySummary findings={findings} />}

      {/* Filters */}
      <FilterBar
        severity={severity}
        setSeverity={(v) => { setSeverity(v); setPage(0); }}
        scanner={scanner}
        setScanner={(v) => { setScanner(v); setPage(0); }}
        sessionId={sessionId}
        setSessionId={(v) => { setSessionId(v); setPage(0); }}
      />

      {/* Content */}
      <div className="rounded-lg border border-border bg-card">
        {loading && (
          <div className="p-8 text-center text-muted-foreground">
            Loading findings...
          </div>
        )}

        {error && (
          <div className="p-8 text-center text-red-600">
            Error: {error}
          </div>
        )}

        {!loading && !error && findings.length === 0 && (
          <div className="p-8 text-center text-muted-foreground">
            No CIS findings found. All scans are clean.
          </div>
        )}

        {!loading && !error && findings.length > 0 && (
          <>
            {findings.map((f) => (
              <FindingRow key={f.finding_id} finding={f} />
            ))}
          </>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">
            Showing {page * pageSize + 1}–{Math.min((page + 1) * pageSize, total)} of{" "}
            {total} findings
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              className="rounded border border-border px-3 py-1 disabled:opacity-50"
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
            >
              Previous
            </button>
            <button
              type="button"
              className="rounded border border-border px-3 py-1 disabled:opacity-50"
              disabled={page >= totalPages - 1}
              onClick={() => setPage((p) => p + 1)}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
