import { useEffect, useState } from "react";

interface ComplianceReport {
  report_id: string;
  report_type: string;
  title: string;
  status: string;
  period_start: string;
  period_end: string;
  generated_at: string | null;
  created_at: string;
  content: Record<string, unknown>;
}

interface ReportListResponse {
  reports: ComplianceReport[];
  total: number;
}

const REPORT_TYPES = [
  { value: "DPDPA", label: "DPDPA (India)" },
  { value: "GDPR_ART25", label: "GDPR Art. 25" },
  { value: "CERT_IN_BOM", label: "CERT-In BOM" },
];

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    COMPLETED: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
    GENERATING: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
    FAILED: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
    PENDING: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200",
  };
  return (
    <span
      className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${colors[status] ?? colors.PENDING}`}
    >
      {status}
    </span>
  );
}

export function ComplianceReports() {
  const [reports, setReports] = useState<ComplianceReport[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Generate form state
  const [genType, setGenType] = useState("DPDPA");
  const [periodStart, setPeriodStart] = useState("");
  const [periodEnd, setPeriodEnd] = useState("");
  const [generating, setGenerating] = useState(false);

  // Preview state
  const [previewReport, setPreviewReport] = useState<ComplianceReport | null>(
    null,
  );

  const fetchReports = async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await fetch("/api/v1/compliance/reports?limit=50");
      if (!resp.ok) throw new Error(`Failed to fetch reports: ${resp.status}`);
      const data: ReportListResponse = await resp.json();
      setReports(data.reports);
      setTotal(data.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load reports");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!periodStart || !periodEnd) return;
    setGenerating(true);
    setError(null);
    try {
      const resp = await fetch("/api/v1/compliance/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          report_type: genType,
          period_start: new Date(periodStart).toISOString(),
          period_end: new Date(periodEnd).toISOString(),
        }),
      });
      if (!resp.ok) throw new Error(`Generation failed: ${resp.status}`);
      await fetchReports();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to generate report",
      );
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (reportId: string) => {
    const resp = await fetch(
      `/api/v1/compliance/reports/${reportId}/download`,
    );
    if (!resp.ok) return;
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download =
      resp.headers.get("content-disposition")?.split("filename=")[1]?.replace(/"/g, "") ??
      "report.json";
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePreview = (report: ComplianceReport) => {
    setPreviewReport(previewReport?.report_id === report.report_id ? null : report);
  };

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Compliance Reports</h2>

      {/* Generate Report Form */}
      <div className="rounded-lg border border-border bg-card p-6">
        <h3 className="mb-4 text-lg font-semibold">Generate Report</h3>
        <form onSubmit={handleGenerate} className="flex flex-wrap items-end gap-4">
          <div>
            <label className="mb-1 block text-sm text-muted-foreground">
              Report Type
            </label>
            <select
              value={genType}
              onChange={(e) => setGenType(e.target.value)}
              className="rounded border border-border bg-background px-3 py-2 text-sm"
            >
              {REPORT_TYPES.map((rt) => (
                <option key={rt.value} value={rt.value}>
                  {rt.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-sm text-muted-foreground">
              Period Start
            </label>
            <input
              type="date"
              value={periodStart}
              onChange={(e) => setPeriodStart(e.target.value)}
              className="rounded border border-border bg-background px-3 py-2 text-sm"
              required
            />
          </div>
          <div>
            <label className="mb-1 block text-sm text-muted-foreground">
              Period End
            </label>
            <input
              type="date"
              value={periodEnd}
              onChange={(e) => setPeriodEnd(e.target.value)}
              className="rounded border border-border bg-background px-3 py-2 text-sm"
              required
            />
          </div>
          <button
            type="submit"
            disabled={generating}
            className="rounded bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            {generating ? "Generating..." : "Generate"}
          </button>
        </form>
      </div>

      {/* Error */}
      {error && (
        <div className="rounded border border-destructive bg-destructive/10 p-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {/* Reports Table */}
      <div className="rounded-lg border border-border bg-card">
        <div className="border-b border-border px-6 py-3">
          <h3 className="text-lg font-semibold">
            Generated Reports{" "}
            <span className="text-sm font-normal text-muted-foreground">
              ({total})
            </span>
          </h3>
        </div>
        {loading ? (
          <div className="p-6 text-center text-muted-foreground">Loading...</div>
        ) : reports.length === 0 ? (
          <div className="p-6 text-center text-muted-foreground">
            No reports generated yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="px-6 py-3 font-medium">Type</th>
                  <th className="px-6 py-3 font-medium">Title</th>
                  <th className="px-6 py-3 font-medium">Status</th>
                  <th className="px-6 py-3 font-medium">Period</th>
                  <th className="px-6 py-3 font-medium">Generated</th>
                  <th className="px-6 py-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {reports.map((r) => (
                  <tr
                    key={r.report_id}
                    className="border-b border-border last:border-0"
                  >
                    <td className="px-6 py-3 font-mono text-xs">
                      {r.report_type}
                    </td>
                    <td className="px-6 py-3">{r.title}</td>
                    <td className="px-6 py-3">
                      <StatusBadge status={r.status} />
                    </td>
                    <td className="px-6 py-3 text-xs text-muted-foreground">
                      {new Date(r.period_start).toLocaleDateString()} &ndash;{" "}
                      {new Date(r.period_end).toLocaleDateString()}
                    </td>
                    <td className="px-6 py-3 text-xs text-muted-foreground">
                      {r.generated_at
                        ? new Date(r.generated_at).toLocaleString()
                        : "--"}
                    </td>
                    <td className="px-6 py-3">
                      <div className="flex gap-2">
                        <button
                          onClick={() => handlePreview(r)}
                          className="rounded border border-border px-2 py-1 text-xs hover:bg-muted"
                        >
                          {previewReport?.report_id === r.report_id
                            ? "Close"
                            : "Preview"}
                        </button>
                        <button
                          onClick={() => handleDownload(r.report_id)}
                          className="rounded border border-border px-2 py-1 text-xs hover:bg-muted"
                        >
                          Download
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Report Preview */}
      {previewReport && (
        <div className="rounded-lg border border-border bg-card p-6">
          <h3 className="mb-4 text-lg font-semibold">
            Preview: {previewReport.title}
          </h3>
          <pre className="max-h-96 overflow-auto rounded bg-muted p-4 text-xs">
            {JSON.stringify(previewReport.content, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
