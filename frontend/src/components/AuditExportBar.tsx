/**
 * APEP-140 — Audit export from UI.
 *
 * Provides CSV / JSON export buttons for the currently-filtered audit view.
 */

import { exportUrl, type DecisionFilters } from "@/lib/api";

export function AuditExportBar({
  filters,
  search,
}: {
  filters: DecisionFilters;
  search: string;
}) {
  const merged: DecisionFilters = { ...filters };
  if (search) merged.search = search;

  return (
    <div className="flex items-center gap-2">
      <span className="text-sm text-muted-foreground">Export:</span>
      <a
        href={exportUrl("csv", merged)}
        download="audit_export.csv"
        className="rounded border border-border px-3 py-1 text-sm hover:bg-muted"
      >
        CSV
      </a>
      <a
        href={exportUrl("json", merged)}
        download="audit_export.json"
        className="rounded border border-border px-3 py-1 text-sm hover:bg-muted"
      >
        JSON
      </a>
    </div>
  );
}
