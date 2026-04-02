/**
 * APEP-141 — Hash chain integrity indicator.
 *
 * Fetches integrity verification for the current filter scope and
 * shows a VERIFIED / TAMPERED / NO_RECORDS badge.
 */

import { useEffect, useState } from "react";
import { fetchIntegrity, type IntegrityResult, type DecisionFilters } from "@/lib/api";
import { cn } from "@/lib/utils";

export function HashChainIndicator({
  filters,
  search,
}: {
  filters: DecisionFilters;
  search: string;
}) {
  const [result, setResult] = useState<IntegrityResult | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    const params: Record<string, string | number | undefined> = {};
    if (filters.session_id) params.session_id = filters.session_id;
    if (filters.start_time) params.start_time = filters.start_time;
    if (filters.end_time) params.end_time = filters.end_time;

    // Only auto-verify when session is scoped to avoid heavy queries
    if (!filters.session_id && !search) {
      params.limit = 100;
    }

    fetchIntegrity(params as { session_id?: string; start_time?: string; end_time?: string; limit?: number })
      .then(setResult)
      .catch(() => setResult(null))
      .finally(() => setLoading(false));
  }, [filters.session_id, filters.start_time, filters.end_time, search]);

  if (loading) {
    return (
      <span className="text-xs text-muted-foreground">Checking integrity...</span>
    );
  }

  if (!result) return null;

  return (
    <div className="flex items-center gap-2">
      <span
        className={cn(
          "rounded px-2 py-0.5 text-xs font-semibold",
          statusStyle(result.status),
        )}
      >
        {result.status}
      </span>
      <span className="text-xs text-muted-foreground">
        {result.verified} verified / {result.tampered} tampered of{" "}
        {result.total_records} records
      </span>
    </div>
  );
}

function statusStyle(status: string): string {
  switch (status) {
    case "VERIFIED":
      return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200";
    case "TAMPERED":
      return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200";
    default:
      return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200";
  }
}
