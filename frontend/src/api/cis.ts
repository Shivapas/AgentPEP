/** API client for Sprint 54 — CIS Findings Screen. */

import { apiFetch } from "../lib/api";
import type { CISFindingsResponse, RepoScanResult, FileScanResult } from "../types/cis";

export async function fetchCISFindings(params?: {
  session_id?: string;
  severity?: string;
  scanner?: string;
  limit?: number;
  offset?: number;
}): Promise<CISFindingsResponse> {
  const searchParams = new URLSearchParams();
  if (params?.session_id) searchParams.set("session_id", params.session_id);
  if (params?.severity) searchParams.set("severity", params.severity);
  if (params?.scanner) searchParams.set("scanner", params.scanner);
  if (params?.limit) searchParams.set("limit", String(params.limit));
  if (params?.offset) searchParams.set("offset", String(params.offset));

  const qs = searchParams.toString();
  const url = `/v1/cis/findings${qs ? `?${qs}` : ""}`;
  const res = await apiFetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<CISFindingsResponse>;
}

export async function scanRepo(repoPath: string, options?: {
  session_id?: string;
  scan_mode?: string;
  max_files?: number;
}): Promise<RepoScanResult> {
  const res = await apiFetch("/v1/cis/scan-repo", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      repo_path: repoPath,
      session_id: options?.session_id,
      scan_mode: options?.scan_mode ?? "STRICT",
      max_files: options?.max_files ?? 500,
    }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<RepoScanResult>;
}

export async function scanFile(filePath: string, options?: {
  session_id?: string;
  scan_mode?: string;
}): Promise<FileScanResult> {
  const res = await apiFetch("/v1/cis/scan-file", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      file_path: filePath,
      session_id: options?.session_id,
      scan_mode: options?.scan_mode,
    }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<FileScanResult>;
}
