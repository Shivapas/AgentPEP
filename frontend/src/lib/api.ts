/** Thin API client for the AgentPEP backend. */

const BASE =
  (import.meta.env.VITE_API_URL as string | undefined) ??
  `http://${window.location.hostname}:8000`;

const TOKEN_KEY = "agentpep_access_token";
const REFRESH_KEY = "agentpep_refresh_token";

let _accessToken: string | null = null;
let _refreshToken: string | null = null;
let _onAuthFailure: (() => void) | null = null;

export function getAccessToken(): string | null {
  return _accessToken;
}

export function loadTokens(): void {
  _accessToken = localStorage.getItem(TOKEN_KEY);
  _refreshToken = localStorage.getItem(REFRESH_KEY);
}

export function clearTokens(): void {
  _accessToken = null;
  _refreshToken = null;
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_KEY);
}

function saveTokens(access: string, refresh: string): void {
  _accessToken = access;
  _refreshToken = refresh;
  localStorage.setItem(TOKEN_KEY, access);
  localStorage.setItem(REFRESH_KEY, refresh);
}

export function setOnAuthFailure(cb: () => void): void {
  _onAuthFailure = cb;
}

/** Authenticated fetch wrapper that attaches Authorization + X-API-Key headers. */
export async function apiFetch(
  path: string,
  init?: RequestInit,
): Promise<Response> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (_accessToken) {
    headers["Authorization"] = `Bearer ${_accessToken}`;
    headers["X-API-Key"] = _accessToken;
  }
  const res = await fetch(`${BASE}${path}`, { ...init, headers });
  if (res.status === 401 && _refreshToken) {
    // Attempt token refresh
    const refreshRes = await fetch(`${BASE}/v1/console/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: _refreshToken }),
    });
    if (refreshRes.ok) {
      const data = await refreshRes.json();
      saveTokens(data.access_token, data.refresh_token);
      headers["Authorization"] = `Bearer ${data.access_token}`;
      headers["X-API-Key"] = data.access_token;
      return fetch(`${BASE}${path}`, { ...init, headers });
    }
    clearTokens();
    _onAuthFailure?.();
  }
  return res;
}

export async function login(
  username: string,
  password: string,
): Promise<{ success: boolean; error?: string }> {
  try {
    const res = await fetch(`${BASE}/v1/console/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      return { success: false, error: body.detail ?? `HTTP ${res.status}` };
    }
    const data = await res.json();
    saveTokens(data.access_token, data.refresh_token);
    return { success: true };
  } catch (err) {
    return { success: false, error: String(err) };
  }
}

export async function logout(): Promise<void> {
  if (_accessToken) {
    await fetch(`${BASE}/v1/console/logout`, {
      method: "POST",
      headers: { Authorization: `Bearer ${_accessToken}` },
    }).catch(() => {});
  }
  clearTokens();
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(path, init);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

/* ---- Audit types & endpoints (APEP-136..141) ---- */

export interface AuditDecision {
  decision_id: string;
  session_id: string;
  agent_id: string;
  agent_role: string;
  tool_name: string;
  tool_args_hash: string;
  decision: string;
  risk_score: number;
  latency_ms: number;
  taint_flags: string[];
  delegation_chain: string[];
  matched_rule_id: string | null;
  escalation_id: string | null;
  chain_hash?: string;
  timestamp: string;
}

export interface DecisionFilters {
  page?: number;
  page_size?: number;
  sort_field?: string;
  sort_order?: string;
  search?: string;
  session_id?: string;
  agent_id?: string;
  tool_name?: string;
  decision?: string;
  risk_min?: string;
  risk_max?: string;
  start_time?: string;
  end_time?: string;
}

export interface PaginatedResponse {
  items: AuditDecision[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface IntegrityResult {
  status: string;
  verified: number;
  tampered: number;
  total_records: number;
}

function buildQuery(params: Record<string, unknown>): string {
  const qs = Object.entries(params)
    .filter(([, v]) => v !== undefined && v !== "")
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
    .join("&");
  return qs ? `?${qs}` : "";
}

export async function fetchDecisions(
  filters: DecisionFilters,
): Promise<PaginatedResponse> {
  const res = await apiFetch(`/v1/audit/decisions${buildQuery(filters as Record<string, unknown>)}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<PaginatedResponse>;
}

export async function fetchDecisionDetail(
  decisionId: string,
): Promise<AuditDecision> {
  const res = await apiFetch(`/v1/audit/decisions/${encodeURIComponent(decisionId)}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<AuditDecision>;
}

export async function fetchSessionTimeline(
  sessionId: string,
): Promise<AuditDecision[]> {
  const res = await apiFetch(`/v1/audit/sessions/${encodeURIComponent(sessionId)}/timeline`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<AuditDecision[]>;
}

export async function fetchIntegrity(
  params: { session_id?: string; start_time?: string; end_time?: string; limit?: number },
): Promise<IntegrityResult> {
  const res = await apiFetch(`/v1/audit/verify-integrity`, {
    method: "POST",
    body: JSON.stringify(params),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<IntegrityResult>;
}

export function exportUrl(
  format: "csv" | "json",
  filters: DecisionFilters,
): string {
  const params = { ...filters, format } as Record<string, unknown>;
  return `${BASE}/v1/audit/export${buildQuery(params)}`;
}

/* ---- Escalation endpoints ---- */

export function fetchPendingTickets() {
  return request<Record<string, unknown>[]>("/v1/escalations/pending");
}

export function fetchTicket(ticketId: string) {
  return request<Record<string, unknown>>(`/v1/escalations/${ticketId}`);
}

export function resolveTicket(
  ticketId: string,
  action: string,
  comment: string,
  resolvedBy = "console_user",
) {
  return request<Record<string, unknown>>(
    `/v1/escalations/${ticketId}/resolve`,
    {
      method: "POST",
      body: JSON.stringify({
        action,
        comment,
        resolved_by: resolvedBy,
      }),
    },
  );
}

export function bulkApprove(
  toolPattern: string,
  comment: string,
  resolvedBy = "console_user",
) {
  return request<{ approved_count: number; ticket_ids: string[] }>(
    "/v1/escalations/bulk-approve",
    {
      method: "POST",
      body: JSON.stringify({
        tool_pattern: toolPattern,
        comment,
        resolved_by: resolvedBy,
      }),
    },
  );
}

export function checkSla() {
  return request<{ expired_count: number; ticket_ids: string[] }>(
    "/v1/escalations/check-sla",
    { method: "POST" },
  );
}

/* ---- Taint visualisation ---- */

import type { TaintVisResponse } from "../types/taint";

export function fetchTaintVisualisation(sessionId: string) {
  return request<TaintVisResponse>(
    `/v1/taint/session/${sessionId}/visualisation`,
  );
}
