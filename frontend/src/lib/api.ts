/** API client for AgentPEP audit endpoints. */

const BASE = "/api/v1/audit";

export interface AuditDecision {
  decision_id: string;
  session_id: string;
  agent_id: string;
  agent_role: string;
  tool_name: string;
  tool_args_hash: string;
  taint_flags: string[];
  risk_score: number;
  delegation_chain: string[];
  matched_rule_id: string | null;
  decision: string;
  escalation_id: string | null;
  latency_ms: number;
  timestamp: string;
  chain_hash?: string | null;
}

export interface PaginatedResponse {
  items: AuditDecision[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface IntegrityRecord {
  decision_id: string;
  status: "VERIFIED" | "TAMPERED" | "UNLINKED";
  expected_hash: string;
  stored_hash: string | null;
}

export interface IntegrityResult {
  status: "VERIFIED" | "TAMPERED" | "NO_RECORDS";
  total_records: number;
  verified: number;
  tampered: number;
  records: IntegrityRecord[];
}

export interface DecisionFilters {
  page?: number;
  page_size?: number;
  sort_field?: string;
  sort_order?: "asc" | "desc";
  session_id?: string;
  agent_id?: string;
  tool_name?: string;
  decision?: string;
  risk_min?: number;
  risk_max?: number;
  start_time?: string;
  end_time?: string;
  search?: string;
}

function toParams(filters: Record<string, unknown>): URLSearchParams {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(filters)) {
    if (v !== undefined && v !== null && v !== "") {
      p.set(k, String(v));
    }
  }
  return p;
}

export async function fetchDecisions(
  filters: DecisionFilters,
): Promise<PaginatedResponse> {
  const url = `${BASE}/decisions?${toParams(filters as Record<string, unknown>)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch decisions: ${res.status}`);
  return res.json() as Promise<PaginatedResponse>;
}

export async function fetchDecisionDetail(
  decisionId: string,
): Promise<AuditDecision> {
  const res = await fetch(`${BASE}/decisions/${decisionId}`);
  if (!res.ok) throw new Error(`Failed to fetch decision: ${res.status}`);
  return res.json() as Promise<AuditDecision>;
}

export async function fetchSessionTimeline(
  sessionId: string,
): Promise<AuditDecision[]> {
  const res = await fetch(`${BASE}/sessions/${sessionId}/timeline`);
  if (!res.ok) throw new Error(`Failed to fetch timeline: ${res.status}`);
  return res.json() as Promise<AuditDecision[]>;
}

export function exportUrl(
  format: "csv" | "json",
  filters: DecisionFilters,
): string {
  const params = toParams(filters as Record<string, unknown>);
  params.set("format", format);
  return `${BASE}/export?${params}`;
}

export async function fetchIntegrity(params: {
  session_id?: string;
  start_time?: string;
  end_time?: string;
  limit?: number;
}): Promise<IntegrityResult> {
  const url = `${BASE}/integrity?${toParams(params as Record<string, unknown>)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to verify integrity: ${res.status}`);
  return res.json() as Promise<IntegrityResult>;
}
