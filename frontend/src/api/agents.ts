/** API client for Agent Registry endpoints. */

import { apiFetch } from "@/lib/api";

export interface Agent {
  agent_id: string;
  name: string;
  roles: string[];
  allowed_tools: string[];
  risk_budget: number;
  max_delegation_depth: number;
  session_limit: number;
  enabled: boolean;
  decision_count: number;
  created_at: string;
  updated_at: string;
}

export interface AgentListResponse {
  agents: Agent[];
  total: number;
}

export interface AgentCreateRequest {
  agent_id: string;
  name: string;
  roles: string[];
  allowed_tools: string[];
  risk_budget: number;
  max_delegation_depth: number;
  session_limit: number;
}

export interface AgentUpdateRequest {
  name?: string;
  roles?: string[];
  allowed_tools?: string[];
  risk_budget?: number;
  max_delegation_depth?: number;
  session_limit?: number;
  enabled?: boolean;
}

export interface APIKey {
  key_id: string;
  prefix: string;
  name: string;
  agent_id: string;
  enabled: boolean;
  created_at: string;
  plain_key?: string | null;
}

export interface ActivityEntry {
  decision_id: string;
  session_id: string;
  tool_name: string;
  decision: string;
  risk_score: number;
  timestamp: string;
}

export interface DelegationGrant {
  target_agent_id: string;
  granted_tools: string[];
  authority_source: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(path, init);
  if (res.status === 204) return undefined as unknown as T;
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export function listAgents(params?: {
  sort_by?: string;
  sort_dir?: string;
  role?: string;
  enabled?: boolean;
  offset?: number;
  limit?: number;
}): Promise<AgentListResponse> {
  const q = new URLSearchParams();
  if (params?.sort_by) q.set("sort_by", params.sort_by);
  if (params?.sort_dir) q.set("sort_dir", params.sort_dir);
  if (params?.role) q.set("role", params.role);
  if (params?.enabled !== undefined) q.set("enabled", String(params.enabled));
  if (params?.offset !== undefined) q.set("offset", String(params.offset));
  if (params?.limit !== undefined) q.set("limit", String(params.limit));
  return request<AgentListResponse>(`/v1/agents?${q.toString()}`);
}

export function getAgent(agentId: string): Promise<Agent> {
  return request<Agent>(`/v1/agents/${agentId}`);
}

export function createAgent(body: AgentCreateRequest): Promise<Agent> {
  return request<Agent>("/v1/agents", { method: "POST", body: JSON.stringify(body) });
}

export function updateAgent(agentId: string, body: AgentUpdateRequest): Promise<Agent> {
  return request<Agent>(`/v1/agents/${agentId}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  });
}

export function deleteAgent(agentId: string): Promise<void> {
  return request<void>(`/v1/agents/${agentId}`, { method: "DELETE" });
}

// API Keys
export function listKeys(agentId: string): Promise<{ keys: APIKey[] }> {
  return request<{ keys: APIKey[] }>(`/v1/agents/${agentId}/keys`);
}

export function generateKey(agentId: string, name = "default"): Promise<APIKey> {
  return request<APIKey>(`/v1/agents/${agentId}/keys?name=${encodeURIComponent(name)}`, {
    method: "POST",
  });
}

export function rotateKey(agentId: string, keyId: string): Promise<APIKey> {
  return request<APIKey>(`/v1/agents/${agentId}/keys/${keyId}/rotate`, { method: "POST" });
}

export function revokeKey(agentId: string, keyId: string): Promise<void> {
  return request<void>(`/v1/agents/${agentId}/keys/${keyId}`, { method: "DELETE" });
}

// Activity
export function getActivity(
  agentId: string,
  limit = 100,
): Promise<{ agent_id: string; entries: ActivityEntry[]; total: number }> {
  return request(`/v1/agents/${agentId}/activity?limit=${limit}`);
}

// Bulk roles
export function bulkAssignRoles(
  agentIds: string[],
  roles: string[],
): Promise<{ updated: number; agent_ids: string[] }> {
  return request(`/v1/agents/bulk/roles`, {
    method: "POST",
    body: JSON.stringify({ agent_ids: agentIds, roles }),
  });
}

// Delegations
export function getDelegations(
  agentId: string,
): Promise<{ agent_id: string; grants: DelegationGrant[] }> {
  return request(`/v1/agents/${agentId}/delegations`);
}
