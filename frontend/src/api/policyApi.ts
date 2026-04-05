/**
 * API client for policy CRUD operations.
 *
 * Uses the centralized apiFetch client from lib/api.ts which handles
 * authentication headers and token refresh automatically.
 */

import type {
  AgentRole,
  PolicyRule,
  PolicySet,
  PolicyVersion,
  RuleConflict,
} from "@/types/policy";

import { apiFetch } from "@/lib/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(path, init);
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text}`);
  }
  // 204 No Content or empty body — nothing to parse
  if (
    res.status === 204 ||
    res.headers.get("content-length") === "0" ||
    !res.headers.get("content-type")?.includes("application/json")
  ) {
    return undefined as unknown as T;
  }
  return res.json() as Promise<T>;
}

// --- Roles ---

export function fetchRoles(): Promise<AgentRole[]> {
  return request(`/v1/roles`);
}

export function createRole(role: Partial<AgentRole>): Promise<AgentRole> {
  return request(`/v1/roles`, {
    method: "POST",
    body: JSON.stringify(role),
  });
}

export function updateRole(
  roleId: string,
  patch: Partial<AgentRole>,
): Promise<AgentRole> {
  return request(`/v1/roles/${roleId}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export function deleteRole(roleId: string): Promise<void> {
  return request(`/v1/roles/${roleId}`, { method: "DELETE" });
}

// --- Rules ---

export function fetchRules(): Promise<PolicyRule[]> {
  return request(`/v1/rules`);
}

export function createRule(rule: Partial<PolicyRule>): Promise<PolicyRule> {
  return request(`/v1/rules`, {
    method: "POST",
    body: JSON.stringify(rule),
  });
}

export function updateRule(
  ruleId: string,
  patch: Partial<PolicyRule>,
): Promise<PolicyRule> {
  return request(`/v1/rules/${ruleId}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export function deleteRule(ruleId: string): Promise<void> {
  return request(`/v1/rules/${ruleId}`, { method: "DELETE" });
}

export function reorderRules(
  ruleIds: string[],
): Promise<{ ok: boolean }> {
  return request(`/v1/rules/reorder`, {
    method: "POST",
    body: JSON.stringify({ rule_ids: ruleIds }),
  });
}

// --- Policy Sets (version history) ---

export function fetchPolicySets(): Promise<PolicySet[]> {
  return request(`/v1/policy-sets`);
}

export function fetchPolicySet(id: string): Promise<PolicySet> {
  return request(`/v1/policy-sets/${id}`);
}

export function createPolicyVersion(
  setId: string,
  version: Partial<PolicyVersion>,
): Promise<PolicyVersion> {
  return request(`/v1/policy-sets/${setId}/versions`, {
    method: "POST",
    body: JSON.stringify(version),
  });
}

export function restoreVersion(
  setId: string,
  versionId: string,
): Promise<PolicyVersion> {
  return request(`/v1/policy-sets/${setId}/versions/${versionId}/restore`, {
    method: "POST",
  });
}

export function updateVersionStatus(
  setId: string,
  versionId: string,
  status: string,
): Promise<PolicyVersion> {
  return request(`/v1/policy-sets/${setId}/versions/${versionId}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  });
}

// --- YAML Import/Export ---

export async function exportPolicyYaml(setId: string): Promise<string> {
  const res = await apiFetch(`/v1/policy-sets/${setId}/export/yaml`);
  if (!res.ok) throw new Error(`Export failed: ${res.status}`);
  return res.text();
}

export function importPolicyYaml(
  yaml: string,
): Promise<PolicySet> {
  return request(`/v1/policy-sets/import/yaml`, {
    method: "POST",
    headers: { "Content-Type": "text/yaml" },
    body: yaml,
  });
}

// --- Conflict Detection ---

export function detectConflicts(): Promise<RuleConflict[]> {
  return request(`/v1/rules/conflicts`);
}
