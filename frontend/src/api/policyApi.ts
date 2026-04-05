/**
 * API client for policy CRUD operations.
 *
 * All functions call `/api/v1/...` which the Vite dev-server proxies to the backend.
 * Responses are typed to match the domain models in `types/policy.ts`.
 */

import type {
  AgentRole,
  PolicyRule,
  PolicySet,
  PolicyVersion,
  RuleConflict,
} from "@/types/policy";

const BASE = "/api/v1";

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
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
  return request(`${BASE}/roles`);
}

export function createRole(role: Partial<AgentRole>): Promise<AgentRole> {
  return request(`${BASE}/roles`, {
    method: "POST",
    body: JSON.stringify(role),
  });
}

export function updateRole(
  roleId: string,
  patch: Partial<AgentRole>,
): Promise<AgentRole> {
  return request(`${BASE}/roles/${roleId}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export function deleteRole(roleId: string): Promise<void> {
  return request(`${BASE}/roles/${roleId}`, { method: "DELETE" });
}

// --- Rules ---

export function fetchRules(): Promise<PolicyRule[]> {
  return request(`${BASE}/rules`);
}

export function createRule(rule: Partial<PolicyRule>): Promise<PolicyRule> {
  return request(`${BASE}/rules`, {
    method: "POST",
    body: JSON.stringify(rule),
  });
}

export function updateRule(
  ruleId: string,
  patch: Partial<PolicyRule>,
): Promise<PolicyRule> {
  return request(`${BASE}/rules/${ruleId}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

export function deleteRule(ruleId: string): Promise<void> {
  return request(`${BASE}/rules/${ruleId}`, { method: "DELETE" });
}

export function reorderRules(
  ruleIds: string[],
): Promise<{ ok: boolean }> {
  return request(`${BASE}/rules/reorder`, {
    method: "POST",
    body: JSON.stringify({ rule_ids: ruleIds }),
  });
}

// --- Policy Sets (version history) ---

export function fetchPolicySets(): Promise<PolicySet[]> {
  return request(`${BASE}/policy-sets`);
}

export function fetchPolicySet(id: string): Promise<PolicySet> {
  return request(`${BASE}/policy-sets/${id}`);
}

export function createPolicyVersion(
  setId: string,
  version: Partial<PolicyVersion>,
): Promise<PolicyVersion> {
  return request(`${BASE}/policy-sets/${setId}/versions`, {
    method: "POST",
    body: JSON.stringify(version),
  });
}

export function restoreVersion(
  setId: string,
  versionId: string,
): Promise<PolicyVersion> {
  return request(`${BASE}/policy-sets/${setId}/versions/${versionId}/restore`, {
    method: "POST",
  });
}

export function updateVersionStatus(
  setId: string,
  versionId: string,
  status: string,
): Promise<PolicyVersion> {
  return request(`${BASE}/policy-sets/${setId}/versions/${versionId}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  });
}

// --- YAML Import/Export ---

export function exportPolicyYaml(setId: string): Promise<string> {
  return fetch(`${BASE}/policy-sets/${setId}/export/yaml`).then((res) => {
    if (!res.ok) throw new Error(`Export failed: ${res.status}`);
    return res.text();
  });
}

export function importPolicyYaml(
  yaml: string,
): Promise<PolicySet> {
  return request(`${BASE}/policy-sets/import/yaml`, {
    method: "POST",
    headers: { "Content-Type": "text/yaml" },
    body: yaml,
  });
}

// --- Conflict Detection ---

export function detectConflicts(): Promise<RuleConflict[]> {
  return request(`${BASE}/rules/conflicts`);
}
