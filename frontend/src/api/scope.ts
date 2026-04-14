/** Sprint 43 — API client for Scope Simulator and Pattern Library. */

import { apiFetch } from "@/lib/api";
import type {
  BatchSimulateRequest,
  BatchSimulateResponse,
  CategoryCount,
  PatternCategory,
  PatternRiskLevel,
  PatternTemplate,
  PatternTemplateListResponse,
  ScopeSimulateRequest,
  ScopeSimulateResult,
} from "@/types/scope";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(path, init);
  if (res.status === 204) return undefined as unknown as T;
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// --- Scope Simulator ---

export function simulateScope(body: ScopeSimulateRequest): Promise<ScopeSimulateResult> {
  return request<ScopeSimulateResult>("/v1/scope/simulate", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function simulateScopeBatch(body: BatchSimulateRequest): Promise<BatchSimulateResponse> {
  return request<BatchSimulateResponse>("/v1/scope/simulate/batch", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

// --- Pattern Library ---

export function listPatterns(params?: {
  category?: PatternCategory;
  risk_level?: PatternRiskLevel;
  tag?: string;
  search?: string;
  offset?: number;
  limit?: number;
}): Promise<PatternTemplateListResponse> {
  const q = new URLSearchParams();
  if (params?.category) q.set("category", params.category);
  if (params?.risk_level) q.set("risk_level", params.risk_level);
  if (params?.tag) q.set("tag", params.tag);
  if (params?.search) q.set("search", params.search);
  if (params?.offset !== undefined) q.set("offset", String(params.offset));
  if (params?.limit !== undefined) q.set("limit", String(params.limit));
  return request<PatternTemplateListResponse>(`/v1/scope/patterns?${q.toString()}`);
}

export function getPattern(templateId: string): Promise<PatternTemplate> {
  return request<PatternTemplate>(`/v1/scope/patterns/${templateId}`);
}

export function getPatternCategories(): Promise<CategoryCount[]> {
  return request<CategoryCount[]>("/v1/scope/patterns/categories");
}
