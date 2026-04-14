/** Sprint 42 — API client for Plan Management endpoints. */

import { apiFetch } from "@/lib/api";
import type {
  BudgetStatusResponse,
  CreatePlanRequest,
  PlanDetail,
  PlanListResponse,
  ReceiptChainResponse,
  ReceiptChainSummary,
} from "@/types/plans";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await apiFetch(path, init);
  if (res.status === 204) return undefined as unknown as T;
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export function listPlans(params?: {
  status?: string;
  issuer?: string;
  sort_by?: string;
  sort_dir?: string;
  offset?: number;
  limit?: number;
}): Promise<PlanListResponse> {
  const q = new URLSearchParams();
  if (params?.status) q.set("status", params.status);
  if (params?.issuer) q.set("issuer", params.issuer);
  if (params?.sort_by) q.set("sort_by", params.sort_by);
  if (params?.sort_dir) q.set("sort_dir", params.sort_dir);
  if (params?.offset !== undefined) q.set("offset", String(params.offset));
  if (params?.limit !== undefined) q.set("limit", String(params.limit));
  return request<PlanListResponse>(`/v1/plans?${q.toString()}`);
}

export function getPlan(planId: string): Promise<PlanDetail> {
  return request<PlanDetail>(`/v1/plans/${planId}`);
}

export function createPlan(body: CreatePlanRequest): Promise<PlanDetail> {
  return request<PlanDetail>("/v1/plans", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function revokePlan(planId: string): Promise<{ plan_id: string; status: string; revoked_at: string }> {
  return request(`/v1/plans/${planId}`, { method: "DELETE" });
}

export function getPlanReceipts(planId: string): Promise<ReceiptChainResponse> {
  return request<ReceiptChainResponse>(`/v1/plans/${planId}/receipts`);
}

export function getPlanReceiptsSummary(planId: string): Promise<ReceiptChainSummary> {
  return request<ReceiptChainSummary>(`/v1/plans/${planId}/receipts/summary`);
}

export function getBudgetStatus(planId: string): Promise<BudgetStatusResponse> {
  return request<BudgetStatusResponse>(`/v1/plans/${planId}/budget`);
}

export function resetBudget(
  planId: string,
  body?: {
    reset_delegations?: boolean;
    reset_risk?: boolean;
    reason?: string;
  },
): Promise<Record<string, unknown>> {
  return request(`/v1/plans/${planId}/budget/reset`, {
    method: "POST",
    body: JSON.stringify(body ?? {}),
  });
}
