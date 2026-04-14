/** Sprint 42 — TypeScript types for Plan Console UI. */

export interface PlanBudget {
  max_delegations: number | null;
  max_risk_total: number | null;
  ttl_seconds: number | null;
}

export type PlanStatus = "ACTIVE" | "EXPIRED" | "REVOKED";

export interface PlanDetail {
  plan_id: string;
  action: string;
  issuer: string;
  scope: string[];
  requires_checkpoint: string[];
  delegates_to: string[];
  budget: PlanBudget;
  human_intent: string;
  status: PlanStatus;
  signature: string;
  issued_at: string;
  expires_at: string | null;
  delegation_count: number;
  accumulated_risk: number;
  is_active: boolean;
  budget_exhausted: boolean;
}

export interface PlanListResponse {
  plans: PlanDetail[];
  total: number;
  offset: number;
  limit: number;
}

export interface CreatePlanRequest {
  action: string;
  issuer: string;
  scope: string[];
  requires_checkpoint: string[];
  delegates_to: string[];
  budget: PlanBudget;
  human_intent: string;
}

export interface BudgetUtilization {
  delegation_pct: number | null;
  risk_pct: number | null;
  ttl_pct: number | null;
}

export interface BudgetStatusResponse {
  plan_id: string;
  status: string;
  delegation_count: number;
  max_delegations: number | null;
  accumulated_risk: number;
  max_risk_total: number | null;
  ttl_seconds: number | null;
  ttl_remaining_seconds: number | null;
  issued_at: string;
  expires_at: string | null;
  exhausted_dimensions: string[];
  budget_utilization: BudgetUtilization | null;
}

export interface ReceiptChainEntry {
  decision_id: string;
  sequence_number: number;
  session_id: string;
  agent_id: string;
  agent_role: string;
  tool_name: string;
  decision: string;
  risk_score: number;
  plan_id: string | null;
  parent_receipt_id: string | null;
  receipt_signature: string;
  record_hash: string;
  previous_hash: string;
  timestamp: string;
}

export interface ReceiptChainResponse {
  plan_id: string;
  total_receipts: number;
  chain_valid: boolean;
  receipts: ReceiptChainEntry[];
}

export interface ReceiptChainSummary {
  plan_id: string;
  total_receipts: number;
  first_timestamp: string | null;
  last_timestamp: string | null;
  decision_counts: Record<string, number>;
  unique_agents: string[];
  unique_tools: string[];
  total_risk: number;
  chain_valid: boolean;
  chain_depth: number;
}
