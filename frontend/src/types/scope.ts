/** Sprint 43 — Scope simulator and pattern library types. */

export interface ScopeSimulateRequest {
  plan_id?: string;
  scope?: string[];
  requires_checkpoint?: string[];
  tool_name: string;
  action?: string;
}

export interface ScopeSimulateResult {
  tool_name: string;
  action: string;
  scope_allowed: boolean;
  scope_matched_pattern: string | null;
  scope_reason: string;
  checkpoint_triggered: boolean;
  checkpoint_matched_pattern: string | null;
  checkpoint_reason: string;
  effective_decision: "ALLOW" | "DENY" | "ESCALATE";
  compiled_rbac_patterns: string[];
}

export interface BatchSimulateRequest {
  scope: string[];
  requires_checkpoint: string[];
  tool_names: string[];
  action?: string;
}

export interface BatchSimulateResponse {
  results: ScopeSimulateResult[];
  summary: {
    total: number;
    allowed: number;
    denied: number;
    escalated: number;
  };
}

export type PatternCategory =
  | "data_access"
  | "code_execution"
  | "network"
  | "secrets"
  | "admin"
  | "messaging"
  | "deployment"
  | "compliance"
  | "custom";

export type PatternRiskLevel = "low" | "medium" | "high" | "critical";

export interface PatternTemplate {
  template_id: string;
  name: string;
  description: string;
  category: PatternCategory;
  risk_level: PatternRiskLevel;
  scope_patterns: string[];
  checkpoint_patterns: string[];
  tags: string[];
  use_cases: string[];
  author: string;
  version: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface PatternTemplateListResponse {
  templates: PatternTemplate[];
  total: number;
  offset: number;
  limit: number;
}

export interface CategoryCount {
  category: string;
  count: number;
}
