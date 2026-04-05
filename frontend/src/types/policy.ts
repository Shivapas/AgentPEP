/** Domain types mirroring the backend Pydantic models for policy authoring. */

export type Decision = "ALLOW" | "DENY" | "ESCALATE" | "DRY_RUN" | "TIMEOUT";

export type TaintLevel = "TRUSTED" | "UNTRUSTED" | "QUARANTINE";

export type ReviewStatus = "draft" | "submitted" | "approved" | "active";

export interface AgentRole {
  role_id: string;
  name: string;
  parent_roles: string[];
  allowed_tools: string[];
  denied_tools: string[];
  max_risk_threshold: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface RateLimit {
  count: number;
  window_s: number;
}

export interface ArgValidator {
  arg_name: string;
  json_schema?: Record<string, unknown> | null;
  regex_pattern?: string | null;
  allowlist?: string[] | null;
  blocklist?: string[] | null;
}

export interface PolicyRule {
  rule_id: string;
  name: string;
  agent_role: string[];
  tool_pattern: string;
  action: Decision;
  taint_check: boolean;
  risk_threshold: number;
  rate_limit: RateLimit | null;
  arg_validators: ArgValidator[];
  priority: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface PolicyVersion {
  version_id: string;
  version: number;
  status: ReviewStatus;
  rules: PolicyRule[];
  roles: AgentRole[];
  author: string;
  comment: string;
  created_at: string;
}

export interface PolicySet {
  policy_set_id: string;
  name: string;
  current_version: number;
  versions: PolicyVersion[];
  created_at: string;
  updated_at: string;
}

export interface RuleConflict {
  rule_a: PolicyRule;
  rule_b: PolicyRule;
  overlap_type: string;
  detail: string;
}

/** Validation result for a single field in the rule builder. */
export interface FieldError {
  field: string;
  message: string;
}
