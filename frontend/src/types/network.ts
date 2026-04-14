/** TypeScript types for Sprint 51 — TFN Network Events & Security Assessment. */

export type NetworkEventType =
  | "DLP_HIT"
  | "INJECTION_DETECTED"
  | "SSRF_BLOCKED"
  | "CHAIN_DETECTED"
  | "KILL_SWITCH"
  | "SENTINEL_HIT";

export type ScanSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface NetworkEvent {
  event_id: string;
  session_id: string | null;
  agent_id: string | null;
  decision_id: string | null;
  event_type: NetworkEventType;
  scanner: string;
  finding_rule_id: string;
  severity: ScanSeverity;
  mitre_technique_id: string;
  url: string | null;
  blocked: boolean;
  timestamp: string;
}

export type AssessmentGrade = "A" | "B" | "C" | "D" | "F";

export type AssessmentCategory =
  | "DLP_COVERAGE"
  | "INJECTION_PROTECTION"
  | "SSRF_PREVENTION"
  | "RATE_LIMITING"
  | "AUTH_CONFIG"
  | "TAINT_TRACKING"
  | "KILL_SWITCH"
  | "CHAIN_DETECTION"
  | "FILESYSTEM_SENTINEL"
  | "TLS_CONFIG"
  | "AUDIT_INTEGRITY"
  | "NETWORK_EGRESS";

export type AssessmentSeverity =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "INFO"
  | "PASS";

export interface AssessmentFinding {
  finding_id: string;
  category: AssessmentCategory;
  phase: string;
  severity: AssessmentSeverity;
  title: string;
  description: string;
  recommendation: string;
  mitre_technique_id: string;
  passed: boolean;
  evidence: Record<string, unknown>;
}

export interface SecurityAssessmentResult {
  assessment_id: string;
  started_at: string;
  completed_at: string | null;
  phases_run: string[];
  findings: AssessmentFinding[];
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  critical_findings: number;
  high_findings: number;
  overall_score: number;
  grade: AssessmentGrade;
  latency_ms: number;
}

export interface RuleBundle {
  bundle_id: string;
  manifest: {
    name: string;
    version: string;
    author: string;
    description: string;
    tags: string[];
    created_at: string;
  };
  rules: Array<{
    rule_id: string;
    rule_type: string;
    severity: string;
    description: string;
    enabled: boolean;
  }>;
  status: "ACTIVE" | "INACTIVE" | "INVALID" | "PENDING_REVIEW";
  verified: boolean;
  loaded_at: string | null;
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string | null;
  description: string;
}
