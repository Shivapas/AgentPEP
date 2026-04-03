/**
 * Escalation types for Sprint 18 — APEP-143 through APEP-150.
 */

export type EscalationStatus =
  | "PENDING"
  | "APPROVED"
  | "DENIED"
  | "ESCALATED_UP"
  | "AUTO_DECIDED";

export type Decision = "ALLOW" | "DENY" | "ESCALATE" | "DRY_RUN" | "TIMEOUT";

export interface EscalationTicket {
  escalation_id: string;
  request_id: string;
  session_id: string;
  agent_id: string;
  agent_role: string;
  tool_name: string;
  tool_args: Record<string, unknown>;
  risk_score: number;
  taint_flags: string[];
  delegation_chain: string[];
  matched_rule_id: string | null;
  reason: string;
  status: EscalationStatus;
  sla_deadline: string | null;
  auto_decision: Decision;
  resolved_by: string | null;
  resolution_comment: string;
  escalated_to: string | null;
  created_at: string;
  resolved_at: string | null;
}

export interface EscalationWsMessage {
  event:
    | "escalation:snapshot"
    | "escalation:created"
    | "escalation:resolved";
  data: EscalationTicket | EscalationTicket[];
}
