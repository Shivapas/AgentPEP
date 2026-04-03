/** Escalation ticket types matching backend models (Sprint 18). */

export type EscalationStatus =
  | "PENDING"
  | "APPROVED"
  | "DENIED"
  | "ESCALATED_UP"
  | "AUTO_DECIDED";

export interface EscalationTicket {
  ticket_id: string;
  session_id: string;
  agent_id: string;
  agent_role: string;
  tool_name: string;
  tool_args: Record<string, unknown>;
  tool_args_hash: string;
  risk_score: number;
  taint_flags: string[];
  delegation_chain: string[];
  matched_rule_id: string | null;
  reason: string;
  status: EscalationStatus;
  resolution_comment: string;
  resolved_by: string | null;
  sla_deadline: string;
  sla_seconds: number;
  created_at: string;
  resolved_at: string | null;
}

export interface EscalationWsMessage {
  type:
    | "snapshot"
    | "ticket_created"
    | "ticket_resolved"
    | "bulk_approved"
    | "sla_expired";
  tickets?: EscalationTicket[];
  ticket?: EscalationTicket;
  ticket_id?: string;
  ticket_ids?: string[];
  action?: string;
  count?: number;
  tool_pattern?: string;
}
