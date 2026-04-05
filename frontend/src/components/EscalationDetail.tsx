/**
 * Escalation detail panel — tool, args, risk score, taint flags, delegation chain (APEP-144).
 */
import type { EscalationTicket } from "../types/escalation";
import { EscalationActions } from "./EscalationActions";
import { SlaTimer } from "./SlaTimer";

interface EscalationDetailProps {
  ticket: EscalationTicket;
  onClose: () => void;
  onResolved: () => void;
}

function Badge({
  children,
  variant,
}: {
  children: React.ReactNode;
  variant: "default" | "warning" | "danger" | "success";
}) {
  const colors = {
    default: "bg-gray-100 text-gray-800",
    warning: "bg-amber-100 text-amber-800",
    danger: "bg-red-100 text-red-800",
    success: "bg-green-100 text-green-800",
  };
  return (
    <span
      className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${colors[variant]}`}
    >
      {children}
    </span>
  );
}

function riskVariant(score: number) {
  if (score >= 0.8) return "danger" as const;
  if (score >= 0.5) return "warning" as const;
  return "default" as const;
}

function statusVariant(status: string) {
  switch (status) {
    case "APPROVED":
      return "success" as const;
    case "DENIED":
    case "AUTO_DECIDED":
      return "danger" as const;
    case "ESCALATED_UP":
      return "warning" as const;
    default:
      return "default" as const;
  }
}

export function EscalationDetail({
  ticket,
  onClose,
  onResolved,
}: EscalationDetailProps) {
  return (
    <div className="space-y-4 rounded-lg border border-border bg-card p-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h3 className="text-lg font-semibold">
            {ticket.tool_name}
          </h3>
          <p className="text-sm text-muted-foreground">
            {ticket.escalation_id}
          </p>
        </div>
        <button
          onClick={onClose}
          className="text-muted-foreground hover:text-foreground"
        >
          Close
        </button>
      </div>

      {/* Status & SLA */}
      <div className="flex items-center gap-3">
        <Badge variant={statusVariant(ticket.status)}>{ticket.status}</Badge>
        <Badge variant={riskVariant(ticket.risk_score)}>
          Risk: {(ticket.risk_score * 100).toFixed(0)}%
        </Badge>
        <SlaTimer
          deadline={ticket.sla_deadline}
          autoDecision={ticket.auto_decision}
        />
      </div>

      {/* Details grid */}
      <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
        <div>
          <span className="text-muted-foreground">Agent:</span>{" "}
          {ticket.agent_id}
        </div>
        <div>
          <span className="text-muted-foreground">Role:</span>{" "}
          {ticket.agent_role || "—"}
        </div>
        <div>
          <span className="text-muted-foreground">Session:</span>{" "}
          {ticket.session_id}
        </div>
        <div>
          <span className="text-muted-foreground">Matched Rule:</span>{" "}
          {ticket.matched_rule_id || "—"}
        </div>
      </div>

      {/* Reason */}
      {ticket.reason && (
        <div className="text-sm">
          <span className="font-medium">Reason:</span> {ticket.reason}
        </div>
      )}

      {/* Taint flags */}
      {ticket.taint_flags.length > 0 && (
        <div>
          <span className="text-sm font-medium">Taint Flags:</span>
          <div className="mt-1 flex flex-wrap gap-1">
            {ticket.taint_flags.map((flag) => (
              <Badge key={flag} variant="warning">
                {flag}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {/* Delegation chain */}
      {ticket.delegation_chain.length > 0 && (
        <div>
          <span className="text-sm font-medium">Delegation Chain:</span>
          <div className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
            {ticket.delegation_chain.map((agent, i) => (
              <span key={i}>
                {i > 0 && <span className="mx-1">&rarr;</span>}
                <span className="rounded bg-muted px-1.5 py-0.5">{agent}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Tool args */}
      <div>
        <span className="text-sm font-medium">Tool Arguments:</span>
        <pre className="mt-1 max-h-40 overflow-auto rounded bg-muted p-3 text-xs">
          {JSON.stringify(ticket.tool_args, null, 2)}
        </pre>
      </div>

      {/* Actions */}
      <EscalationActions ticket={ticket} onResolved={onResolved} />
    </div>
  );
}
