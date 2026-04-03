import { useState } from "react";
import type { EscalationTicket } from "../../types/escalation";
import { resolveTicket } from "../../lib/api";
import { SlaTimer } from "./SlaTimer";

/**
 * Detail panel showing full escalation context and action buttons.
 * APEP-144: tool, args, risk score, taint flags, delegation chain.
 * APEP-145: approve / deny / escalate-up actions with comment field.
 */
export function EscalationDetailPanel({
  ticket,
  onResolved,
  onClose,
}: {
  ticket: EscalationTicket;
  onResolved: () => void;
  onClose: () => void;
}) {
  const [comment, setComment] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isPending = ticket.status === "PENDING";

  async function handleAction(action: "APPROVED" | "DENIED" | "ESCALATED_UP") {
    setLoading(true);
    setError(null);
    try {
      await resolveTicket(ticket.ticket_id, action, comment);
      onResolved();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="rounded-lg border border-border bg-card p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-card-foreground">
          Escalation Detail
        </h3>
        <button
          onClick={onClose}
          className="text-sm text-muted-foreground hover:text-foreground"
        >
          Close
        </button>
      </div>

      {/* Ticket metadata */}
      <div className="grid grid-cols-2 gap-3 text-sm">
        <Field label="Ticket ID" value={ticket.ticket_id} />
        <Field label="Status" value={ticket.status} />
        <Field label="Session" value={ticket.session_id} />
        <Field label="Agent" value={`${ticket.agent_id} (${ticket.agent_role})`} />
        <Field label="Tool" value={ticket.tool_name} />
        <Field
          label="Risk Score"
          value={ticket.risk_score.toFixed(2)}
        />
        <Field
          label="SLA Remaining"
          value={<SlaTimer deadline={ticket.sla_deadline} />}
        />
        <Field label="Matched Rule" value={ticket.matched_rule_id ?? "—"} />
      </div>

      {/* Tool args */}
      <div>
        <p className="text-xs font-medium text-muted-foreground mb-1">
          Tool Arguments
        </p>
        <pre className="rounded bg-muted p-3 text-xs overflow-auto max-h-40">
          {JSON.stringify(ticket.tool_args, null, 2)}
        </pre>
      </div>

      {/* Taint flags */}
      {ticket.taint_flags.length > 0 && (
        <div>
          <p className="text-xs font-medium text-muted-foreground mb-1">
            Taint Flags
          </p>
          <div className="flex flex-wrap gap-1">
            {ticket.taint_flags.map((flag) => (
              <span
                key={flag}
                className="rounded-full bg-destructive/10 px-2 py-0.5 text-xs text-destructive"
              >
                {flag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Delegation chain */}
      {ticket.delegation_chain.length > 0 && (
        <div>
          <p className="text-xs font-medium text-muted-foreground mb-1">
            Delegation Chain
          </p>
          <p className="text-sm text-foreground">
            {ticket.delegation_chain.join(" → ")}
          </p>
        </div>
      )}

      {/* Reason */}
      {ticket.reason && (
        <div>
          <p className="text-xs font-medium text-muted-foreground mb-1">
            Reason
          </p>
          <p className="text-sm text-foreground">{ticket.reason}</p>
        </div>
      )}

      {/* Resolution (if already resolved) */}
      {!isPending && (
        <div className="rounded bg-muted p-3 text-sm">
          <p>
            <strong>Resolved:</strong> {ticket.status} by{" "}
            {ticket.resolved_by ?? "system"}
          </p>
          {ticket.resolution_comment && (
            <p className="text-muted-foreground mt-1">
              {ticket.resolution_comment}
            </p>
          )}
        </div>
      )}

      {/* APEP-145: Action buttons */}
      {isPending && (
        <div className="space-y-3 pt-2 border-t border-border">
          <textarea
            className="w-full rounded border border-border bg-background p-2 text-sm"
            placeholder="Add a comment..."
            rows={2}
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
          {error && <p className="text-sm text-destructive">{error}</p>}
          <div className="flex gap-2">
            <button
              disabled={loading}
              onClick={() => handleAction("APPROVED")}
              className="rounded bg-green-600 px-4 py-2 text-sm text-white hover:bg-green-700 disabled:opacity-50"
            >
              Approve
            </button>
            <button
              disabled={loading}
              onClick={() => handleAction("DENIED")}
              className="rounded bg-destructive px-4 py-2 text-sm text-destructive-foreground hover:opacity-90 disabled:opacity-50"
            >
              Deny
            </button>
            <button
              disabled={loading}
              onClick={() => handleAction("ESCALATED_UP")}
              className="rounded border border-border px-4 py-2 text-sm text-foreground hover:bg-muted disabled:opacity-50"
            >
              Escalate Up
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function Field({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="font-medium text-foreground break-all">
        {typeof value === "string" ? value : value}
      </p>
    </div>
  );
}
