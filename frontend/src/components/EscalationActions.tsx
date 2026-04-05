/**
 * Approve / Deny / Escalate-up actions with comment field (APEP-145).
 */
import { useState } from "react";
import type { EscalationTicket } from "../types/escalation";

interface EscalationActionsProps {
  ticket: EscalationTicket;
  onResolved: () => void;
}

export function EscalationActions({
  ticket,
  onResolved,
}: EscalationActionsProps) {
  const [comment, setComment] = useState("");
  const [escalateTo, setEscalateTo] = useState("");
  const [loading, setLoading] = useState(false);

  const resolve = async (action: "approve" | "deny" | "escalate-up") => {
    setLoading(true);
    try {
      const body: Record<string, string> = {
        resolved_by: "console_user",
        comment,
      };
      if (action === "escalate-up") {
        body.escalated_to = escalateTo;
      }
      await fetch(`/v1/escalations/${ticket.escalation_id}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      onResolved();
    } finally {
      setLoading(false);
    }
  };

  if (ticket.status !== "PENDING") {
    return (
      <div className="rounded border border-border bg-muted/50 p-3 text-sm">
        <span className="font-medium">Resolved:</span> {ticket.status}
        {ticket.resolved_by && (
          <span className="ml-2 text-muted-foreground">
            by {ticket.resolved_by}
          </span>
        )}
        {ticket.resolution_comment && (
          <p className="mt-1 text-muted-foreground">
            {ticket.resolution_comment}
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <textarea
        className="w-full rounded border border-border bg-background px-3 py-2 text-sm"
        rows={2}
        placeholder="Comment (optional)"
        value={comment}
        onChange={(e) => setComment(e.target.value)}
      />
      <div className="flex items-center gap-2">
        <button
          className="rounded bg-green-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50"
          disabled={loading}
          onClick={() => resolve("approve")}
        >
          Approve
        </button>
        <button
          className="rounded bg-red-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
          disabled={loading}
          onClick={() => resolve("deny")}
        >
          Deny
        </button>
        <input
          className="rounded border border-border bg-background px-2 py-1.5 text-sm"
          placeholder="Escalate to..."
          value={escalateTo}
          onChange={(e) => setEscalateTo(e.target.value)}
        />
        <button
          className="rounded bg-amber-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-amber-700 disabled:opacity-50"
          disabled={loading || !escalateTo}
          onClick={() => resolve("escalate-up")}
        >
          Escalate Up
        </button>
      </div>
    </div>
  );
}
