/**
 * APEP-138 — Decision detail side panel.
 *
 * Shows full context: args hash, taint flags, delegation chain,
 * matched rule, escalation ID, risk score, and latency.
 */

import { useEffect, useState } from "react";
import { fetchDecisionDetail, type AuditDecision } from "@/lib/api";

export function DecisionDetailPanel({
  decisionId,
  onClose,
}: {
  decisionId: string;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<AuditDecision | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    fetchDecisionDetail(decisionId)
      .then(setDetail)
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : "Failed to load"),
      )
      .finally(() => setLoading(false));
  }, [decisionId]);

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-md overflow-y-auto border-l border-border bg-card shadow-lg">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h3 className="font-semibold text-card-foreground">Decision Detail</h3>
        <button
          onClick={onClose}
          className="rounded px-2 py-1 text-sm hover:bg-muted"
        >
          Close
        </button>
      </div>

      <div className="p-4 text-sm">
        {loading && <p className="text-muted-foreground">Loading...</p>}
        {error && <p className="text-destructive">{error}</p>}
        {detail && <DetailContent detail={detail} />}
      </div>
    </div>
  );
}

function DetailContent({ detail }: { detail: AuditDecision }) {
  return (
    <dl className="space-y-3">
      <Field label="Decision ID" value={detail.decision_id} mono />
      <Field label="Decision" value={detail.decision} />
      <Field label="Session ID" value={detail.session_id} mono />
      <Field label="Agent ID" value={detail.agent_id} />
      <Field label="Agent Role" value={detail.agent_role} />
      <Field label="Tool Name" value={detail.tool_name} />
      <Field label="Risk Score" value={detail.risk_score.toFixed(3)} />
      <Field label="Latency" value={`${detail.latency_ms}ms`} />
      <Field label="Tool Args Hash" value={detail.tool_args_hash} mono />
      <Field
        label="Matched Rule"
        value={detail.matched_rule_id ?? "None"}
        mono
      />
      <Field
        label="Escalation ID"
        value={detail.escalation_id ?? "None"}
        mono
      />
      <Field label="Timestamp" value={new Date(detail.timestamp).toISOString()} />

      {detail.taint_flags.length > 0 && (
        <div>
          <dt className="font-medium text-muted-foreground">Taint Flags</dt>
          <dd className="mt-1 flex flex-wrap gap-1">
            {detail.taint_flags.map((f) => (
              <span
                key={f}
                className="rounded bg-yellow-100 px-2 py-0.5 text-xs text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
              >
                {f}
              </span>
            ))}
          </dd>
        </div>
      )}

      {detail.delegation_chain.length > 0 && (
        <div>
          <dt className="font-medium text-muted-foreground">
            Delegation Chain
          </dt>
          <dd className="mt-1 space-y-1">
            {detail.delegation_chain.map((hop, i) => (
              <div
                key={i}
                className="rounded bg-muted px-2 py-1 font-mono text-xs"
              >
                {i + 1}. {hop}
              </div>
            ))}
          </dd>
        </div>
      )}

      {detail.chain_hash && (
        <Field label="Chain Hash" value={detail.chain_hash} mono />
      )}
    </dl>
  );
}

function Field({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <dt className="font-medium text-muted-foreground">{label}</dt>
      <dd
        className={`mt-0.5 break-all text-card-foreground ${mono ? "font-mono text-xs" : ""}`}
      >
        {value}
      </dd>
    </div>
  );
}
