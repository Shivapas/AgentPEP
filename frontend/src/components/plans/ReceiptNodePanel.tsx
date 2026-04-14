/**
 * APEP-336 — Receipt Node Drill-Down Panel
 * Displays full details for a single receipt chain entry.
 */
import type { ReceiptChainEntry } from "@/types/plans";
import { cn } from "@/lib/utils";

export function ReceiptNodePanel({
  receipt,
  onClose,
}: {
  receipt: ReceiptChainEntry;
  onClose: () => void;
}) {
  const badge = decisionBadge(receipt.decision);

  return (
    <div className="rounded-lg border border-border bg-card">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h3 className="text-sm font-semibold">Receipt Detail</h3>
        <button
          onClick={onClose}
          className="rounded px-2 py-1 text-xs text-muted-foreground hover:bg-muted"
        >
          Close
        </button>
      </div>

      {/* Content */}
      <div className="space-y-3 p-4">
        <Row label="Decision ID">
          <span className="break-all font-mono text-xs">{receipt.decision_id}</span>
        </Row>

        <Row label="Sequence">
          <span className="font-mono text-sm">#{receipt.sequence_number}</span>
        </Row>

        <Row label="Decision">
          <span className={cn("rounded px-2 py-0.5 text-xs font-medium", badge)}>
            {receipt.decision}
          </span>
        </Row>

        <Row label="Tool">
          <span className="font-mono text-sm">{receipt.tool_name}</span>
        </Row>

        <Row label="Agent">
          <span className="text-sm">{receipt.agent_id}</span>
        </Row>

        <Row label="Agent Role">
          <span className="text-sm">{receipt.agent_role || "—"}</span>
        </Row>

        <Row label="Risk Score">
          <span className="font-mono text-sm">{receipt.risk_score.toFixed(4)}</span>
        </Row>

        <Row label="Session">
          <span className="break-all font-mono text-xs">{receipt.session_id}</span>
        </Row>

        <Row label="Timestamp">
          <span className="text-sm">{new Date(receipt.timestamp).toLocaleString()}</span>
        </Row>

        {receipt.parent_receipt_id && (
          <Row label="Parent Receipt">
            <span className="break-all font-mono text-xs">{receipt.parent_receipt_id}</span>
          </Row>
        )}

        <Row label="Plan ID">
          <span className="break-all font-mono text-xs">{receipt.plan_id ?? "—"}</span>
        </Row>

        {/* Hash chain info */}
        <div className="rounded border border-border bg-muted/30 p-3">
          <h4 className="mb-2 text-xs font-semibold text-muted-foreground">Hash Chain</h4>
          <div className="space-y-1">
            <HashField label="Record Hash" value={receipt.record_hash} />
            <HashField label="Previous Hash" value={receipt.previous_hash} />
            <HashField label="Signature" value={receipt.receipt_signature} />
          </div>
        </div>
      </div>
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="shrink-0 text-xs text-muted-foreground">{label}</span>
      <div className="text-right">{children}</div>
    </div>
  );
}

function HashField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-xs text-muted-foreground">{label}:</span>
      <p className="break-all font-mono text-xs">{value || "—"}</p>
    </div>
  );
}

function decisionBadge(d: string): string {
  switch (d) {
    case "ALLOW":
      return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200";
    case "DENY":
      return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200";
    case "ESCALATE":
      return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200";
    case "TIMEOUT":
      return "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200";
    default:
      return "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200";
  }
}
