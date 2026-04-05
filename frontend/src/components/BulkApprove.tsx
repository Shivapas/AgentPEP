/**
 * Bulk approve dialog for same-pattern pending escalations (APEP-146).
 */
import { useState } from "react";
import { apiFetch } from "../lib/api";

interface BulkApproveProps {
  toolPattern: string;
  matchCount: number;
  onComplete: () => void;
  onCancel: () => void;
}

export function BulkApprove({
  toolPattern,
  matchCount,
  onComplete,
  onCancel,
}: BulkApproveProps) {
  const [comment, setComment] = useState("");
  const [loading, setLoading] = useState(false);

  const handleBulkApprove = async () => {
    setLoading(true);
    try {
      await apiFetch("/v1/escalations/bulk-approve", {
        method: "POST",
        body: JSON.stringify({
          tool_pattern: toolPattern,
          resolved_by: "console_user",
          comment,
        }),
      });
      onComplete();
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded-lg border border-amber-300 bg-amber-50 p-4">
      <h4 className="font-medium text-amber-900">Bulk Approve</h4>
      <p className="mt-1 text-sm text-amber-800">
        Approve all <strong>{matchCount}</strong> pending escalations for tool{" "}
        <code className="rounded bg-amber-100 px-1">{toolPattern}</code>?
      </p>
      <textarea
        className="mt-2 w-full rounded border border-amber-300 bg-white px-3 py-2 text-sm"
        rows={2}
        placeholder="Comment (optional)"
        value={comment}
        onChange={(e) => setComment(e.target.value)}
      />
      <div className="mt-2 flex gap-2">
        <button
          className="rounded bg-green-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50"
          disabled={loading}
          onClick={handleBulkApprove}
        >
          Approve All ({matchCount})
        </button>
        <button
          className="rounded border border-border px-4 py-1.5 text-sm hover:bg-muted"
          onClick={onCancel}
        >
          Cancel
        </button>
      </div>
    </div>
  );
}
