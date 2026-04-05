import { useState } from "react";
import { bulkApprove } from "../../lib/api";

/**
 * Dialog for bulk-approving pending escalations matching a tool pattern (APEP-146).
 */
export function BulkApproveDialog({ onDone }: { onDone: () => void }) {
  const [pattern, setPattern] = useState("");
  const [comment, setComment] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    approved_count: number;
    ticket_ids: string[];
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!pattern.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await bulkApprove(pattern, comment);
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="rounded-lg border border-border bg-card p-6 space-y-4">
      <h3 className="text-lg font-semibold text-card-foreground">
        Bulk Approve
      </h3>
      <p className="text-sm text-muted-foreground">
        Approve all pending escalations whose tool name matches the glob
        pattern.
      </p>
      <form onSubmit={handleSubmit} className="space-y-3">
        <input
          type="text"
          className="w-full rounded border border-border bg-background p-2 text-sm"
          placeholder="Tool pattern (e.g., file_read.*)"
          value={pattern}
          onChange={(e) => setPattern(e.target.value)}
        />
        <textarea
          className="w-full rounded border border-border bg-background p-2 text-sm"
          placeholder="Comment (optional)"
          rows={2}
          value={comment}
          onChange={(e) => setComment(e.target.value)}
        />
        {error && <p className="text-sm text-destructive">{error}</p>}
        {result && (
          <p className="text-sm text-green-600">
            Approved {result.approved_count} ticket(s).
          </p>
        )}
        <div className="flex gap-2">
          <button
            type="submit"
            disabled={loading || !pattern.trim()}
            className="rounded bg-green-600 px-4 py-2 text-sm text-white hover:bg-green-700 disabled:opacity-50"
          >
            {loading ? "Approving..." : "Bulk Approve"}
          </button>
          <button
            type="button"
            onClick={onDone}
            className="rounded border border-border px-4 py-2 text-sm text-foreground hover:bg-muted"
          >
            Close
          </button>
        </div>
      </form>
    </div>
  );
}
