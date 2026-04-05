/**
 * APEP-118: Peer review workflow — draft -> submitted -> approved -> active.
 *
 * Renders the current version's review status and transition buttons.
 * Only valid forward transitions are shown. "Reject" sends back to draft.
 */

import type { PolicyVersion, ReviewStatus } from "@/types/policy";

const STATUS_ORDER: ReviewStatus[] = ["draft", "submitted", "approved", "active"];

const STATUS_META: Record<
  ReviewStatus,
  { label: string; color: string; description: string }
> = {
  draft: {
    label: "Draft",
    color: "bg-gray-100 text-gray-700 border-gray-300",
    description: "Work in progress. Only the author can edit.",
  },
  submitted: {
    label: "Submitted",
    color: "bg-blue-100 text-blue-700 border-blue-300",
    description: "Awaiting peer review.",
  },
  approved: {
    label: "Approved",
    color: "bg-green-100 text-green-700 border-green-300",
    description: "Peer-approved. Ready to activate.",
  },
  active: {
    label: "Active",
    color: "bg-purple-100 text-purple-700 border-purple-300",
    description: "Live policy enforced by the PEP engine.",
  },
};

function nextStatus(current: ReviewStatus): ReviewStatus | null {
  const idx = STATUS_ORDER.indexOf(current);
  return idx >= 0 && idx < STATUS_ORDER.length - 1
    ? STATUS_ORDER[idx + 1]!
    : null;
}

function actionLabel(from: ReviewStatus): string {
  switch (from) {
    case "draft":
      return "Submit for Review";
    case "submitted":
      return "Approve";
    case "approved":
      return "Activate";
    default:
      return "";
  }
}

interface PeerReviewWorkflowProps {
  version: PolicyVersion;
  onTransition: (versionId: string, newStatus: ReviewStatus) => void;
}

export function PeerReviewWorkflow({
  version,
  onTransition,
}: PeerReviewWorkflowProps) {
  const next = nextStatus(version.status);
  const canReject =
    version.status === "submitted" || version.status === "approved";

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Review Workflow</h2>

      {/* Status stepper */}
      <div className="flex items-center gap-2">
        {STATUS_ORDER.map((s, i) => {
          const meta = STATUS_META[s];
          const isCurrent = s === version.status;
          const isPast = STATUS_ORDER.indexOf(version.status) > i;
          return (
            <div key={s} className="flex items-center gap-2">
              {i > 0 && (
                <div
                  className={`h-0.5 w-6 ${
                    isPast ? "bg-primary" : "bg-border"
                  }`}
                />
              )}
              <div
                className={`rounded-full border px-3 py-1 text-xs font-medium ${
                  isCurrent
                    ? meta.color
                    : isPast
                      ? "bg-primary/10 text-primary border-primary/30"
                      : "bg-muted text-muted-foreground border-border"
                }`}
              >
                {meta.label}
              </div>
            </div>
          );
        })}
      </div>

      {/* Status description */}
      <p className="text-sm text-muted-foreground">
        {STATUS_META[version.status].description}
      </p>

      {/* Info */}
      <div className="text-xs text-muted-foreground space-y-1">
        <p>Author: {version.author}</p>
        <p>Version: v{version.version}</p>
        <p>Created: {new Date(version.created_at).toLocaleString()}</p>
        {version.comment && <p>Comment: {version.comment}</p>}
      </div>

      {/* Actions */}
      <div className="flex gap-2">
        {next && (
          <button
            onClick={() => onTransition(version.version_id, next)}
            className="rounded bg-primary px-4 py-1.5 text-sm text-primary-foreground hover:opacity-90"
          >
            {actionLabel(version.status)}
          </button>
        )}
        {canReject && (
          <button
            onClick={() => onTransition(version.version_id, "draft")}
            className="rounded border border-destructive px-4 py-1.5 text-sm text-destructive hover:bg-destructive/10"
          >
            Reject (back to Draft)
          </button>
        )}
      </div>
    </div>
  );
}
