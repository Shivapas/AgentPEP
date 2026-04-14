/**
 * APEP-335 — Plan Explorer: Receipt Tree View
 * Visualise the plan-scoped receipt chain as a tree with node drill-down.
 */
import { useEffect, useState, useMemo } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getPlan, getPlanReceipts } from "@/api/plans";
import type { PlanDetail, ReceiptChainEntry, ReceiptChainResponse } from "@/types/plans";
import { ReceiptNodePanel } from "./ReceiptNodePanel";
import { cn } from "@/lib/utils";

interface TreeNode {
  receipt: ReceiptChainEntry;
  children: TreeNode[];
}

export function PlanExplorer() {
  const { planId } = useParams<{ planId: string }>();
  const navigate = useNavigate();
  const [plan, setPlan] = useState<PlanDetail | null>(null);
  const [chain, setChain] = useState<ReceiptChainResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedReceipt, setSelectedReceipt] = useState<ReceiptChainEntry | null>(null);

  useEffect(() => {
    if (!planId) return;
    setLoading(true);
    Promise.all([getPlan(planId), getPlanReceipts(planId)])
      .then(([p, c]) => {
        setPlan(p);
        setChain(c);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Load failed"))
      .finally(() => setLoading(false));
  }, [planId]);

  const tree = useMemo(() => {
    if (!chain) return [];
    return buildTree(chain.receipts);
  }, [chain]);

  if (loading) return <p className="text-muted-foreground">Loading receipt tree...</p>;
  if (error) {
    return (
      <div className="rounded border border-destructive bg-destructive/10 px-4 py-2 text-sm text-destructive">
        {error}
      </div>
    );
  }
  if (!plan || !planId) return <p>Plan not found.</p>;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Plan Explorer</h2>
          <p className="text-sm text-muted-foreground">{plan.action}</p>
          <p className="font-mono text-xs text-muted-foreground">{plan.plan_id}</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => navigate(`/plans/${planId}`)}
            className="rounded border border-border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Detail
          </button>
          <button
            onClick={() => navigate("/plans")}
            className="rounded border border-border px-3 py-1.5 text-sm hover:bg-muted"
          >
            Back
          </button>
        </div>
      </div>

      {/* Chain status bar */}
      <div className="flex items-center gap-4 rounded-lg border border-border bg-card px-4 py-3">
        <span className="text-sm font-medium">
          {chain?.total_receipts ?? 0} receipts
        </span>
        <span
          className={cn(
            "rounded-full px-2 py-0.5 text-xs font-medium",
            chain?.chain_valid
              ? "bg-green-500/10 text-green-600"
              : "bg-red-500/10 text-red-500",
          )}
        >
          Chain {chain?.chain_valid ? "Valid" : "Tampered"}
        </span>
      </div>

      {/* Tree + detail layout */}
      <div className="flex gap-6">
        {/* Tree */}
        <div className="min-w-0 flex-1">
          {tree.length === 0 ? (
            <p className="text-muted-foreground">No receipts in this plan yet.</p>
          ) : (
            <div className="space-y-1">
              {tree.map((node) => (
                <TreeNodeView
                  key={node.receipt.decision_id}
                  node={node}
                  depth={0}
                  selectedId={selectedReceipt?.decision_id ?? null}
                  onSelect={setSelectedReceipt}
                />
              ))}
            </div>
          )}
        </div>

        {/* Side panel */}
        {selectedReceipt && (
          <div className="w-96 shrink-0">
            <ReceiptNodePanel
              receipt={selectedReceipt}
              onClose={() => setSelectedReceipt(null)}
            />
          </div>
        )}
      </div>
    </div>
  );
}

function TreeNodeView({
  node,
  depth,
  selectedId,
  onSelect,
}: {
  node: TreeNode;
  depth: number;
  selectedId: string | null;
  onSelect: (r: ReceiptChainEntry) => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const r = node.receipt;
  const isSelected = r.decision_id === selectedId;
  const hasChildren = node.children.length > 0;

  const badge = decisionBadge(r.decision);

  return (
    <div>
      <div
        onClick={() => onSelect(r)}
        className={cn(
          "flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm hover:bg-muted/50",
          isSelected && "bg-muted",
        )}
        style={{ paddingLeft: `${depth * 24 + 8}px` }}
      >
        {/* Expand/collapse toggle */}
        {hasChildren ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              setExpanded((v) => !v);
            }}
            className="w-4 text-center text-xs text-muted-foreground"
          >
            {expanded ? "\u25BC" : "\u25B6"}
          </button>
        ) : (
          <span className="w-4 text-center text-xs text-muted-foreground">\u2022</span>
        )}

        {/* Sequence number */}
        <span className="w-8 text-right font-mono text-xs text-muted-foreground">
          #{r.sequence_number}
        </span>

        {/* Decision badge */}
        <span className={cn("rounded px-1.5 py-0.5 text-xs font-medium", badge)}>
          {r.decision}
        </span>

        {/* Tool name */}
        <span className="font-mono text-xs">{r.tool_name}</span>

        {/* Agent */}
        <span className="text-xs text-muted-foreground">{r.agent_id}</span>

        {/* Risk */}
        <span className="ml-auto text-xs text-muted-foreground">
          risk {r.risk_score.toFixed(2)}
        </span>
      </div>

      {/* Children */}
      {expanded &&
        node.children.map((child) => (
          <TreeNodeView
            key={child.receipt.decision_id}
            node={child}
            depth={depth + 1}
            selectedId={selectedId}
            onSelect={onSelect}
          />
        ))}
    </div>
  );
}

function buildTree(receipts: ReceiptChainEntry[]): TreeNode[] {
  const nodeMap = new Map<string, TreeNode>();
  const roots: TreeNode[] = [];

  // Create nodes
  for (const r of receipts) {
    nodeMap.set(r.decision_id, { receipt: r, children: [] });
  }

  // Link parent -> children
  for (const r of receipts) {
    const node = nodeMap.get(r.decision_id)!;
    if (r.parent_receipt_id && nodeMap.has(r.parent_receipt_id)) {
      nodeMap.get(r.parent_receipt_id)!.children.push(node);
    } else {
      roots.push(node);
    }
  }

  return roots;
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
