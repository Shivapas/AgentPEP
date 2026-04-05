/**
 * APEP-115: Rule priority drag-and-drop reordering.
 *
 * Displays rules sorted by priority with drag handles. Reordering
 * updates the priority field and calls onReorder with the new order.
 */

import { cn } from "@/lib/utils";
import { useDragReorder } from "@/hooks/useDragReorder";
import type { PolicyRule, Decision } from "@/types/policy";

const ACTION_COLORS: Record<Decision, string> = {
  ALLOW: "bg-green-100 text-green-800",
  DENY: "bg-red-100 text-red-800",
  ESCALATE: "bg-yellow-100 text-yellow-800",
  DRY_RUN: "bg-blue-100 text-blue-800",
  TIMEOUT: "bg-gray-100 text-gray-800",
};

interface RulePriorityListProps {
  rules: PolicyRule[];
  onReorder: (ruleIds: string[]) => void;
  onEdit: (rule: PolicyRule) => void;
  onDelete: (ruleId: string) => void;
}

export function RulePriorityList({
  rules,
  onReorder,
  onEdit,
  onDelete,
}: RulePriorityListProps) {
  const sorted = [...rules].sort((a, b) => a.priority - b.priority);

  const { dragIdx, onDragStart, onDragOver, onDragEnd } = useDragReorder(
    sorted,
    (reordered) => onReorder(reordered.map((r) => r.rule_id)),
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Rule Priority</h2>
        <span className="text-xs text-muted-foreground">
          Drag to reorder. Top = highest priority.
        </span>
      </div>
      <div className="space-y-1">
        {sorted.map((rule, idx) => (
          <div
            key={rule.rule_id}
            draggable
            onDragStart={onDragStart(idx)}
            onDragOver={onDragOver(idx)}
            onDragEnd={onDragEnd}
            className={cn(
              "group flex items-center gap-3 rounded border border-border bg-card px-3 py-2 cursor-grab",
              dragIdx === idx && "opacity-50",
            )}
          >
            <span className="text-muted-foreground select-none">⠿</span>
            <span className="text-xs font-mono text-muted-foreground w-8">
              #{idx + 1}
            </span>
            <span className="font-medium text-sm flex-1">{rule.name}</span>
            <span className="font-mono text-xs text-muted-foreground">
              {rule.tool_pattern}
            </span>
            <span
              className={cn(
                "rounded px-2 py-0.5 text-xs font-medium",
                ACTION_COLORS[rule.action],
              )}
            >
              {rule.action}
            </span>
            <span className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
              <button
                onClick={() => onEdit(rule)}
                className="rounded px-1.5 py-0.5 text-xs hover:bg-accent"
              >
                Edit
              </button>
              <button
                onClick={() => onDelete(rule.rule_id)}
                className="rounded px-1.5 py-0.5 text-xs text-destructive hover:bg-destructive/10"
              >
                Delete
              </button>
            </span>
          </div>
        ))}
        {sorted.length === 0 && (
          <p className="text-sm text-muted-foreground py-4 text-center">
            No rules defined yet.
          </p>
        )}
      </div>
    </div>
  );
}
