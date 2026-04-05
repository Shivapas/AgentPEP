/**
 * APEP-119: Policy conflict detector — highlights rules that may conflict
 * or shadow each other.
 *
 * Runs conflict detection client-side using the same heuristics as the
 * backend ConflictDetector, providing immediate feedback in the console.
 */

import { useMemo } from "react";
import type { PolicyRule, RuleConflict } from "@/types/policy";

// ---------- detection logic (mirrors backend) ----------

function rolesOverlap(a: string[], b: string[]): boolean {
  if (a.includes("*") || b.includes("*")) return true;
  return a.some((r) => b.includes(r));
}

function patternsOverlap(a: string, b: string): boolean {
  if (a === b) return true;
  if ((a === "*" || a === ".*") && (b === "*" || b === ".*")) return true;

  // Try matching a against b and vice versa as globs
  try {
    if (new RegExp(a).test(b)) return true;
  } catch {
    /* not a valid regex — skip */
  }
  try {
    if (new RegExp(b).test(a)) return true;
  } catch {
    /* skip */
  }

  // Prefix heuristic
  const pa = a.replace(/[.*]+$/, "");
  const pb = b.replace(/[.*]+$/, "");
  if (pa && pb && (pa.startsWith(pb) || pb.startsWith(pa))) return true;

  return false;
}

export function detectConflictsLocal(rules: PolicyRule[]): RuleConflict[] {
  const enabled = rules.filter((r) => r.enabled);
  const sorted = [...enabled].sort((a, b) => a.priority - b.priority);
  const conflicts: RuleConflict[] = [];

  for (let i = 0; i < sorted.length; i++) {
    for (let j = i + 1; j < sorted.length; j++) {
      const a = sorted[i]!;
      const b = sorted[j]!;
      if (a.action === b.action) continue;
      if (!rolesOverlap(a.agent_role, b.agent_role)) continue;
      if (!patternsOverlap(a.tool_pattern, b.tool_pattern)) continue;

      conflicts.push({
        rule_a: a,
        rule_b: b,
        overlap_type: "action_conflict",
        detail:
          `Rules '${a.name}' (priority ${a.priority}, ${a.action}) and ` +
          `'${b.name}' (priority ${b.priority}, ${b.action}) overlap on ` +
          `roles and tool patterns. First-match uses '${a.name}'.`,
      });
    }
  }
  return conflicts;
}

// ---------- component ----------

interface PolicyConflictDetectorProps {
  rules: PolicyRule[];
  /** Optional server-fetched conflicts (takes precedence if provided). */
  serverConflicts?: RuleConflict[];
}

export function PolicyConflictDetector({
  rules,
  serverConflicts,
}: PolicyConflictDetectorProps) {
  const conflicts = useMemo(
    () => serverConflicts ?? detectConflictsLocal(rules),
    [rules, serverConflicts],
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">Conflict Detector</h2>
        <span className="text-xs text-muted-foreground">
          {conflicts.length} conflict{conflicts.length !== 1 ? "s" : ""}{" "}
          detected
        </span>
      </div>

      {conflicts.length === 0 ? (
        <div className="rounded-lg border border-green-200 bg-green-50 p-4 text-sm text-green-800">
          No conflicts detected. All rules have distinct scopes.
        </div>
      ) : (
        <div className="space-y-2">
          {conflicts.map((c, i) => (
            <div
              key={i}
              className="rounded-lg border border-yellow-300 bg-yellow-50 p-4 space-y-1"
            >
              <div className="flex items-center gap-2 text-sm font-medium text-yellow-800">
                <span>Conflict #{i + 1}</span>
                <span className="rounded bg-yellow-200 px-1.5 py-0.5 text-xs">
                  {c.overlap_type}
                </span>
              </div>
              <p className="text-sm text-yellow-700">{c.detail}</p>
              <div className="flex gap-4 text-xs text-yellow-600">
                <span>
                  Rule A: <strong>{c.rule_a.name}</strong> ({c.rule_a.action},{" "}
                  priority {c.rule_a.priority})
                </span>
                <span>
                  Rule B: <strong>{c.rule_b.name}</strong> ({c.rule_b.action},{" "}
                  priority {c.rule_b.priority})
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
