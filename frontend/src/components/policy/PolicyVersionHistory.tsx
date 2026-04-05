/**
 * APEP-117: Policy version history — list versions, restore, diff two
 * versions side-by-side.
 */

import { useState, useMemo } from "react";
import type { PolicyVersion, PolicyRule, ReviewStatus } from "@/types/policy";

// ---------- diff helpers ----------

interface DiffLine {
  type: "same" | "added" | "removed";
  text: string;
}

function diffLines(a: string, b: string): DiffLine[] {
  const linesA = a.split("\n");
  const linesB = b.split("\n");
  const result: DiffLine[] = [];

  const max = Math.max(linesA.length, linesB.length);
  // Simple line-by-line diff (good enough for structured YAML/JSON output)
  let ia = 0;
  let ib = 0;
  while (ia < linesA.length || ib < linesB.length) {
    if (ia >= linesA.length) {
      result.push({ type: "added", text: linesB[ib]! });
      ib++;
    } else if (ib >= linesB.length) {
      result.push({ type: "removed", text: linesA[ia]! });
      ia++;
    } else if (linesA[ia] === linesB[ib]) {
      result.push({ type: "same", text: linesA[ia]! });
      ia++;
      ib++;
    } else {
      // Look ahead for a match
      const lookAhead = 3;
      let foundA = -1;
      let foundB = -1;
      for (let d = 1; d <= lookAhead && d + ia < linesA.length; d++) {
        if (linesA[ia + d] === linesB[ib]) { foundA = d; break; }
      }
      for (let d = 1; d <= lookAhead && d + ib < linesB.length; d++) {
        if (linesA[ia] === linesB[ib + d]) { foundB = d; break; }
      }
      if (foundA >= 0 && (foundB < 0 || foundA <= foundB)) {
        for (let d = 0; d < foundA; d++) {
          result.push({ type: "removed", text: linesA[ia + d]! });
        }
        ia += foundA;
      } else if (foundB >= 0) {
        for (let d = 0; d < foundB; d++) {
          result.push({ type: "added", text: linesB[ib + d]! });
        }
        ib += foundB;
      } else {
        result.push({ type: "removed", text: linesA[ia]! });
        result.push({ type: "added", text: linesB[ib]! });
        ia++;
        ib++;
      }
    }
    if (result.length > max * 3) break; // safety valve
  }
  return result;
}

function ruleSummary(rules: PolicyRule[]): string {
  return rules
    .map(
      (r) =>
        `${r.name} [${r.action}] tool=${r.tool_pattern} roles=${r.agent_role.join(",")} priority=${r.priority}`,
    )
    .join("\n");
}

// ---------- status badge ----------

const STATUS_COLORS: Record<ReviewStatus, string> = {
  draft: "bg-gray-100 text-gray-700",
  submitted: "bg-blue-100 text-blue-700",
  approved: "bg-green-100 text-green-700",
  active: "bg-purple-100 text-purple-700",
};

// ---------- component ----------

interface PolicyVersionHistoryProps {
  versions: PolicyVersion[];
  onRestore: (versionId: string) => void;
}

export function PolicyVersionHistory({
  versions,
  onRestore,
}: PolicyVersionHistoryProps) {
  const sorted = useMemo(
    () => [...versions].sort((a, b) => b.version - a.version),
    [versions],
  );

  const [diffA, setDiffA] = useState<string | null>(null);
  const [diffB, setDiffB] = useState<string | null>(null);

  const diffResult = useMemo(() => {
    if (!diffA || !diffB) return null;
    const vA = sorted.find((v) => v.version_id === diffA);
    const vB = sorted.find((v) => v.version_id === diffB);
    if (!vA || !vB) return null;
    return diffLines(ruleSummary(vA.rules), ruleSummary(vB.rules));
  }, [diffA, diffB, sorted]);

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">Version History</h2>

      {/* version list */}
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-muted">
            <tr>
              <th className="text-left px-3 py-2">#</th>
              <th className="text-left px-3 py-2">Status</th>
              <th className="text-left px-3 py-2">Author</th>
              <th className="text-left px-3 py-2">Comment</th>
              <th className="text-left px-3 py-2">Date</th>
              <th className="text-left px-3 py-2">Diff</th>
              <th className="text-right px-3 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((v) => (
              <tr key={v.version_id} className="border-t border-border">
                <td className="px-3 py-2 font-mono">v{v.version}</td>
                <td className="px-3 py-2">
                  <span
                    className={`rounded px-2 py-0.5 text-xs font-medium ${STATUS_COLORS[v.status]}`}
                  >
                    {v.status}
                  </span>
                </td>
                <td className="px-3 py-2">{v.author}</td>
                <td className="px-3 py-2 text-muted-foreground max-w-xs truncate">
                  {v.comment}
                </td>
                <td className="px-3 py-2 text-xs text-muted-foreground">
                  {new Date(v.created_at).toLocaleString()}
                </td>
                <td className="px-3 py-2">
                  <label className="flex items-center gap-1 text-xs">
                    <input
                      type="radio"
                      name="diffA"
                      checked={diffA === v.version_id}
                      onChange={() => setDiffA(v.version_id)}
                    />
                    A
                  </label>
                  <label className="flex items-center gap-1 text-xs">
                    <input
                      type="radio"
                      name="diffB"
                      checked={diffB === v.version_id}
                      onChange={() => setDiffB(v.version_id)}
                    />
                    B
                  </label>
                </td>
                <td className="px-3 py-2 text-right">
                  <button
                    onClick={() => onRestore(v.version_id)}
                    className="rounded border border-border px-2 py-0.5 text-xs hover:bg-secondary"
                  >
                    Restore
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* diff view */}
      {diffResult && (
        <div className="space-y-2">
          <h3 className="text-sm font-semibold">
            Diff: v
            {sorted.find((v) => v.version_id === diffA)?.version} vs v
            {sorted.find((v) => v.version_id === diffB)?.version}
          </h3>
          <div className="rounded-lg border border-border bg-card p-4 font-mono text-xs overflow-x-auto max-h-96 overflow-y-auto">
            {diffResult.map((line, i) => (
              <div
                key={i}
                className={
                  line.type === "added"
                    ? "bg-green-50 text-green-800"
                    : line.type === "removed"
                      ? "bg-red-50 text-red-800"
                      : ""
                }
              >
                <span className="select-none text-muted-foreground mr-2">
                  {line.type === "added"
                    ? "+"
                    : line.type === "removed"
                      ? "-"
                      : " "}
                </span>
                {line.text}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
