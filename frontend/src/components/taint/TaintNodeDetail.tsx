import type { TaintVisNode, TaintVisEdge } from "../../types/taint";

/**
 * Drill-down panel for a selected taint node (APEP-149).
 * Shows source, propagation path, and taint level.
 */
export function TaintNodeDetail({
  node,
  edges,
  allNodes,
  onClose,
}: {
  node: TaintVisNode;
  edges: TaintVisEdge[];
  allNodes: TaintVisNode[];
  onClose: () => void;
}) {
  const nodeMap = new Map(allNodes.map((n) => [n.id, n]));

  // Walk backwards through edges to reconstruct the propagation path
  const path = buildPropagationPath(node.id, edges, nodeMap);

  return (
    <div className="rounded-lg border border-border bg-card p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-card-foreground">
          Node Detail
        </h3>
        <button
          onClick={onClose}
          className="text-sm text-muted-foreground hover:text-foreground"
        >
          Close
        </button>
      </div>

      <div className="grid grid-cols-2 gap-3 text-sm">
        <div>
          <p className="text-xs text-muted-foreground">Node ID</p>
          <p className="font-mono text-xs break-all">{node.id}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Taint Level</p>
          <TaintBadge level={node.taint_level} />
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Source</p>
          <p className="font-medium">{node.source}</p>
        </div>
        <div>
          <p className="text-xs text-muted-foreground">Hop Depth</p>
          <p className="font-medium">{node.hop_depth}</p>
        </div>
        {node.agent_id && (
          <div>
            <p className="text-xs text-muted-foreground">Agent</p>
            <p className="font-medium">{node.agent_id}</p>
          </div>
        )}
      </div>

      {/* Propagation path */}
      <div>
        <p className="text-xs font-medium text-muted-foreground mb-2">
          Propagation Path
        </p>
        {path.length === 0 ? (
          <p className="text-sm text-muted-foreground">Root node (no ancestors)</p>
        ) : (
          <div className="space-y-1">
            {path.map((step, i) => (
              <div
                key={step.id}
                className="flex items-center gap-2 text-xs"
                style={{ paddingLeft: `${i * 16}px` }}
              >
                <span className="text-muted-foreground">
                  {i === 0 ? "Root:" : "→"}
                </span>
                <TaintBadge level={step.taint_level} />
                <span className="font-mono">{step.source}</span>
                <span className="text-muted-foreground truncate">
                  {step.id.slice(0, 8)}...
                </span>
              </div>
            ))}
            {/* Current node at end */}
            <div
              className="flex items-center gap-2 text-xs font-bold"
              style={{ paddingLeft: `${path.length * 16}px` }}
            >
              <span className="text-muted-foreground">→</span>
              <TaintBadge level={node.taint_level} />
              <span className="font-mono">{node.source}</span>
              <span className="text-muted-foreground">
                {node.id.slice(0, 8)}... (selected)
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export function TaintBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    TRUSTED: "bg-green-100 text-green-800",
    UNTRUSTED: "bg-yellow-100 text-yellow-800",
    QUARANTINE: "bg-red-100 text-red-800",
  };
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-xs font-medium ${colors[level] ?? "bg-muted text-foreground"}`}
    >
      {level}
    </span>
  );
}

function buildPropagationPath(
  nodeId: string,
  edges: TaintVisEdge[],
  nodeMap: Map<string, TaintVisNode>,
): TaintVisNode[] {
  // Build a reverse edge map (target -> sources)
  const reverseEdges = new Map<string, string[]>();
  for (const e of edges) {
    const existing = reverseEdges.get(e.target) ?? [];
    existing.push(e.source);
    reverseEdges.set(e.target, existing);
  }

  // Walk backwards from the node to roots
  const path: TaintVisNode[] = [];
  const visited = new Set<string>();
  let current = nodeId;

  while (true) {
    const parents = reverseEdges.get(current);
    if (!parents || parents.length === 0) break;
    // Take the first parent for a linear path
    const parentId = parents[0]!;
    if (visited.has(parentId)) break;
    visited.add(parentId);
    const parentNode = nodeMap.get(parentId);
    if (!parentNode) break;
    path.unshift(parentNode);
    current = parentId;
  }

  return path;
}
