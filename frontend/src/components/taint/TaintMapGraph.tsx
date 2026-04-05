import { useCallback, useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import type {
  TaintVisNode,
  TaintVisEdge,
  TaintVisResponse,
} from "../../types/taint";
import { fetchTaintVisualisation } from "../../lib/api";
import { TaintNodeDetail, TaintBadge } from "./TaintNodeDetail";

const TAINT_COLORS: Record<string, string> = {
  TRUSTED: "#22c55e",
  UNTRUSTED: "#eab308",
  QUARANTINE: "#ef4444",
};

const NODE_RADIUS = 20;

interface SimNode extends d3.SimulationNodeDatum, TaintVisNode {}
interface SimLink extends d3.SimulationLinkDatum<SimNode> {
  label: string;
}

/**
 * D3.js DAG visualisation of taint propagation for a session (APEP-148).
 * Clicking a node opens the drill-down panel (APEP-149).
 */
export function TaintMapGraph() {
  const [sessionId, setSessionId] = useState("");
  const [data, setData] = useState<TaintVisResponse | null>(null);
  const [selectedNode, setSelectedNode] = useState<TaintVisNode | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const svgRef = useRef<SVGSVGElement>(null!);

  async function handleLoad() {
    if (!sessionId.trim()) return;
    setLoading(true);
    setError(null);
    setSelectedNode(null);
    try {
      const res = await fetchTaintVisualisation(sessionId);
      setData(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load");
      setData(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold">Taint Map</h2>
        <p className="text-sm text-muted-foreground">
          Visualise taint propagation DAG for a session
        </p>
      </div>

      {/* Session input */}
      <div className="flex gap-2">
        <input
          type="text"
          className="flex-1 rounded border border-border bg-background p-2 text-sm"
          placeholder="Enter session ID..."
          value={sessionId}
          onChange={(e) => setSessionId(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleLoad();
          }}
        />
        <button
          onClick={handleLoad}
          disabled={loading || !sessionId.trim()}
          className="rounded bg-primary px-4 py-2 text-sm text-primary-foreground hover:opacity-90 disabled:opacity-50"
        >
          {loading ? "Loading..." : "Load"}
        </button>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      {data && (
        <>
          {/* Metadata summary */}
          <div className="flex gap-4 text-sm">
            <span>
              Nodes: <strong>{data.metadata.node_count}</strong>
            </span>
            <span>
              Edges: <strong>{data.metadata.edge_count}</strong>
            </span>
            <span>
              Max Hop: <strong>{data.metadata.max_hop_depth}</strong>
            </span>
            {Object.entries(data.metadata.taint_level_counts).map(
              ([level, count]) => (
                <span key={level} className="flex items-center gap-1">
                  <TaintBadge level={level} /> {count}
                </span>
              ),
            )}
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            {/* D3 graph */}
            <div className="lg:col-span-2 rounded-lg border border-border bg-card overflow-hidden">
              <D3Graph
                svgRef={svgRef}
                nodes={data.nodes}
                edges={data.edges}
                onNodeClick={setSelectedNode}
                selectedNodeId={selectedNode?.id ?? null}
              />
            </div>

            {/* Drill-down panel (APEP-149) */}
            <div>
              {selectedNode ? (
                <TaintNodeDetail
                  node={selectedNode}
                  edges={data.edges}
                  allNodes={data.nodes}
                  onClose={() => setSelectedNode(null)}
                />
              ) : (
                <div className="flex h-48 items-center justify-center rounded-lg border border-dashed border-border">
                  <p className="text-muted-foreground text-sm">
                    Click a node to inspect
                  </p>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function D3Graph({
  svgRef,
  nodes,
  edges,
  onNodeClick,
  selectedNodeId,
}: {
  svgRef: React.RefObject<SVGSVGElement>;
  nodes: TaintVisNode[];
  edges: TaintVisEdge[];
  onNodeClick: (node: TaintVisNode) => void;
  selectedNodeId: string | null;
}) {
  const containerRef = useRef<HTMLDivElement>(null);

  const render = useCallback(() => {
    const svg = svgRef.current;
    const container = containerRef.current;
    if (!svg || !container) return;

    const width = container.clientWidth || 600;
    const height = 500;

    // Clear previous render
    d3.select(svg).selectAll("*").remove();

    const svgSel = d3
      .select(svg)
      .attr("width", width)
      .attr("height", height)
      .attr("viewBox", `0 0 ${width} ${height}`);

    // Zoom support
    const g = svgSel.append("g");
    svgSel.call(
      d3
        .zoom<SVGSVGElement, unknown>()
        .scaleExtent([0.2, 4])
        .on("zoom", (event: d3.D3ZoomEvent<SVGSVGElement, unknown>) => {
          g.attr("transform", event.transform.toString());
        }),
    );

    // Arrow marker for directed edges
    g.append("defs")
      .append("marker")
      .attr("id", "arrowhead")
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", NODE_RADIUS + 10)
      .attr("refY", 0)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", "#94a3b8");

    // Build simulation data
    const simNodes: SimNode[] = nodes.map((n) => ({ ...n }));
    const nodeMap = new Map(simNodes.map((n) => [n.id, n]));
    const simLinks: SimLink[] = edges
      .filter((e) => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map((e) => ({
        source: e.source,
        target: e.target,
        label: e.label,
      }));

    // Force simulation
    const simulation = d3
      .forceSimulation(simNodes)
      .force(
        "link",
        d3
          .forceLink<SimNode, SimLink>(simLinks)
          .id((d) => d.id)
          .distance(100),
      )
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collide", d3.forceCollide(NODE_RADIUS + 10));

    // Edges
    const link = g
      .append("g")
      .selectAll("line")
      .data(simLinks)
      .join("line")
      .attr("stroke", "#94a3b8")
      .attr("stroke-width", 1.5)
      .attr("marker-end", "url(#arrowhead)");

    // Node groups
    const node = g
      .append("g")
      .selectAll<SVGGElement, SimNode>("g")
      .data(simNodes)
      .join("g")
      .attr("cursor", "pointer")
      .call(
        d3
          .drag<SVGGElement, SimNode>()
          .on("start", (event: d3.D3DragEvent<SVGGElement, SimNode, SimNode>, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event: d3.D3DragEvent<SVGGElement, SimNode, SimNode>, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event: d3.D3DragEvent<SVGGElement, SimNode, SimNode>, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          }),
      )
      .on("click", (_event: MouseEvent, d: SimNode) => {
        onNodeClick(d);
      });

    // Node circles
    node
      .append("circle")
      .attr("r", NODE_RADIUS)
      .attr("fill", (d) => TAINT_COLORS[d.taint_level] ?? "#94a3b8")
      .attr("stroke", (d) =>
        d.id === selectedNodeId ? "#1e40af" : "transparent",
      )
      .attr("stroke-width", 3)
      .attr("opacity", 0.85);

    // Hop depth label inside node
    node
      .append("text")
      .text((d) => String(d.hop_depth))
      .attr("text-anchor", "middle")
      .attr("dominant-baseline", "central")
      .attr("font-size", "11px")
      .attr("font-weight", "bold")
      .attr("fill", "#fff");

    // Source label below node
    node
      .append("text")
      .text((d) => d.source)
      .attr("text-anchor", "middle")
      .attr("dy", NODE_RADIUS + 14)
      .attr("font-size", "9px")
      .attr("fill", "#64748b");

    // Tick handler
    simulation.on("tick", () => {
      link
        .attr("x1", (d) => (d.source as SimNode).x!)
        .attr("y1", (d) => (d.source as SimNode).y!)
        .attr("x2", (d) => (d.target as SimNode).x!)
        .attr("y2", (d) => (d.target as SimNode).y!);

      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    return () => {
      simulation.stop();
    };
  }, [nodes, edges, onNodeClick, selectedNodeId, svgRef]);

  useEffect(() => {
    const cleanup = render();
    return cleanup;
  }, [render]);

  return (
    <div ref={containerRef} className="w-full">
      <svg ref={svgRef} className="w-full" style={{ minHeight: 500 }} />
    </div>
  );
}
