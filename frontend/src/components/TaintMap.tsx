/**
 * Taint map graph view — D3.js DAG visualising taint propagation (APEP-148).
 * Node click drill-down: source, propagation path, taint level (APEP-149).
 */
import * as d3 from "d3";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTaintMap } from "../hooks/useTaintMap";
import type { VisualisationNode, TaintVisEdge } from "../types/taint";

const TAINT_COLORS: Record<string, string> = {
  TRUSTED: "#22c55e",
  UNTRUSTED: "#f59e0b",
  QUARANTINE: "#ef4444",
};

const NODE_RADIUS = 20;

interface SimNode extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  taint_level: string;
  source: string;
  agent_id: string | null;
  hop_depth: number;
}

interface SimLink extends d3.SimulationLinkDatum<SimNode> {
  label: string;
}

function NodeDrillDown({
  node,
  onClose,
}: {
  node: VisualisationNode;
  onClose: () => void;
}) {
  return (
    <div className="rounded-lg border border-border bg-card p-4 shadow-lg">
      <div className="flex items-start justify-between">
        <h4 className="font-semibold">Node Details</h4>
        <button
          onClick={onClose}
          className="text-muted-foreground hover:text-foreground"
        >
          Close
        </button>
      </div>
      <div className="mt-3 space-y-2 text-sm">
        <div>
          <span className="text-muted-foreground">ID:</span>{" "}
          <code className="text-xs">{node.id}</code>
        </div>
        <div>
          <span className="text-muted-foreground">Taint Level:</span>{" "}
          <span
            className="inline-block rounded px-2 py-0.5 text-xs font-medium text-white"
            style={{ backgroundColor: TAINT_COLORS[node.taint_level] || "#999" }}
          >
            {node.taint_level}
          </span>
        </div>
        <div>
          <span className="text-muted-foreground">Source:</span> {node.source}
        </div>
        <div>
          <span className="text-muted-foreground">Agent:</span>{" "}
          {node.agent_id || "—"}
        </div>
        <div>
          <span className="text-muted-foreground">Hop Depth:</span>{" "}
          {node.hop_depth}
        </div>
        <div>
          <span className="text-muted-foreground">Label:</span> {node.label}
        </div>
      </div>
    </div>
  );
}

export function TaintMap() {
  const { data, loading, error, fetchGraph } = useTaintMap();
  const [sessionId, setSessionId] = useState("");
  const [selectedNode, setSelectedNode] = useState<VisualisationNode | null>(
    null
  );
  const svgRef = useRef<SVGSVGElement>(null);

  const handleLoad = useCallback(() => {
    if (sessionId.trim()) {
      fetchGraph(sessionId.trim());
      setSelectedNode(null);
    }
  }, [sessionId, fetchGraph]);

  // D3 rendering
  useEffect(() => {
    if (!data || !svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const width = svgRef.current.clientWidth || 800;
    const height = svgRef.current.clientHeight || 500;

    // Build simulation data
    const simNodes: SimNode[] = data.nodes.map((n: VisualisationNode) => ({
      id: n.id,
      label: n.label,
      taint_level: n.taint_level,
      source: n.source,
      agent_id: n.agent_id,
      hop_depth: n.hop_depth,
    }));

    const nodeMap = new Map(simNodes.map((n) => [n.id, n]));

    const simLinks: SimLink[] = data.edges
      .filter((e: TaintVisEdge) => nodeMap.has(e.source) && nodeMap.has(e.target))
      .map((e: TaintVisEdge) => ({
        source: e.source,
        target: e.target,
        label: e.label,
      }));

    // Arrow marker
    svg
      .append("defs")
      .append("marker")
      .attr("id", "arrowhead")
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", NODE_RADIUS + 10)
      .attr("refY", 0)
      .attr("markerWidth", 8)
      .attr("markerHeight", 8)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", "#94a3b8");

    const g = svg.append("g");

    // Zoom
    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 4])
      .on("zoom", (event) => {
        g.attr("transform", event.transform);
      });
    svg.call(zoom);

    // Force simulation
    const simulation = d3
      .forceSimulation<SimNode>(simNodes)
      .force(
        "link",
        d3
          .forceLink<SimNode, SimLink>(simLinks)
          .id((d) => d.id)
          .distance(120)
      )
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide(NODE_RADIUS + 10));

    // Links
    const link = g
      .selectAll<SVGLineElement, SimLink>("line")
      .data(simLinks)
      .join("line")
      .attr("stroke", "#94a3b8")
      .attr("stroke-width", 1.5)
      .attr("marker-end", "url(#arrowhead)");

    // Node groups
    const node = g
      .selectAll<SVGGElement, SimNode>("g.node")
      .data(simNodes)
      .join("g")
      .attr("class", "node")
      .style("cursor", "pointer")
      .call(
        d3
          .drag<SVGGElement, SimNode>()
          .on("start", (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      );

    // Circles
    node
      .append("circle")
      .attr("r", NODE_RADIUS)
      .attr("fill", (d) => TAINT_COLORS[d.taint_level] || "#999")
      .attr("stroke", "#fff")
      .attr("stroke-width", 2);

    // Labels
    node
      .append("text")
      .text((d) => d.source.slice(0, 4))
      .attr("text-anchor", "middle")
      .attr("dy", "0.35em")
      .attr("fill", "#fff")
      .attr("font-size", "10px")
      .attr("font-weight", "bold")
      .attr("pointer-events", "none");

    // Hop depth below
    node
      .append("text")
      .text((d) => `h${d.hop_depth}`)
      .attr("text-anchor", "middle")
      .attr("dy", NODE_RADIUS + 14)
      .attr("fill", "#64748b")
      .attr("font-size", "9px")
      .attr("pointer-events", "none");

    // Click handler for drill-down (APEP-149)
    node.on("click", (_event, d) => {
      const original = data.nodes.find((n: VisualisationNode) => n.id === d.id);
      if (original) setSelectedNode(original);
    });

    // Tick
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
  }, [data]);

  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Taint Map</h2>

      {/* Session input */}
      <div className="flex items-center gap-2">
        <input
          className="rounded border border-border bg-background px-3 py-1.5 text-sm"
          placeholder="Session ID"
          value={sessionId}
          onChange={(e) => setSessionId(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleLoad()}
        />
        <button
          onClick={handleLoad}
          disabled={loading || !sessionId.trim()}
          className="rounded bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? "Loading..." : "Load Graph"}
        </button>
      </div>

      {error && <p className="text-sm text-red-600">{error}</p>}

      {/* Metadata */}
      {data && (
        <div className="flex gap-4 text-sm text-muted-foreground">
          <span>Nodes: {data.metadata.node_count}</span>
          <span>Edges: {data.metadata.edge_count}</span>
          <span>Max Hop: {data.metadata.max_hop_depth}</span>
          {Object.entries(data.metadata.taint_level_counts).map(([lvl, cnt]) => (
            <span key={lvl}>
              <span
                className="mr-1 inline-block h-2.5 w-2.5 rounded-full"
                style={{ backgroundColor: TAINT_COLORS[lvl] || "#999" }}
              />
              {lvl}: {cnt as number}
            </span>
          ))}
        </div>
      )}

      {/* SVG canvas */}
      <div className="relative rounded-lg border border-border bg-white">
        <svg
          ref={svgRef}
          className="h-[500px] w-full"
          style={{ minHeight: 500 }}
        />
      </div>

      {/* Node drill-down panel (APEP-149) */}
      {selectedNode && (
        <NodeDrillDown
          node={selectedNode}
          onClose={() => setSelectedNode(null)}
        />
      )}
    </div>
  );
}
