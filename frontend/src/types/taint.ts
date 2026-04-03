/**
 * Taint visualization types for Sprint 18 — APEP-148, APEP-149.
 */

export type TaintLevel = "TRUSTED" | "UNTRUSTED" | "QUARANTINE";

export type TaintSource =
  | "USER_PROMPT"
  | "SYSTEM_PROMPT"
  | "WEB"
  | "EMAIL"
  | "TOOL_OUTPUT"
  | "AGENT_MSG"
  | "CROSS_AGENT"
  | "SANITISED";

export interface VisualisationNode {
  id: string;
  label: string;
  taint_level: TaintLevel;
  source: TaintSource;
  agent_id: string | null;
  hop_depth: number;
}

export interface VisualisationEdge {
  source: string;
  target: string;
  label: string;
}

export interface VisualisationMetadata {
  node_count: number;
  edge_count: number;
  max_hop_depth: number;
  taint_level_counts: Record<string, number>;
}

export interface VisualisationResponse {
  session_id: string;
  nodes: VisualisationNode[];
  edges: VisualisationEdge[];
  metadata: VisualisationMetadata;
}
