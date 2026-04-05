/** Taint visualisation types matching backend APEP-050 response. */

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

export interface TaintVisNode {
  id: string;
  label: string;
  taint_level: TaintLevel;
  source: TaintSource;
  agent_id: string | null;
  hop_depth: number;
}

export interface TaintVisEdge {
  source: string;
  target: string;
  label: string;
}

export interface TaintVisMetadata {
  node_count: number;
  edge_count: number;
  max_hop_depth: number;
  taint_level_counts: Record<string, number>;
}

export interface TaintVisResponse {
  session_id: string;
  nodes: TaintVisNode[];
  edges: TaintVisEdge[];
  metadata: TaintVisMetadata;
}

/** Aliases used by components and hooks. */
export type VisualisationNode = TaintVisNode;
export type VisualisationResponse = TaintVisResponse;
