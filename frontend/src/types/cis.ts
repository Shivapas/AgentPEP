/** TypeScript types for Sprint 54 — CIS Findings Screen. */

export type CISScanVerdict = "CLEAN" | "SUSPICIOUS" | "MALICIOUS";

export type CISSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type InstructionFileType =
  | "CLAUDE.md"
  | ".cursorrules"
  | "AGENTS.md"
  | ".github/copilot-instructions.md"
  | "UNKNOWN";

export type PostToolScanTrigger =
  | "file_read"
  | "file_write"
  | "command_output"
  | "mcp_response"
  | "web_fetch"
  | "tool_output";

export interface CISFinding {
  finding_id: string;
  rule_id: string;
  scanner: string;
  severity: CISSeverity;
  description: string;
  matched_text: string;
  file_path: string | null;
  line_number: number | null;
  metadata: Record<string, unknown>;
  timestamp?: string;
  session_id?: string;
}

export interface RepoScanResult {
  scan_id: string;
  repo_path: string;
  allowed: boolean;
  verdict: CISScanVerdict;
  total_files_scanned: number;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  instruction_files_found: number;
  file_results: RepoScanFileResult[];
  taint_assigned: string | null;
  scan_mode: string;
  latency_ms: number;
  started_at: string;
  completed_at: string | null;
}

export interface RepoScanFileResult {
  file_path: string;
  scan_mode_applied: string;
  allowed: boolean;
  findings: CISFinding[];
  is_instruction_file: boolean;
  instruction_file_type: InstructionFileType | null;
  cache_hit: boolean;
  latency_ms: number;
}

export interface FileScanResult {
  scan_id: string;
  file_path: string;
  allowed: boolean;
  verdict: CISScanVerdict;
  findings: CISFinding[];
  scan_mode_applied: string;
  is_instruction_file: boolean;
  instruction_file_type: InstructionFileType | null;
  taint_assigned: string | null;
  cache_hit: boolean;
  latency_ms: number;
}

export interface PostToolScanResult {
  scan_id: string;
  session_id: string;
  tool_name: string;
  trigger: PostToolScanTrigger;
  allowed: boolean;
  verdict: CISScanVerdict;
  findings: CISFinding[];
  scan_mode_applied: string;
  taint_assigned: string | null;
  escalated: boolean;
  latency_ms: number;
}

export interface CISFindingsResponse {
  findings: CISFinding[];
  total: number;
}
