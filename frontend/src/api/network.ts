/** API client for Sprint 51 — TFN Network Events & Security Assessment. */

import { apiFetch } from "../lib/api";
import type { SecurityAssessmentResult, RuleBundle } from "../types/network";

export async function fetchSecurityAssessment(
  includePassed = true,
): Promise<SecurityAssessmentResult> {
  const res = await apiFetch(
    `/v1/network/assess?include_passed=${includePassed}`,
  );
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<SecurityAssessmentResult>;
}

export async function fetchRuleBundles(): Promise<{
  bundles: RuleBundle[];
  total: number;
}> {
  const res = await apiFetch("/v1/network/bundles");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<{ bundles: RuleBundle[]; total: number }>;
}

export async function fetchMitreStats(): Promise<{
  techniques: number;
  event_type_mappings: number;
  rule_id_mappings: number;
}> {
  const res = await apiFetch("/v1/network/mitre/stats");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<{
    techniques: number;
    event_type_mappings: number;
    rule_id_mappings: number;
  }>;
}
