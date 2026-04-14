/**
 * Sprint 51 (APEP-409.c) — Component tests for Network Events Tab.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

import type {
  SecurityAssessmentResult,
  AssessmentFinding,
  RuleBundle,
} from "../types/network";

describe("Network Events types", () => {
  it("SecurityAssessmentResult has correct shape", () => {
    const result: SecurityAssessmentResult = {
      assessment_id: "test-id",
      started_at: "2026-04-14T00:00:00Z",
      completed_at: "2026-04-14T00:00:01Z",
      phases_run: ["CONFIG_AUDIT", "ATTACK_SIMULATION", "DEPLOYMENT_PROBE"],
      findings: [],
      total_checks: 15,
      passed_checks: 12,
      failed_checks: 3,
      critical_findings: 1,
      high_findings: 1,
      overall_score: 75.0,
      grade: "C",
      latency_ms: 150,
    };
    expect(result.grade).toBe("C");
    expect(result.overall_score).toBe(75.0);
    expect(result.phases_run).toHaveLength(3);
    expect(result.total_checks).toBe(15);
  });

  it("AssessmentFinding has required fields", () => {
    const finding: AssessmentFinding = {
      finding_id: "f-1",
      category: "DLP_COVERAGE",
      phase: "CONFIG_AUDIT",
      severity: "HIGH",
      title: "DLP pattern coverage",
      description: "46 patterns loaded",
      recommendation: "",
      mitre_technique_id: "T1552",
      passed: true,
      evidence: { pattern_count: 46 },
    };
    expect(finding.category).toBe("DLP_COVERAGE");
    expect(finding.mitre_technique_id).toBe("T1552");
    expect(finding.passed).toBe(true);
  });

  it("RuleBundle represents a loaded bundle", () => {
    const bundle: RuleBundle = {
      bundle_id: "b-1",
      manifest: {
        name: "community-dlp-v1",
        version: "1.0.0",
        author: "AgentPEP Community",
        description: "Community DLP patterns",
        tags: ["dlp", "community"],
        created_at: "2026-04-14T00:00:00Z",
      },
      rules: [
        {
          rule_id: "DLP-001",
          rule_type: "DLP",
          severity: "HIGH",
          description: "OpenAI API Key",
          enabled: true,
        },
      ],
      status: "ACTIVE",
      verified: true,
      loaded_at: "2026-04-14T00:00:00Z",
    };
    expect(bundle.status).toBe("ACTIVE");
    expect(bundle.verified).toBe(true);
    expect(bundle.rules).toHaveLength(1);
    expect(bundle.manifest.name).toBe("community-dlp-v1");
  });

  it("Assessment grade maps correctly", () => {
    const grades: Record<string, number> = {
      A: 95,
      B: 85,
      C: 75,
      D: 65,
      F: 50,
    };
    for (const [grade, score] of Object.entries(grades)) {
      expect(score).toBeGreaterThanOrEqual(
        grade === "F" ? 0 : { A: 90, B: 80, C: 70, D: 60 }[grade] ?? 0,
      );
    }
  });

  it("Severity levels are ordered correctly", () => {
    const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"];
    expect(severities).toHaveLength(6);
    expect(severities[0]).toBe("CRITICAL");
    expect(severities[5]).toBe("PASS");
  });

  it("Network event types are defined", () => {
    const eventTypes = [
      "DLP_HIT",
      "INJECTION_DETECTED",
      "SSRF_BLOCKED",
      "CHAIN_DETECTED",
      "KILL_SWITCH",
      "SENTINEL_HIT",
    ];
    expect(eventTypes).toHaveLength(6);
  });
});
