/**
 * Unit tests for the client-side conflict detector (APEP-119).
 */

import { describe, it, expect } from "vitest";
import { detectConflictsLocal } from "@/components/policy/PolicyConflictDetector";
import type { PolicyRule } from "@/types/policy";

function makeRule(overrides: Partial<PolicyRule>): PolicyRule {
  return {
    rule_id: crypto.randomUUID(),
    name: "rule",
    agent_role: ["admin"],
    tool_pattern: "file_*",
    action: "ALLOW",
    taint_check: false,
    risk_threshold: 1.0,
    rate_limit: null,
    arg_validators: [],
    priority: 100,
    enabled: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

describe("detectConflictsLocal", () => {
  it("returns no conflicts for empty rules", () => {
    expect(detectConflictsLocal([])).toEqual([]);
  });

  it("returns no conflicts when all actions match", () => {
    const rules = [
      makeRule({ name: "a", action: "ALLOW", tool_pattern: "file_*" }),
      makeRule({ name: "b", action: "ALLOW", tool_pattern: "file_*" }),
    ];
    expect(detectConflictsLocal(rules)).toEqual([]);
  });

  it("detects conflict between ALLOW and DENY on same pattern/roles", () => {
    const rules = [
      makeRule({ name: "a", action: "ALLOW", tool_pattern: "file_*", priority: 1 }),
      makeRule({ name: "b", action: "DENY", tool_pattern: "file_*", priority: 2 }),
    ];
    const conflicts = detectConflictsLocal(rules);
    expect(conflicts).toHaveLength(1);
    expect(conflicts[0]!.overlap_type).toBe("action_conflict");
  });

  it("no conflict when roles don't overlap", () => {
    const rules = [
      makeRule({ name: "a", action: "ALLOW", agent_role: ["admin"] }),
      makeRule({ name: "b", action: "DENY", agent_role: ["reader"] }),
    ];
    expect(detectConflictsLocal(rules)).toEqual([]);
  });

  it("detects conflict when one role is wildcard", () => {
    const rules = [
      makeRule({ name: "a", action: "ALLOW", agent_role: ["*"] }),
      makeRule({ name: "b", action: "DENY", agent_role: ["reader"] }),
    ];
    expect(detectConflictsLocal(rules)).toHaveLength(1);
  });

  it("skips disabled rules", () => {
    const rules = [
      makeRule({ name: "a", action: "ALLOW", enabled: true }),
      makeRule({ name: "b", action: "DENY", enabled: false }),
    ];
    expect(detectConflictsLocal(rules)).toEqual([]);
  });

  it("detects conflicts with overlapping tool prefixes", () => {
    const rules = [
      makeRule({ name: "a", action: "ALLOW", tool_pattern: "file_read*" }),
      makeRule({ name: "b", action: "DENY", tool_pattern: "file_*" }),
    ];
    expect(detectConflictsLocal(rules)).toHaveLength(1);
  });
});
