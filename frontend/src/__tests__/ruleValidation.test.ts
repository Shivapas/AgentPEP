/**
 * APEP-120: Unit tests for rule builder validation logic.
 */

import { describe, it, expect } from "vitest";
import { validateRule } from "@/lib/ruleValidation";
import type { PolicyRule } from "@/types/policy";

function validRule(overrides: Partial<PolicyRule> = {}): Partial<PolicyRule> {
  return {
    name: "Test Rule",
    agent_role: ["admin"],
    tool_pattern: "file_*",
    action: "DENY",
    taint_check: false,
    risk_threshold: 0.8,
    rate_limit: null,
    arg_validators: [],
    priority: 100,
    enabled: true,
    ...overrides,
  };
}

describe("validateRule", () => {
  it("returns no errors for a valid rule", () => {
    expect(validateRule(validRule())).toEqual([]);
  });

  // --- name ---
  it("requires a name", () => {
    const errors = validateRule(validRule({ name: "" }));
    expect(errors).toContainEqual(
      expect.objectContaining({ field: "name" }),
    );
  });

  it("rejects names longer than 128 characters", () => {
    const errors = validateRule(validRule({ name: "x".repeat(129) }));
    expect(errors).toContainEqual(
      expect.objectContaining({ field: "name", message: expect.stringContaining("128") }),
    );
  });

  // --- agent_role ---
  it("requires at least one agent role", () => {
    const errors = validateRule(validRule({ agent_role: [] }));
    expect(errors).toContainEqual(
      expect.objectContaining({ field: "agent_role" }),
    );
  });

  // --- tool_pattern ---
  it("requires a tool pattern", () => {
    const errors = validateRule(validRule({ tool_pattern: "" }));
    expect(errors).toContainEqual(
      expect.objectContaining({ field: "tool_pattern" }),
    );
  });

  it("validates regex patterns", () => {
    const errors = validateRule(validRule({ tool_pattern: "^(invalid[" }));
    expect(errors).toContainEqual(
      expect.objectContaining({
        field: "tool_pattern",
        message: expect.stringContaining("regex"),
      }),
    );
  });

  it("accepts valid regex patterns", () => {
    const errors = validateRule(
      validRule({ tool_pattern: "^file_(read|write)$" }),
    );
    expect(errors).toEqual([]);
  });

  // --- risk_threshold ---
  it("rejects risk threshold below 0", () => {
    const errors = validateRule(validRule({ risk_threshold: -0.1 }));
    expect(errors).toContainEqual(
      expect.objectContaining({ field: "risk_threshold" }),
    );
  });

  it("rejects risk threshold above 1", () => {
    const errors = validateRule(validRule({ risk_threshold: 1.5 }));
    expect(errors).toContainEqual(
      expect.objectContaining({ field: "risk_threshold" }),
    );
  });

  // --- priority ---
  it("rejects negative priority", () => {
    const errors = validateRule(validRule({ priority: -1 }));
    expect(errors).toContainEqual(
      expect.objectContaining({ field: "priority" }),
    );
  });

  it("allows zero priority", () => {
    const errors = validateRule(validRule({ priority: 0 }));
    expect(errors).toEqual([]);
  });

  // --- rate_limit ---
  it("validates rate limit count", () => {
    const errors = validateRule(
      validRule({ rate_limit: { count: 0, window_s: 60 } }),
    );
    expect(errors).toContainEqual(
      expect.objectContaining({
        field: "rate_limit",
        message: expect.stringContaining("count"),
      }),
    );
  });

  it("validates rate limit window", () => {
    const errors = validateRule(
      validRule({ rate_limit: { count: 10, window_s: 0 } }),
    );
    expect(errors).toContainEqual(
      expect.objectContaining({
        field: "rate_limit",
        message: expect.stringContaining("window"),
      }),
    );
  });

  it("accepts valid rate limit", () => {
    const errors = validateRule(
      validRule({ rate_limit: { count: 5, window_s: 30 } }),
    );
    expect(errors).toEqual([]);
  });

  // --- arg_validators ---
  it("requires arg_name in validators", () => {
    const errors = validateRule(
      validRule({
        arg_validators: [{ arg_name: "", regex_pattern: null }],
      }),
    );
    expect(errors).toContainEqual(
      expect.objectContaining({
        field: "arg_validators[0].arg_name",
      }),
    );
  });

  it("validates regex in arg validators", () => {
    const errors = validateRule(
      validRule({
        arg_validators: [{ arg_name: "path", regex_pattern: "^(broken[" }],
      }),
    );
    expect(errors).toContainEqual(
      expect.objectContaining({
        field: "arg_validators[0].regex_pattern",
      }),
    );
  });

  it("accepts valid arg validators", () => {
    const errors = validateRule(
      validRule({
        arg_validators: [
          { arg_name: "path", regex_pattern: "^/tmp/.*$" },
          { arg_name: "mode", allowlist: ["read", "write"] },
        ],
      }),
    );
    expect(errors).toEqual([]);
  });

  // --- multiple errors ---
  it("returns multiple errors at once", () => {
    const errors = validateRule({
      name: "",
      agent_role: [],
      tool_pattern: "",
      risk_threshold: 5,
      priority: -1,
    });
    expect(errors.length).toBeGreaterThanOrEqual(4);
  });
});
