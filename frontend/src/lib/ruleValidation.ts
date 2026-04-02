/**
 * Rule builder validation logic.
 * Validates a partial PolicyRule and returns a list of field errors.
 */

import type { PolicyRule, FieldError } from "@/types/policy";

export function validateRule(rule: Partial<PolicyRule>): FieldError[] {
  const errors: FieldError[] = [];

  // Name
  if (!rule.name || rule.name.trim().length === 0) {
    errors.push({ field: "name", message: "Rule name is required." });
  } else if (rule.name.trim().length > 128) {
    errors.push({
      field: "name",
      message: "Rule name must be 128 characters or fewer.",
    });
  }

  // Agent roles
  if (!rule.agent_role || rule.agent_role.length === 0) {
    errors.push({
      field: "agent_role",
      message: "At least one agent role is required.",
    });
  }

  // Tool pattern
  if (!rule.tool_pattern || rule.tool_pattern.trim().length === 0) {
    errors.push({
      field: "tool_pattern",
      message: "Tool pattern is required.",
    });
  } else {
    // Validate regex if it looks like one (starts with ^ or contains unescaped regex chars)
    const pat = rule.tool_pattern.trim();
    if (pat.startsWith("^") || pat.includes("(") || pat.includes("|")) {
      try {
        new RegExp(pat);
      } catch {
        errors.push({
          field: "tool_pattern",
          message: "Invalid regex pattern.",
        });
      }
    }
  }

  // Risk threshold
  if (rule.risk_threshold !== undefined) {
    if (rule.risk_threshold < 0 || rule.risk_threshold > 1) {
      errors.push({
        field: "risk_threshold",
        message: "Risk threshold must be between 0 and 1.",
      });
    }
  }

  // Priority
  if (rule.priority !== undefined && rule.priority < 0) {
    errors.push({
      field: "priority",
      message: "Priority must be a non-negative integer.",
    });
  }

  // Rate limit
  if (rule.rate_limit) {
    if (!rule.rate_limit.count || rule.rate_limit.count < 1) {
      errors.push({
        field: "rate_limit",
        message: "Rate limit count must be at least 1.",
      });
    }
    if (!rule.rate_limit.window_s || rule.rate_limit.window_s < 1) {
      errors.push({
        field: "rate_limit",
        message: "Rate limit window must be at least 1 second.",
      });
    }
  }

  // Arg validators
  for (const [i, v] of (rule.arg_validators ?? []).entries()) {
    if (!v.arg_name || v.arg_name.trim().length === 0) {
      errors.push({
        field: `arg_validators[${i}].arg_name`,
        message: `Validator #${i + 1}: arg_name is required.`,
      });
    }
    if (v.regex_pattern) {
      try {
        new RegExp(v.regex_pattern);
      } catch {
        errors.push({
          field: `arg_validators[${i}].regex_pattern`,
          message: `Validator #${i + 1}: invalid regex pattern.`,
        });
      }
    }
  }

  return errors;
}
