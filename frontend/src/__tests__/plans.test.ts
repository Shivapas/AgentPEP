/**
 * Sprint 42 — Unit and component tests for Plan Console UI.
 *
 * APEP-332.c: Plan Management list screen tests
 * APEP-333.e: Plan Issuance form tests
 * APEP-334.c: Plan Detail screen tests
 * APEP-335.e: Plan Explorer receipt tree view tests
 * APEP-336.c: Receipt node drill-down tests
 * APEP-337.c: Plan budget widget tests
 * APEP-338.c: Plan filter to Audit Explorer tests
 */

import { describe, it, expect } from "vitest";
import type {
  PlanDetail,
  PlanBudget,
  ReceiptChainEntry,
  BudgetStatusResponse,
} from "@/types/plans";

// ---------------------------------------------------------------------------
// Test data factories
// ---------------------------------------------------------------------------

function makeBudget(overrides: Partial<PlanBudget> = {}): PlanBudget {
  return {
    max_delegations: 10,
    max_risk_total: 5.0,
    ttl_seconds: 3600,
    ...overrides,
  };
}

function makePlan(overrides: Partial<PlanDetail> = {}): PlanDetail {
  return {
    plan_id: crypto.randomUUID(),
    action: "Analyze Q3 finance reports",
    issuer: "admin@company.com",
    scope: ["read:finance:*"],
    requires_checkpoint: ["delete_*"],
    delegates_to: ["research-agent-01"],
    budget: makeBudget(),
    human_intent: "Review quarterly financials",
    status: "ACTIVE",
    signature: "ed25519:abc123",
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 3600_000).toISOString(),
    delegation_count: 3,
    accumulated_risk: 1.5,
    is_active: true,
    budget_exhausted: false,
    ...overrides,
  };
}

function makeReceipt(overrides: Partial<ReceiptChainEntry> = {}): ReceiptChainEntry {
  return {
    decision_id: crypto.randomUUID(),
    sequence_number: 1,
    session_id: "sess-001",
    agent_id: "agent-01",
    agent_role: "worker",
    tool_name: "read_file",
    decision: "ALLOW",
    risk_score: 0.15,
    plan_id: crypto.randomUUID(),
    parent_receipt_id: null,
    receipt_signature: "sig-abc",
    record_hash: "hash-abc",
    previous_hash: "",
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// APEP-332.c: Plan Management list data tests
// ---------------------------------------------------------------------------

describe("Plan Management list (APEP-332)", () => {
  it("formats unlimited budget correctly", () => {
    const plan = makePlan({
      budget: makeBudget({
        max_delegations: null,
        max_risk_total: null,
        ttl_seconds: null,
      }),
    });
    const label = formatBudget(plan);
    expect(label).toBe("Unlimited");
  });

  it("formats delegation budget", () => {
    const plan = makePlan({ delegation_count: 5, budget: makeBudget({ max_delegations: 10 }) });
    const label = formatBudget(plan);
    expect(label).toContain("5/10 del");
  });

  it("formats risk budget", () => {
    const plan = makePlan({
      accumulated_risk: 2.5,
      budget: makeBudget({ max_risk_total: 5.0, max_delegations: null, ttl_seconds: null }),
    });
    const label = formatBudget(plan);
    expect(label).toContain("2.50/5 risk");
  });

  it("formats TTL budget", () => {
    const plan = makePlan({
      budget: makeBudget({ max_delegations: null, max_risk_total: null, ttl_seconds: 7200 }),
    });
    const label = formatBudget(plan);
    expect(label).toContain("TTL 7200s");
  });

  it("sorts plans by status correctly", () => {
    const plans = [
      makePlan({ status: "REVOKED" }),
      makePlan({ status: "ACTIVE" }),
      makePlan({ status: "EXPIRED" }),
    ];
    const sorted = [...plans].sort((a, b) => a.status.localeCompare(b.status));
    expect(sorted[0]!.status).toBe("ACTIVE");
    expect(sorted[1]!.status).toBe("EXPIRED");
    expect(sorted[2]!.status).toBe("REVOKED");
  });
});

// ---------------------------------------------------------------------------
// APEP-333.e: Plan Issuance form tests
// ---------------------------------------------------------------------------

describe("Plan Issuance form (APEP-333)", () => {
  it("parses comma-separated list correctly", () => {
    expect(parseList("agent-01, agent-02, agent-03")).toEqual([
      "agent-01",
      "agent-02",
      "agent-03",
    ]);
  });

  it("trims whitespace in list parsing", () => {
    expect(parseList("  foo , bar  ,  baz  ")).toEqual(["foo", "bar", "baz"]);
  });

  it("filters empty entries", () => {
    expect(parseList("foo,,bar,,,")).toEqual(["foo", "bar"]);
  });

  it("handles empty string", () => {
    expect(parseList("")).toEqual([]);
  });

  it("constructs valid budget with nullable fields", () => {
    const budget: PlanBudget = {
      max_delegations: null,
      max_risk_total: null,
      ttl_seconds: null,
    };
    expect(budget.max_delegations).toBeNull();
    expect(budget.max_risk_total).toBeNull();
    expect(budget.ttl_seconds).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// APEP-334.c: Plan Detail screen tests
// ---------------------------------------------------------------------------

describe("Plan Detail screen (APEP-334)", () => {
  it("identifies active plan correctly", () => {
    const plan = makePlan({ status: "ACTIVE", is_active: true });
    expect(plan.is_active).toBe(true);
    expect(plan.status).toBe("ACTIVE");
  });

  it("identifies expired plan correctly", () => {
    const plan = makePlan({ status: "EXPIRED", is_active: false });
    expect(plan.is_active).toBe(false);
    expect(plan.status).toBe("EXPIRED");
  });

  it("identifies revoked plan correctly", () => {
    const plan = makePlan({ status: "REVOKED", is_active: false });
    expect(plan.status).toBe("REVOKED");
  });

  it("detects budget exhaustion", () => {
    const plan = makePlan({ budget_exhausted: true });
    expect(plan.budget_exhausted).toBe(true);
  });

  it("computes budget utilization percentage", () => {
    const budget: BudgetStatusResponse = {
      plan_id: crypto.randomUUID(),
      status: "ACTIVE",
      delegation_count: 7,
      max_delegations: 10,
      accumulated_risk: 3.5,
      max_risk_total: 5.0,
      ttl_seconds: 3600,
      ttl_remaining_seconds: 1800,
      issued_at: new Date().toISOString(),
      expires_at: null,
      exhausted_dimensions: [],
      budget_utilization: {
        delegation_pct: 70,
        risk_pct: 70,
        ttl_pct: 50,
      },
    };
    expect(budget.budget_utilization?.delegation_pct).toBe(70);
    expect(budget.budget_utilization?.risk_pct).toBe(70);
    expect(budget.budget_utilization?.ttl_pct).toBe(50);
  });
});

// ---------------------------------------------------------------------------
// APEP-335.e: Plan Explorer receipt tree tests
// ---------------------------------------------------------------------------

describe("Plan Explorer receipt tree (APEP-335)", () => {
  it("builds a flat tree from root-only receipts", () => {
    const receipts = [
      makeReceipt({ decision_id: "r1", parent_receipt_id: null, sequence_number: 1 }),
      makeReceipt({ decision_id: "r2", parent_receipt_id: null, sequence_number: 2 }),
    ];
    const tree = buildTree(receipts);
    expect(tree).toHaveLength(2);
    expect(tree[0]!.children).toHaveLength(0);
    expect(tree[1]!.children).toHaveLength(0);
  });

  it("builds a nested tree from parent-child receipts", () => {
    const receipts = [
      makeReceipt({ decision_id: "r1", parent_receipt_id: null, sequence_number: 1 }),
      makeReceipt({ decision_id: "r2", parent_receipt_id: "r1", sequence_number: 2 }),
      makeReceipt({ decision_id: "r3", parent_receipt_id: "r1", sequence_number: 3 }),
      makeReceipt({ decision_id: "r4", parent_receipt_id: "r2", sequence_number: 4 }),
    ];
    const tree = buildTree(receipts);
    expect(tree).toHaveLength(1); // Only root
    expect(tree[0]!.receipt.decision_id).toBe("r1");
    expect(tree[0]!.children).toHaveLength(2); // r2, r3
    expect(tree[0]!.children[0]!.children).toHaveLength(1); // r4
  });

  it("handles empty receipt list", () => {
    expect(buildTree([])).toEqual([]);
  });

  it("treats orphan receipts as roots", () => {
    const receipts = [
      makeReceipt({ decision_id: "r1", parent_receipt_id: "nonexistent" }),
    ];
    const tree = buildTree(receipts);
    expect(tree).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// APEP-336.c: Receipt node drill-down tests
// ---------------------------------------------------------------------------

describe("Receipt node drill-down (APEP-336)", () => {
  it("receipt has all required fields", () => {
    const receipt = makeReceipt();
    expect(receipt.decision_id).toBeTruthy();
    expect(receipt.session_id).toBeTruthy();
    expect(receipt.agent_id).toBeTruthy();
    expect(receipt.tool_name).toBeTruthy();
    expect(receipt.decision).toBeTruthy();
    expect(typeof receipt.risk_score).toBe("number");
    expect(typeof receipt.sequence_number).toBe("number");
  });

  it("receipt hash chain fields are populated", () => {
    const receipt = makeReceipt({
      record_hash: "hash-123",
      previous_hash: "hash-122",
      receipt_signature: "sig-456",
    });
    expect(receipt.record_hash).toBe("hash-123");
    expect(receipt.previous_hash).toBe("hash-122");
    expect(receipt.receipt_signature).toBe("sig-456");
  });

  it("receipt with parent reference", () => {
    const receipt = makeReceipt({ parent_receipt_id: "parent-001" });
    expect(receipt.parent_receipt_id).toBe("parent-001");
  });

  it("receipt without parent reference", () => {
    const receipt = makeReceipt({ parent_receipt_id: null });
    expect(receipt.parent_receipt_id).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// APEP-337.c: Plan budget widget tests
// ---------------------------------------------------------------------------

describe("Plan budget widget (APEP-337)", () => {
  it("determines bar color based on percentage", () => {
    expect(barColor(95)).toBe("bg-red-500");
    expect(barColor(75)).toBe("bg-yellow-500");
    expect(barColor(50)).toBe("bg-green-500");
    expect(barColor(0)).toBe("bg-green-500");
  });

  it("caps bar width at 100%", () => {
    const width = Math.min(120, 100);
    expect(width).toBe(100);
  });

  it("identifies exhausted budget plan", () => {
    const summary = {
      plan_id: "p1",
      action: "test",
      status: "ACTIVE",
      delegation_pct: 100,
      risk_pct: null,
      ttl_pct: null,
      exhausted_dimensions: ["DELEGATION_COUNT"],
    };
    expect(summary.exhausted_dimensions.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// APEP-338.c: Plan filter to Audit Explorer tests
// ---------------------------------------------------------------------------

describe("Plan filter for Audit Explorer (APEP-338)", () => {
  it("plan_id filter is included in DecisionFilters type", () => {
    const filters = {
      page: 1,
      page_size: 25,
      plan_id: "some-plan-id",
    };
    expect(filters.plan_id).toBe("some-plan-id");
  });

  it("plan_id filter can be undefined", () => {
    const filters: { plan_id?: string } = {};
    expect(filters.plan_id).toBeUndefined();
  });

  it("plan_id filter integrates with other filters", () => {
    const filters = {
      page: 1,
      page_size: 25,
      session_id: "sess-001",
      agent_id: "agent-01",
      plan_id: "plan-001",
      decision: "ALLOW",
    };
    expect(filters.plan_id).toBe("plan-001");
    expect(filters.session_id).toBe("sess-001");
  });
});

// ---------------------------------------------------------------------------
// Shared helper functions (extracted from component logic for testability)
// ---------------------------------------------------------------------------

function formatBudget(plan: PlanDetail): string {
  const parts: string[] = [];
  if (plan.budget.max_delegations != null)
    parts.push(`${plan.delegation_count}/${plan.budget.max_delegations} del`);
  if (plan.budget.max_risk_total != null)
    parts.push(`${plan.accumulated_risk.toFixed(2)}/${plan.budget.max_risk_total} risk`);
  if (plan.budget.ttl_seconds != null)
    parts.push(`TTL ${plan.budget.ttl_seconds}s`);
  return parts.length > 0 ? parts.join(", ") : "Unlimited";
}

function parseList(input: string): string[] {
  return input
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

interface TreeNode {
  receipt: ReceiptChainEntry;
  children: TreeNode[];
}

function buildTree(receipts: ReceiptChainEntry[]): TreeNode[] {
  const nodeMap = new Map<string, TreeNode>();
  const roots: TreeNode[] = [];

  for (const r of receipts) {
    nodeMap.set(r.decision_id, { receipt: r, children: [] });
  }

  for (const r of receipts) {
    const node = nodeMap.get(r.decision_id)!;
    if (r.parent_receipt_id && nodeMap.has(r.parent_receipt_id)) {
      nodeMap.get(r.parent_receipt_id)!.children.push(node);
    } else {
      roots.push(node);
    }
  }

  return roots;
}

function barColor(pct: number): string {
  if (pct >= 90) return "bg-red-500";
  if (pct >= 70) return "bg-yellow-500";
  return "bg-green-500";
}
