/**
 * APEP-339 — E2E tests for Plan Console UI.
 *
 * Uses Playwright to test Plan Management, Plan Issuance, Plan Detail,
 * and Plan Explorer screens against mocked API responses.
 */

import { test, expect, type Page } from "@playwright/test";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const MOCK_PLAN = {
  plan_id: "550e8400-e29b-41d4-a716-446655440000",
  action: "Analyze Q3 finance reports",
  issuer: "admin@company.com",
  scope: ["read:finance:*"],
  requires_checkpoint: ["delete_*"],
  delegates_to: ["research-agent-01"],
  budget: { max_delegations: 10, max_risk_total: 5.0, ttl_seconds: 3600 },
  human_intent: "Review quarterly financials",
  status: "ACTIVE",
  signature: "ed25519:abcdef1234567890",
  issued_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 3600_000).toISOString(),
  delegation_count: 3,
  accumulated_risk: 1.5,
  is_active: true,
  budget_exhausted: false,
};

const MOCK_EXPIRED_PLAN = {
  ...MOCK_PLAN,
  plan_id: "550e8400-e29b-41d4-a716-446655440001",
  action: "Old expired plan",
  status: "EXPIRED",
  is_active: false,
};

const MOCK_PLANS_LIST = {
  plans: [MOCK_PLAN, MOCK_EXPIRED_PLAN],
  total: 2,
  offset: 0,
  limit: 50,
};

const MOCK_BUDGET_STATUS = {
  plan_id: MOCK_PLAN.plan_id,
  status: "ACTIVE",
  delegation_count: 3,
  max_delegations: 10,
  accumulated_risk: 1.5,
  max_risk_total: 5.0,
  ttl_seconds: 3600,
  ttl_remaining_seconds: 1800,
  issued_at: MOCK_PLAN.issued_at,
  expires_at: MOCK_PLAN.expires_at,
  exhausted_dimensions: [],
  budget_utilization: {
    delegation_pct: 30,
    risk_pct: 30,
    ttl_pct: 50,
  },
};

const MOCK_RECEIPTS = {
  plan_id: MOCK_PLAN.plan_id,
  total_receipts: 3,
  chain_valid: true,
  receipts: [
    {
      decision_id: "dec-001",
      sequence_number: 1,
      session_id: "sess-A",
      agent_id: "agent-01",
      agent_role: "worker",
      tool_name: "read_file",
      decision: "ALLOW",
      risk_score: 0.15,
      plan_id: MOCK_PLAN.plan_id,
      parent_receipt_id: null,
      receipt_signature: "sig-001",
      record_hash: "hash-001",
      previous_hash: "",
      timestamp: new Date(Date.now() - 300_000).toISOString(),
    },
    {
      decision_id: "dec-002",
      sequence_number: 2,
      session_id: "sess-A",
      agent_id: "agent-02",
      agent_role: "analyst",
      tool_name: "search_web",
      decision: "ALLOW",
      risk_score: 0.35,
      plan_id: MOCK_PLAN.plan_id,
      parent_receipt_id: "dec-001",
      receipt_signature: "sig-002",
      record_hash: "hash-002",
      previous_hash: "hash-001",
      timestamp: new Date(Date.now() - 200_000).toISOString(),
    },
    {
      decision_id: "dec-003",
      sequence_number: 3,
      session_id: "sess-A",
      agent_id: "agent-01",
      agent_role: "worker",
      tool_name: "delete_report",
      decision: "ESCALATE",
      risk_score: 0.8,
      plan_id: MOCK_PLAN.plan_id,
      parent_receipt_id: "dec-001",
      receipt_signature: "sig-003",
      record_hash: "hash-003",
      previous_hash: "hash-002",
      timestamp: new Date(Date.now() - 100_000).toISOString(),
    },
  ],
};

const MOCK_RECEIPTS_SUMMARY = {
  plan_id: MOCK_PLAN.plan_id,
  total_receipts: 3,
  first_timestamp: MOCK_RECEIPTS.receipts[0].timestamp,
  last_timestamp: MOCK_RECEIPTS.receipts[2].timestamp,
  decision_counts: { ALLOW: 2, ESCALATE: 1 },
  unique_agents: ["agent-01", "agent-02"],
  unique_tools: ["delete_report", "read_file", "search_web"],
  total_risk: 1.3,
  chain_valid: true,
  chain_depth: 2,
};

// ---------------------------------------------------------------------------
// Mock API setup
// ---------------------------------------------------------------------------

async function mockPlanApi(page: Page) {
  // List plans
  await page.route("**/v1/plans?**", async (route) => {
    const url = new URL(route.request().url());
    const status = url.searchParams.get("status");
    if (status) {
      const filtered = MOCK_PLANS_LIST.plans.filter((p) => p.status === status);
      await route.fulfill({
        json: { ...MOCK_PLANS_LIST, plans: filtered, total: filtered.length },
      });
    } else {
      await route.fulfill({ json: MOCK_PLANS_LIST });
    }
  });

  // Get plan detail
  await page.route(`**/v1/plans/${MOCK_PLAN.plan_id}`, async (route) => {
    if (route.request().method() === "DELETE") {
      await route.fulfill({
        json: { plan_id: MOCK_PLAN.plan_id, status: "REVOKED", revoked_at: new Date().toISOString() },
      });
    } else {
      await route.fulfill({ json: MOCK_PLAN });
    }
  });

  // Create plan
  await page.route("**/v1/plans", async (route) => {
    if (route.request().method() === "POST") {
      await route.fulfill({ json: MOCK_PLAN, status: 201 });
    } else {
      await route.fulfill({ json: MOCK_PLANS_LIST });
    }
  });

  // Budget status
  await page.route(`**/v1/plans/${MOCK_PLAN.plan_id}/budget`, async (route) => {
    await route.fulfill({ json: MOCK_BUDGET_STATUS });
  });

  // Receipts
  await page.route(`**/v1/plans/${MOCK_PLAN.plan_id}/receipts/summary`, async (route) => {
    await route.fulfill({ json: MOCK_RECEIPTS_SUMMARY });
  });

  await page.route(`**/v1/plans/${MOCK_PLAN.plan_id}/receipts`, async (route) => {
    await route.fulfill({ json: MOCK_RECEIPTS });
  });
}

// ---------------------------------------------------------------------------
// Plan Management List (APEP-332)
// ---------------------------------------------------------------------------

test.describe("Plan Management List (APEP-332)", () => {
  test.beforeEach(async ({ page }) => {
    await mockPlanApi(page);
    await page.goto("/plans");
  });

  test("displays plan management heading and table", async ({ page }) => {
    await expect(page.getByText("Plan Management")).toBeVisible();
    const rows = page.locator("tbody tr");
    await expect(rows).toHaveCount(2);
  });

  test("shows plan action and issuer in table", async ({ page }) => {
    await expect(page.getByText("Analyze Q3 finance reports")).toBeVisible();
    await expect(page.getByText("admin@company.com")).toBeVisible();
  });

  test("shows status badges", async ({ page }) => {
    await expect(page.getByText("ACTIVE").first()).toBeVisible();
    await expect(page.getByText("EXPIRED").first()).toBeVisible();
  });

  test("issue plan button navigates to form", async ({ page }) => {
    await page.getByText("+ Issue Plan").click();
    await expect(page).toHaveURL(/\/plans\/new/);
  });

  test("view button navigates to detail", async ({ page }) => {
    await page.getByText("View").first().click();
    await expect(page).toHaveURL(new RegExp(`/plans/${MOCK_PLAN.plan_id}`));
  });

  test("status filter dropdown is present", async ({ page }) => {
    const select = page.locator("select");
    await expect(select).toBeVisible();
    await expect(select.locator("option")).toHaveCount(4); // All, ACTIVE, EXPIRED, REVOKED
  });

  test("shows total count", async ({ page }) => {
    await expect(page.getByText("2 plan(s) total")).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Plan Issuance Form (APEP-333)
// ---------------------------------------------------------------------------

test.describe("Plan Issuance Form (APEP-333)", () => {
  test.beforeEach(async ({ page }) => {
    await mockPlanApi(page);
    await page.goto("/plans/new");
  });

  test("displays form heading", async ({ page }) => {
    await expect(page.getByText("Issue New Plan")).toBeVisible();
  });

  test("has required form fields", async ({ page }) => {
    await expect(page.getByPlaceholder("e.g. Analyze Q3 finance reports")).toBeVisible();
    await expect(page.getByPlaceholder("e.g. admin@company.com")).toBeVisible();
  });

  test("has budget constraint fields", async ({ page }) => {
    await expect(page.getByText("Budget Constraints")).toBeVisible();
    await expect(page.getByText("Max Delegations")).toBeVisible();
    await expect(page.getByText("Max Risk Total")).toBeVisible();
    await expect(page.getByText("TTL (seconds)")).toBeVisible();
  });

  test("cancel button navigates back to list", async ({ page }) => {
    await page.getByText("Cancel").click();
    await expect(page).toHaveURL(/\/plans$/);
  });

  test("submitting form shows success message", async ({ page }) => {
    await page.getByPlaceholder("e.g. Analyze Q3 finance reports").fill("Test plan");
    await page.getByPlaceholder("e.g. admin@company.com").fill("test@test.com");
    await page.getByText("Issue Plan").click();
    await expect(page.getByText("Plan issued successfully")).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Plan Detail Screen (APEP-334)
// ---------------------------------------------------------------------------

test.describe("Plan Detail Screen (APEP-334)", () => {
  test.beforeEach(async ({ page }) => {
    await mockPlanApi(page);
    await page.goto(`/plans/${MOCK_PLAN.plan_id}`);
  });

  test("displays plan action as heading", async ({ page }) => {
    await expect(page.getByText("Analyze Q3 finance reports")).toBeVisible();
  });

  test("shows plan ID", async ({ page }) => {
    await expect(page.getByText(MOCK_PLAN.plan_id)).toBeVisible();
  });

  test("shows summary cards", async ({ page }) => {
    await expect(page.getByText("Issuer")).toBeVisible();
    await expect(page.getByText("Delegations")).toBeVisible();
    await expect(page.getByText("Risk Accumulated")).toBeVisible();
  });

  test("has tab navigation", async ({ page }) => {
    await expect(page.getByText("Budget")).toBeVisible();
    await expect(page.getByText("Receipts")).toBeVisible();
    await expect(page.getByText("Scope & Config")).toBeVisible();
  });

  test("Explorer button navigates to explorer", async ({ page }) => {
    await page.getByText("Explorer").click();
    await expect(page).toHaveURL(new RegExp(`/plans/${MOCK_PLAN.plan_id}/explorer`));
  });
});

// ---------------------------------------------------------------------------
// Plan Explorer (APEP-335)
// ---------------------------------------------------------------------------

test.describe("Plan Explorer (APEP-335)", () => {
  test.beforeEach(async ({ page }) => {
    await mockPlanApi(page);
    await page.goto(`/plans/${MOCK_PLAN.plan_id}/explorer`);
  });

  test("displays explorer heading", async ({ page }) => {
    await expect(page.getByText("Plan Explorer")).toBeVisible();
  });

  test("shows receipt count", async ({ page }) => {
    await expect(page.getByText("3 receipts")).toBeVisible();
  });

  test("shows chain validity", async ({ page }) => {
    await expect(page.getByText("Chain Valid")).toBeVisible();
  });

  test("shows receipt tree nodes with tool names", async ({ page }) => {
    await expect(page.getByText("read_file")).toBeVisible();
    await expect(page.getByText("search_web")).toBeVisible();
    await expect(page.getByText("delete_report")).toBeVisible();
  });

  test("shows decision badges in tree", async ({ page }) => {
    await expect(page.getByText("ALLOW").first()).toBeVisible();
    await expect(page.getByText("ESCALATE")).toBeVisible();
  });

  test("clicking a receipt node shows detail panel", async ({ page }) => {
    await page.getByText("read_file").click();
    await expect(page.getByText("Receipt Detail")).toBeVisible();
    await expect(page.getByText("Hash Chain")).toBeVisible();
  });

  test("close button hides detail panel", async ({ page }) => {
    await page.getByText("read_file").click();
    await expect(page.getByText("Receipt Detail")).toBeVisible();
    await page.getByText("Close").click();
    await expect(page.getByText("Receipt Detail")).not.toBeVisible();
  });
});
