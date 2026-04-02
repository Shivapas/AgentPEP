/**
 * APEP-142 — E2E tests for audit search and export flows.
 *
 * Uses Playwright to test the Audit Explorer UI against a running
 * dev server with mocked API responses.
 */

import { test, expect, type Page } from "@playwright/test";

// Mock data for audit decisions
const MOCK_DECISIONS = {
  items: Array.from({ length: 5 }, (_, i) => ({
    decision_id: `dec-${i}`,
    session_id: `sess-${i < 3 ? "A" : "B"}`,
    agent_id: `agent-${i}`,
    agent_role: "worker",
    tool_name: `tool_${i}`,
    tool_args_hash: "a".repeat(64),
    taint_flags: i === 0 ? ["UNTRUSTED"] : [],
    risk_score: i * 0.2,
    delegation_chain: [],
    matched_rule_id: null,
    decision: i % 2 === 0 ? "ALLOW" : "DENY",
    escalation_id: null,
    latency_ms: 10 + i,
    timestamp: new Date(Date.now() - i * 60000).toISOString(),
  })),
  total: 5,
  page: 1,
  page_size: 25,
  total_pages: 1,
};

const MOCK_INTEGRITY = {
  status: "VERIFIED",
  total_records: 5,
  verified: 5,
  tampered: 0,
  records: [],
};

const MOCK_TIMELINE = MOCK_DECISIONS.items.filter(
  (d) => d.session_id === "sess-A",
);

async function mockAuditApi(page: Page) {
  await page.route("**/api/v1/audit/decisions*", async (route) => {
    const url = new URL(route.request().url());
    const search = url.searchParams.get("search");
    if (search) {
      const filtered = MOCK_DECISIONS.items.filter(
        (d) =>
          d.agent_id.includes(search) ||
          d.tool_name.includes(search) ||
          d.decision.includes(search) ||
          d.session_id.includes(search),
      );
      await route.fulfill({
        json: { ...MOCK_DECISIONS, items: filtered, total: filtered.length },
      });
    } else {
      await route.fulfill({ json: MOCK_DECISIONS });
    }
  });

  await page.route("**/api/v1/audit/integrity*", async (route) => {
    await route.fulfill({ json: MOCK_INTEGRITY });
  });

  await page.route("**/api/v1/audit/sessions/*/timeline", async (route) => {
    await route.fulfill({ json: MOCK_TIMELINE });
  });

  await page.route("**/api/v1/audit/export*", async (route) => {
    const url = new URL(route.request().url());
    const format = url.searchParams.get("format");
    if (format === "csv") {
      await route.fulfill({
        body: "decision_id,session_id\ndec-0,sess-A\n",
        headers: { "content-type": "text/csv" },
      });
    } else {
      await route.fulfill({ json: MOCK_DECISIONS.items });
    }
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe("Audit Explorer", () => {
  test.beforeEach(async ({ page }) => {
    await mockAuditApi(page);
    await page.goto("/audit");
  });

  test("displays paginated decision table", async ({ page }) => {
    await expect(page.getByText("Audit Explorer")).toBeVisible();
    // Table should render 5 rows
    const rows = page.locator("tbody tr");
    await expect(rows).toHaveCount(5);
  });

  test("shows decision badges with correct text", async ({ page }) => {
    await expect(page.getByText("ALLOW").first()).toBeVisible();
    await expect(page.getByText("DENY").first()).toBeVisible();
  });

  test("shows hash chain integrity indicator", async ({ page }) => {
    await expect(page.getByText("VERIFIED")).toBeVisible();
    await expect(page.getByText(/5 verified/)).toBeVisible();
  });

  test("full-text search filters results", async ({ page }) => {
    const searchInput = page.getByPlaceholder("Search decisions...");
    await searchInput.fill("agent-0");
    // Wait for filtered results
    await page.waitForTimeout(300);
    const rows = page.locator("tbody tr");
    const count = await rows.count();
    expect(count).toBeGreaterThan(0);
    // All visible rows should contain agent-0
    for (let i = 0; i < count; i++) {
      const text = await rows.nth(i).textContent();
      expect(text).toContain("agent-0");
    }
  });

  test("clicking a row opens decision detail panel", async ({ page }) => {
    // Mock the detail endpoint
    await page.route("**/api/v1/audit/decisions/dec-0", async (route) => {
      await route.fulfill({ json: MOCK_DECISIONS.items[0] });
    });

    await page.locator("tbody tr").first().click();
    await expect(page.getByText("Decision Detail")).toBeVisible();
    await expect(page.getByText("Tool Args Hash")).toBeVisible();
  });

  test("closing detail panel works", async ({ page }) => {
    await page.route("**/api/v1/audit/decisions/dec-0", async (route) => {
      await route.fulfill({ json: MOCK_DECISIONS.items[0] });
    });

    await page.locator("tbody tr").first().click();
    await expect(page.getByText("Decision Detail")).toBeVisible();
    await page.getByText("Close").click();
    await expect(page.getByText("Decision Detail")).not.toBeVisible();
  });

  test("export CSV link is present", async ({ page }) => {
    const csvLink = page.getByRole("link", { name: "CSV" });
    await expect(csvLink).toBeVisible();
    const href = await csvLink.getAttribute("href");
    expect(href).toContain("/api/v1/audit/export");
    expect(href).toContain("format=csv");
  });

  test("export JSON link is present", async ({ page }) => {
    const jsonLink = page.getByRole("link", { name: "JSON" });
    await expect(jsonLink).toBeVisible();
    const href = await jsonLink.getAttribute("href");
    expect(href).toContain("format=json");
  });

  test("column sort toggles order", async ({ page }) => {
    // Click the "Risk" header
    await page.getByText("Risk").first().click();
    // Should show sort indicator
    await expect(
      page.locator("th").filter({ hasText: /Risk/ }),
    ).toBeVisible();
  });
});

test.describe("Session Timeline", () => {
  test("displays timeline for a session", async ({ page }) => {
    await mockAuditApi(page);
    await page.goto("/audit/session/sess-A");
    await expect(page.getByText("Session Timeline")).toBeVisible();
    await expect(page.locator(".font-mono").first()).toContainText("sess-A");
  });
});
