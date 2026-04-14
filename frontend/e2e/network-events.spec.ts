/**
 * Sprint 51 (APEP-409.d) — E2E tests for TFN Network Events Tab.
 */

import { test, expect } from "@playwright/test";

test.describe("Network Events Tab", () => {
  test.beforeEach(async ({ page }) => {
    // Login first
    await page.goto("/");
    // Fill login form if redirected
    const loginForm = page.locator("form");
    if (await loginForm.isVisible({ timeout: 2000 }).catch(() => false)) {
      await page.fill('input[name="username"]', "admin");
      await page.fill('input[name="password"]', "admin");
      await page.click('button[type="submit"]');
      await page.waitForURL("**/");
    }
  });

  test("navigates to Network Events tab", async ({ page }) => {
    await page.click('a[href="/network-events"]');
    await expect(page).toHaveURL(/network-events/);
    await expect(page.locator("h2")).toContainText("Network Events");
  });

  test("displays security assessment summary", async ({ page }) => {
    await page.goto("/network-events");
    // Wait for assessment to load
    await expect(
      page.locator("text=Security Assessment"),
    ).toBeVisible({ timeout: 10000 });
    // Grade should be visible
    await expect(
      page.locator("text=/[ABCDF]/"),
    ).toBeVisible();
  });

  test("displays assessment findings table", async ({ page }) => {
    await page.goto("/network-events");
    await expect(
      page.locator("text=Assessment Findings"),
    ).toBeVisible({ timeout: 10000 });
    // Table header should be visible
    await expect(page.locator("th:text('Category')")).toBeVisible();
    await expect(page.locator("th:text('Severity')")).toBeVisible();
  });

  test("toggle show passed checkbox filters findings", async ({ page }) => {
    await page.goto("/network-events");
    await expect(
      page.locator("text=Assessment Findings"),
    ).toBeVisible({ timeout: 10000 });

    // Get initial count
    const initialRows = await page.locator("tbody tr").count();

    // Uncheck show passed
    await page.click('input[type="checkbox"]');
    await page.waitForTimeout(500);

    // Count should be less or equal
    const filteredRows = await page.locator("tbody tr").count();
    expect(filteredRows).toBeLessThanOrEqual(initialRows);
  });

  test("displays MITRE ATT&CK coverage card", async ({ page }) => {
    await page.goto("/network-events");
    await expect(
      page.locator("text=MITRE ATT&CK Coverage"),
    ).toBeVisible({ timeout: 10000 });
    await expect(page.locator("text=Techniques")).toBeVisible();
  });

  test("displays Rule Bundles card", async ({ page }) => {
    await page.goto("/network-events");
    await expect(
      page.locator("text=Rule Bundles"),
    ).toBeVisible({ timeout: 10000 });
  });

  test("refresh button reloads data", async ({ page }) => {
    await page.goto("/network-events");
    await expect(
      page.locator("text=Security Assessment"),
    ).toBeVisible({ timeout: 10000 });
    await page.click("button:text('Refresh')");
    // Assessment should still be visible after refresh
    await expect(
      page.locator("text=Security Assessment"),
    ).toBeVisible({ timeout: 10000 });
  });
});
