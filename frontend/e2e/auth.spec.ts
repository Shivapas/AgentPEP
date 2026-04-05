/**
 * Playwright E2E tests for authentication flow (APEP-112).
 *
 * These tests verify:
 * - Login page renders when unauthenticated
 * - Successful login redirects to dashboard
 * - Invalid credentials show error
 * - Logout returns to login page
 * - Protected routes redirect to login
 * - Theme toggle works
 */

import { test, expect } from "@playwright/test";

const BASE_URL = "http://localhost:5173";

test.describe("Authentication Flow", () => {
  test.beforeEach(async ({ page }) => {
    // Clear localStorage to ensure logged-out state
    await page.goto(BASE_URL);
    await page.evaluate(() => localStorage.clear());
    await page.goto(BASE_URL);
  });

  test("shows login page when not authenticated", async ({ page }) => {
    await expect(page.getByRole("heading", { name: "AgentPEP" })).toBeVisible();
    await expect(page.getByText("Policy Console")).toBeVisible();
    await expect(page.getByLabel("Username")).toBeVisible();
    await expect(page.getByLabel("Password")).toBeVisible();
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  });

  test("shows error on invalid credentials", async ({ page }) => {
    await page.getByLabel("Username").fill("baduser");
    await page.getByLabel("Password").fill("badpass");
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(page.getByText(/invalid|failed/i)).toBeVisible();
  });

  test("successful login shows dashboard", async ({ page }) => {
    // Seed admin user first
    await page.request.post(`${BASE_URL}/api/v1/console/seed`);

    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("admin");
    await page.getByRole("button", { name: "Sign in" }).click();

    // Should see dashboard after login
    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible({
      timeout: 10_000,
    });
    // Sidebar should be visible
    await expect(page.getByText("Policies")).toBeVisible();
    await expect(page.getByText("Agents")).toBeVisible();
  });

  test("logout returns to login page", async ({ page }) => {
    // Login first
    await page.request.post(`${BASE_URL}/api/v1/console/seed`);
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("admin");
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible({
      timeout: 10_000,
    });

    // Open user menu and click sign out
    await page.getByText("admin").last().click();
    await page.getByText("Sign out").click();

    // Should return to login
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  });

  test("protected route redirects to login when not authenticated", async ({
    page,
  }) => {
    await page.goto(`${BASE_URL}/policies`);
    // Should show login page, not the policies page
    await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
  });
});

test.describe("Theme Toggle", () => {
  test("toggles between light and dark mode", async ({ page }) => {
    // Login first
    await page.goto(BASE_URL);
    await page.evaluate(() => localStorage.clear());
    await page.goto(BASE_URL);
    await page.request.post(`${BASE_URL}/api/v1/console/seed`);
    await page.getByLabel("Username").fill("admin");
    await page.getByLabel("Password").fill("admin");
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible({
      timeout: 10_000,
    });

    // Click theme toggle
    const toggle = page.getByRole("button", { name: "Toggle theme" });
    await toggle.click();

    // Check that dark class is toggled on <html>
    const hasDark = await page.evaluate(() =>
      document.documentElement.classList.contains("dark"),
    );
    // Toggle again
    await toggle.click();
    const hasDarkAfter = await page.evaluate(() =>
      document.documentElement.classList.contains("dark"),
    );

    // States should differ
    expect(hasDark).not.toBe(hasDarkAfter);
  });
});
