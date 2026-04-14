/**
 * APEP-340.e / APEP-343.c -- Component tests for scope simulator and pattern library UI.
 *
 * Tests component rendering, state management, and user interactions.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

// Mock the API module
vi.mock("@/api/scope", () => ({
  simulateScopeBatch: vi.fn(),
  listPatterns: vi.fn(),
  getPatternCategories: vi.fn(),
}));

import { simulateScopeBatch, listPatterns, getPatternCategories } from "@/api/scope";
import { ScopeSimulator } from "@/components/scope/ScopeSimulator";
import { PatternLibrary } from "@/components/scope/PatternLibrary";

// Mock react-router-dom if needed
vi.mock("react-router-dom", () => ({
  useParams: () => ({}),
  useNavigate: () => vi.fn(),
}));

describe("ScopeSimulator", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the simulator form", () => {
    render(<ScopeSimulator />);
    expect(screen.getByText("Scope Simulator")).toBeDefined();
    expect(screen.getByText("Run Simulation")).toBeDefined();
  });

  it("shows error when scope patterns are empty", async () => {
    render(<ScopeSimulator />);

    // Clear the default scope input
    const scopeTextarea = screen.getAllByRole("textbox")[0];
    fireEvent.change(scopeTextarea, { target: { value: "" } });

    fireEvent.click(screen.getByText("Run Simulation"));

    await waitFor(() => {
      expect(screen.getByText(/At least one scope pattern is required/)).toBeDefined();
    });
  });

  it("calls API and displays results on simulation", async () => {
    const mockResponse = {
      results: [
        {
          tool_name: "file.read.public.report",
          action: "",
          scope_allowed: true,
          scope_matched_pattern: "read:public:*",
          scope_reason: "Tool is within scope",
          checkpoint_triggered: false,
          checkpoint_matched_pattern: null,
          checkpoint_reason: "No checkpoint match",
          effective_decision: "ALLOW",
          compiled_rbac_patterns: ["file.read.public.*"],
        },
      ],
      summary: { total: 1, allowed: 1, denied: 0, escalated: 0 },
    };

    (simulateScopeBatch as ReturnType<typeof vi.fn>).mockResolvedValueOnce(mockResponse);

    render(<ScopeSimulator />);
    fireEvent.click(screen.getByText("Run Simulation"));

    await waitFor(() => {
      expect(screen.getByText("ALLOW")).toBeDefined();
      expect(screen.getByText("file.read.public.report")).toBeDefined();
    });
  });

  it("displays error message on API failure", async () => {
    (simulateScopeBatch as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("500: Internal Server Error"),
    );

    render(<ScopeSimulator />);
    fireEvent.click(screen.getByText("Run Simulation"));

    await waitFor(() => {
      expect(screen.getByText(/500: Internal Server Error/)).toBeDefined();
    });
  });
});

describe("PatternLibrary", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the pattern library with loading state", () => {
    (listPatterns as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));
    (getPatternCategories as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));

    render(<PatternLibrary />);
    expect(screen.getByText("Pattern Library")).toBeDefined();
    expect(screen.getByText(/Loading patterns/)).toBeDefined();
  });

  it("displays templates after loading", async () => {
    const mockTemplates = {
      templates: [
        {
          template_id: "abc-123",
          name: "Read-Only Public Data",
          description: "Allow read access to all public resources.",
          category: "data_access",
          risk_level: "low",
          scope_patterns: ["read:public:*"],
          checkpoint_patterns: [],
          tags: ["read-only", "public"],
          use_cases: ["Reporting bots"],
          author: "agentpep",
          version: "1.0",
          enabled: true,
          created_at: "2026-01-01T00:00:00Z",
          updated_at: "2026-01-01T00:00:00Z",
        },
      ],
      total: 1,
      offset: 0,
      limit: 50,
    };

    const mockCategories = [{ category: "data_access", count: 1 }];

    (listPatterns as ReturnType<typeof vi.fn>).mockResolvedValueOnce(mockTemplates);
    (getPatternCategories as ReturnType<typeof vi.fn>).mockResolvedValueOnce(mockCategories);

    render(<PatternLibrary />);

    await waitFor(() => {
      expect(screen.getByText("Read-Only Public Data")).toBeDefined();
      expect(screen.getByText("low")).toBeDefined();
    });
  });

  it("shows error on API failure", async () => {
    (listPatterns as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("Network error"),
    );
    (getPatternCategories as ReturnType<typeof vi.fn>).mockRejectedValueOnce(
      new Error("Network error"),
    );

    render(<PatternLibrary />);

    await waitFor(() => {
      expect(screen.getByText(/Network error/)).toBeDefined();
    });
  });
});
