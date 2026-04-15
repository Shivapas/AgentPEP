/**
 * Sprint 56 (APEP-447.c) — Component tests for CIS Dashboard Widget.
 *
 * Tests cover:
 *   - Renders loading state
 *   - Renders dashboard with data
 *   - Displays YOLO alert banner when active
 *   - Shows severity breakdown
 *   - Handles API error gracefully
 *   - Refresh button triggers reload
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// Mock the API module
vi.mock("../lib/api", () => ({
  apiFetch: vi.fn(),
}));

import { apiFetch } from "../lib/api";
import { CISDashboardWidget } from "../components/CISDashboardWidget";

const mockApiFetch = apiFetch as ReturnType<typeof vi.fn>;

const DASHBOARD_DATA = {
  summary: {
    total_findings: 15,
    critical: 2,
    high: 5,
    medium: 6,
    low: 1,
    info: 1,
  },
  yolo_sessions: {
    active_count: 1,
    sessions: [
      {
        session_id: "sess-yolo-1",
        risk_multiplier: 1.5,
        signals: ["YOLO_MODE env var detected"],
        detected_at: "2026-04-15T10:00:00Z",
      },
    ],
  },
  scan_mode_distribution: {
    STRICT: 10,
    STANDARD: 20,
    LENIENT: 5,
  },
  scanner_breakdown: {
    InjectionSignatureLibrary: 8,
    ONNXSemanticClassifier: 7,
  },
  recent_findings: [
    {
      finding_id: "f-1",
      severity: "CRITICAL" as const,
      scanner: "InjectionSignatureLibrary",
      rule_id: "INJ-001",
      description: "Prompt override detected",
      timestamp: "2026-04-15T10:00:00Z",
    },
    {
      finding_id: "f-2",
      severity: "HIGH" as const,
      scanner: "ONNXSemanticClassifier",
      rule_id: "ONNX-SEMANTIC",
      description: "Semantic injection detected",
      timestamp: "2026-04-15T10:01:00Z",
    },
  ],
};

function setupFetchMock(data: unknown = DASHBOARD_DATA, ok = true) {
  mockApiFetch.mockResolvedValue({
    ok,
    status: ok ? 200 : 500,
    json: () => Promise.resolve(data),
  });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("CISDashboardWidget", () => {
  it("renders loading state initially", () => {
    mockApiFetch.mockReturnValue(new Promise(() => {})); // Never resolves
    render(<CISDashboardWidget />);
    expect(screen.getByText(/Loading CIS dashboard/)).toBeTruthy();
  });

  it("renders dashboard with data", async () => {
    setupFetchMock();
    render(<CISDashboardWidget />);

    await waitFor(() => {
      expect(screen.getByText("CIS Dashboard")).toBeTruthy();
    });

    // Check stat cards
    expect(screen.getByText("15")).toBeTruthy(); // total findings
    expect(screen.getByText("2")).toBeTruthy(); // critical
    expect(screen.getByText("5")).toBeTruthy(); // high

    // Check scan mode distribution section exists
    expect(screen.getByText("Scan Mode Distribution")).toBeTruthy();

    // Check recent findings
    expect(screen.getByText(/INJ-001/)).toBeTruthy();
    expect(screen.getByText(/ONNX-SEMANTIC/)).toBeTruthy();
  });

  it("displays YOLO alert banner when sessions active", async () => {
    setupFetchMock();
    render(<CISDashboardWidget />);

    await waitFor(() => {
      expect(screen.getByText("YOLO Mode Active")).toBeTruthy();
    });

    expect(
      screen.getByText(/1 session running in YOLO mode/)
    ).toBeTruthy();
  });

  it("hides YOLO banner when no active sessions", async () => {
    const noYoloData = {
      ...DASHBOARD_DATA,
      yolo_sessions: { active_count: 0, sessions: [] },
    };
    setupFetchMock(noYoloData);
    render(<CISDashboardWidget />);

    await waitFor(() => {
      expect(screen.getByText("CIS Dashboard")).toBeTruthy();
    });

    expect(screen.queryByText("YOLO Mode Active")).toBeNull();
  });

  it("shows severity breakdown", async () => {
    setupFetchMock();
    render(<CISDashboardWidget />);

    await waitFor(() => {
      expect(screen.getByText("Total Findings")).toBeTruthy();
    });

    expect(screen.getByText("Critical")).toBeTruthy();
    expect(screen.getByText("High")).toBeTruthy();
    expect(screen.getByText("Medium")).toBeTruthy();
  });

  it("handles API error gracefully", async () => {
    setupFetchMock(null, false);
    render(<CISDashboardWidget />);

    await waitFor(() => {
      expect(screen.getByText(/Error/)).toBeTruthy();
    });
  });

  it("calls API on mount", async () => {
    setupFetchMock();
    render(<CISDashboardWidget />);

    await waitFor(() => {
      expect(mockApiFetch).toHaveBeenCalledWith("/v1/sprint56/cis-dashboard");
    });
  });

  it("refresh button triggers reload", async () => {
    setupFetchMock();
    const user = userEvent.setup();

    render(<CISDashboardWidget />);

    await waitFor(() => {
      expect(screen.getByText("CIS Dashboard")).toBeTruthy();
    });

    const refreshBtn = screen.getByText("Refresh");
    await user.click(refreshBtn);

    expect(mockApiFetch).toHaveBeenCalledTimes(2);
  });

  it("displays scanner breakdown", async () => {
    setupFetchMock();
    render(<CISDashboardWidget />);

    await waitFor(() => {
      expect(screen.getByText("Findings by Scanner")).toBeTruthy();
    });

    expect(screen.getByText("Tier 0 (Regex)")).toBeTruthy();
    expect(screen.getByText("Tier 1 (ONNX)")).toBeTruthy();
  });
});
