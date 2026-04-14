/**
 * Sprint 54 (APEP-433.e) — Component tests for CIS Findings Screen.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { CISFindingsScreen } from "../components/CISFindingsScreen";
import type { CISFindingsResponse } from "../types/cis";

// Mock the API module
vi.mock("../api/cis", () => ({
  fetchCISFindings: vi.fn(),
}));

import { fetchCISFindings } from "../api/cis";

const mockFetchCISFindings = vi.mocked(fetchCISFindings);

describe("CISFindingsScreen", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders the heading", async () => {
    mockFetchCISFindings.mockResolvedValue({ findings: [], total: 0 });
    render(<CISFindingsScreen />);
    expect(screen.getByText("CIS Findings")).toBeTruthy();
  });

  it("shows empty state when no findings", async () => {
    mockFetchCISFindings.mockResolvedValue({ findings: [], total: 0 });
    render(<CISFindingsScreen />);
    await waitFor(() => {
      expect(
        screen.getByText(/No CIS findings found/),
      ).toBeTruthy();
    });
  });

  it("displays findings when data is returned", async () => {
    const mockResponse: CISFindingsResponse = {
      findings: [
        {
          finding_id: "f1",
          rule_id: "INJ-001",
          scanner: "InjectionSignatureLibrary",
          severity: "CRITICAL",
          description: "Test injection finding",
          matched_text: "ignore all previous",
          file_path: "CLAUDE.md",
          line_number: null,
          metadata: {},
        },
      ],
      total: 1,
    };
    mockFetchCISFindings.mockResolvedValue(mockResponse);
    render(<CISFindingsScreen />);
    await waitFor(() => {
      expect(screen.getByText(/INJ-001/)).toBeTruthy();
    });
  });

  it("shows severity badges", async () => {
    const mockResponse: CISFindingsResponse = {
      findings: [
        {
          finding_id: "f1",
          rule_id: "INJ-001",
          scanner: "InjectionSignatureLibrary",
          severity: "CRITICAL",
          description: "Critical finding",
          matched_text: "",
          file_path: null,
          line_number: null,
          metadata: {},
        },
        {
          finding_id: "f2",
          rule_id: "INJ-002",
          scanner: "ONNXSemanticClassifier",
          severity: "HIGH",
          description: "High finding",
          matched_text: "",
          file_path: null,
          line_number: null,
          metadata: {},
        },
      ],
      total: 2,
    };
    mockFetchCISFindings.mockResolvedValue(mockResponse);
    render(<CISFindingsScreen />);
    await waitFor(() => {
      expect(screen.getAllByText("CRITICAL").length).toBeGreaterThan(0);
      expect(screen.getAllByText("HIGH").length).toBeGreaterThan(0);
    });
  });

  it("shows error state on fetch failure", async () => {
    mockFetchCISFindings.mockRejectedValue(new Error("Network error"));
    render(<CISFindingsScreen />);
    await waitFor(() => {
      expect(screen.getByText(/Error: Network error/)).toBeTruthy();
    });
  });

  it("has a refresh button", async () => {
    mockFetchCISFindings.mockResolvedValue({ findings: [], total: 0 });
    render(<CISFindingsScreen />);
    expect(screen.getByText("Refresh")).toBeTruthy();
  });

  it("has filter controls", async () => {
    mockFetchCISFindings.mockResolvedValue({ findings: [], total: 0 });
    render(<CISFindingsScreen />);
    await waitFor(() => {
      expect(screen.getByText("All severities")).toBeTruthy();
      expect(screen.getByText("All scanners")).toBeTruthy();
      expect(screen.getByPlaceholderText("Session ID...")).toBeTruthy();
    });
  });
});
