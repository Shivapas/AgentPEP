/** Thin API client for the AgentPEP backend. */

const BASE =
  (import.meta.env.VITE_API_URL as string | undefined) ??
  `http://${window.location.hostname}:8000`;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API ${res.status}: ${body}`);
  }
  return res.json() as Promise<T>;
}

/* ---- Escalation endpoints ---- */

export function fetchPendingTickets() {
  return request<Record<string, unknown>[]>("/v1/escalations/pending");
}

export function fetchTicket(ticketId: string) {
  return request<Record<string, unknown>>(`/v1/escalations/${ticketId}`);
}

export function resolveTicket(
  ticketId: string,
  action: string,
  comment: string,
  resolvedBy = "console_user",
) {
  return request<Record<string, unknown>>(
    `/v1/escalations/${ticketId}/resolve`,
    {
      method: "POST",
      body: JSON.stringify({
        action,
        comment,
        resolved_by: resolvedBy,
      }),
    },
  );
}

export function bulkApprove(
  toolPattern: string,
  comment: string,
  resolvedBy = "console_user",
) {
  return request<{ approved_count: number; ticket_ids: string[] }>(
    "/v1/escalations/bulk-approve",
    {
      method: "POST",
      body: JSON.stringify({
        tool_pattern: toolPattern,
        comment,
        resolved_by: resolvedBy,
      }),
    },
  );
}

export function checkSla() {
  return request<{ expired_count: number; ticket_ids: string[] }>(
    "/v1/escalations/check-sla",
    { method: "POST" },
  );
}

/* ---- Taint visualisation ---- */

import type { TaintVisResponse } from "../types/taint";

export function fetchTaintVisualisation(sessionId: string) {
  return request<TaintVisResponse>(
    `/v1/taint/session/${sessionId}/visualisation`,
  );
}
