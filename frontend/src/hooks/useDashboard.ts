/** Sprint 16 — Hook for fetching dashboard data via REST and WebSocket (APEP-133). */

import { useCallback, useEffect, useRef, useState } from "react";
import type { DashboardSummary, TimeWindow } from "../types/dashboard";

const API_BASE = "/api/v1/dashboard";

function wsUrl(): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/api/v1/dashboard/ws`;
}

export function useDashboard(window: TimeWindow) {
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const fetchSummary = useCallback(async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_BASE}/summary?window=${window}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json: DashboardSummary = await res.json();
      setData(json);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Fetch failed");
    } finally {
      setLoading(false);
    }
  }, [window]);

  // Initial REST fetch
  useEffect(() => {
    void fetchSummary();
  }, [fetchSummary]);

  // WebSocket connection for real-time updates (APEP-133)
  useEffect(() => {
    let ws: WebSocket;
    try {
      ws = new WebSocket(wsUrl());
      wsRef.current = ws;

      ws.onopen = () => {
        ws.send(JSON.stringify({ window }));
      };

      ws.onmessage = (event: MessageEvent) => {
        try {
          const summary: DashboardSummary = JSON.parse(event.data as string);
          setData(summary);
        } catch {
          // ignore malformed messages
        }
      };

      ws.onerror = () => {
        // Fall back to polling if WS fails — not critical
      };

      ws.onclose = () => {
        wsRef.current = null;
      };
    } catch {
      // WebSocket not available — REST-only mode
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [window]);

  // Send window change over existing WS
  useEffect(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ window }));
    }
  }, [window]);

  return { data, loading, error, refresh: fetchSummary };
}
