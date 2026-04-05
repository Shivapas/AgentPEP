/**
 * WebSocket hook for real-time escalation queue (APEP-143).
 */
import { useCallback, useEffect, useRef, useState } from "react";
import type {
  EscalationTicket,
  EscalationWsMessage,
} from "../types/escalation";

const BASE =
  (import.meta.env.VITE_API_URL as string | undefined) ??
  `http://${window.location.hostname}:8000`;

function wsUrl(): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = BASE.replace(/^https?:\/\//, "");
  return `${proto}//${host}/v1/escalations/ws`;
}

export function useEscalationQueue() {
  const [tickets, setTickets] = useState<EscalationTicket[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const ws = new WebSocket(wsUrl());
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);
    ws.onclose = () => {
      setConnected(false);
      // Reconnect after 3s
      setTimeout(() => {
        wsRef.current = null;
      }, 3000);
    };

    ws.onmessage = (event) => {
      try {
        const msg: EscalationWsMessage = JSON.parse(event.data);
        switch (msg.type) {
          case "snapshot":
            setTickets(msg.tickets ?? []);
            break;
          case "ticket_created":
            if (msg.ticket) {
              setTickets((prev) => [msg.ticket!, ...prev]);
            }
            break;
          case "ticket_resolved":
          case "sla_expired":
            if (msg.ticket_id) {
              setTickets((prev) =>
                prev.filter((t) => t.ticket_id !== msg.ticket_id),
              );
            }
            break;
          case "bulk_approved":
            if (msg.ticket_ids) {
              const ids = new Set(msg.ticket_ids);
              setTickets((prev) => prev.filter((t) => !ids.has(t.ticket_id)));
            }
            break;
        }
      } catch {
        // ignore malformed messages
      }
    };

    return () => {
      ws.close();
    };
  }, []);

  const refresh = useCallback(async () => {
    const res = await fetch(`${BASE}/v1/escalations/pending`);
    if (res.ok) {
      const data = await res.json();
      setTickets(data);
    }
  }, []);

  return { tickets, connected, refresh };
}
