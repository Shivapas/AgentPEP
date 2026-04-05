import { useCallback, useEffect, useRef, useState } from "react";
import type {
  EscalationTicket,
  EscalationWsMessage,
} from "../types/escalation";

const WS_URL =
  (import.meta.env.VITE_API_WS_URL as string | undefined) ??
  `ws://${window.location.hostname}:8000/v1/escalations/ws`;

/**
 * Hook that maintains a WebSocket connection to the escalation feed.
 * Returns the live list of pending tickets and connection status.
 */
export function useEscalationWs() {
  const [tickets, setTickets] = useState<EscalationTicket[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

    ws.onmessage = (event: MessageEvent) => {
      const msg: EscalationWsMessage = JSON.parse(event.data as string);
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
    };

    ws.onclose = () => {
      setConnected(false);
      reconnectTimer.current = setTimeout(connect, 3000);
    };

    ws.onerror = () => ws.close();
  }, []);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { tickets, connected };
}
