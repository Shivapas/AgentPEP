/**
 * WebSocket hook for real-time escalation queue (APEP-143).
 */
import { useCallback, useEffect, useRef, useState } from "react";
import type {
  EscalationTicket,
  EscalationWsMessage,
} from "../types/escalation";

const WS_URL =
  (window.location.protocol === "https:" ? "wss:" : "ws:") +
  "//" +
  window.location.host +
  "/v1/escalations/ws";

export function useEscalationQueue() {
  const [tickets, setTickets] = useState<EscalationTicket[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const ws = new WebSocket(WS_URL);
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
        switch (msg.event) {
          case "escalation:snapshot":
            setTickets(msg.data as EscalationTicket[]);
            break;
          case "escalation:created":
            setTickets((prev) => [msg.data as EscalationTicket, ...prev]);
            break;
          case "escalation:resolved": {
            const resolved = msg.data as EscalationTicket;
            setTickets((prev) =>
              prev.map((t) =>
                t.escalation_id === resolved.escalation_id ? resolved : t
              )
            );
            break;
          }
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
    const res = await fetch("/v1/escalations/pending");
    if (res.ok) {
      const data = await res.json();
      setTickets(data);
    }
  }, []);

  return { tickets, connected, refresh };
}
