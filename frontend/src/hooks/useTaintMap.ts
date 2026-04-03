/**
 * Hook to fetch taint visualization data for a session (APEP-148).
 */
import { useCallback, useState } from "react";
import type { VisualisationResponse } from "../types/taint";

export function useTaintMap() {
  const [data, setData] = useState<VisualisationResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchGraph = useCallback(async (sessionId: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `/v1/taint/session/${encodeURIComponent(sessionId)}/visualisation`
      );
      if (!res.ok) {
        throw new Error(`Failed to load taint graph: ${res.status}`);
      }
      const json: VisualisationResponse = await res.json();
      setData(json);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  return { data, loading, error, fetchGraph };
}
