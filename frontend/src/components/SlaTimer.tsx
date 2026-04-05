/**
 * SLA countdown timer — shows time remaining before auto-decision (APEP-147).
 */
import { useEffect, useState } from "react";

interface SlaTimerProps {
  deadline: string | null;
  autoDecision: string;
}

function formatRemaining(ms: number): string {
  if (ms <= 0) return "Expired";
  const totalSec = Math.floor(ms / 1000);
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${m}m ${s.toString().padStart(2, "0")}s`;
}

export function SlaTimer({ deadline, autoDecision }: SlaTimerProps) {
  const [remaining, setRemaining] = useState<number | null>(null);

  useEffect(() => {
    if (!deadline) {
      setRemaining(null);
      return;
    }
    const target = new Date(deadline).getTime();

    const tick = () => {
      setRemaining(target - Date.now());
    };
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [deadline]);

  if (remaining === null) {
    return <span className="text-xs text-muted-foreground">No SLA</span>;
  }

  const expired = remaining <= 0;
  const urgent = remaining > 0 && remaining < 60_000;

  return (
    <span
      className={
        expired
          ? "text-xs font-semibold text-red-600"
          : urgent
            ? "text-xs font-semibold text-amber-500"
            : "text-xs text-muted-foreground"
      }
    >
      {expired
        ? `Expired (auto: ${autoDecision})`
        : formatRemaining(remaining)}
    </span>
  );
}
