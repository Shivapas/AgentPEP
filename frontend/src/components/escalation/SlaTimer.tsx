import { useEffect, useState } from "react";

/** Displays a countdown timer until the SLA deadline (APEP-147). */
export function SlaTimer({ deadline }: { deadline: string }) {
  const [remaining, setRemaining] = useState(() => calcRemaining(deadline));

  useEffect(() => {
    const id = setInterval(() => setRemaining(calcRemaining(deadline)), 1000);
    return () => clearInterval(id);
  }, [deadline]);

  const expired = remaining <= 0;
  const mins = Math.floor(Math.abs(remaining) / 60);
  const secs = Math.abs(remaining) % 60;
  const display = `${mins}:${secs.toString().padStart(2, "0")}`;

  return (
    <span
      className={
        expired
          ? "font-mono text-sm text-destructive"
          : remaining < 60
            ? "font-mono text-sm text-yellow-500"
            : "font-mono text-sm text-muted-foreground"
      }
    >
      {expired ? `−${display} (expired)` : display}
    </span>
  );
}

function calcRemaining(deadline: string): number {
  return Math.round(
    (new Date(deadline).getTime() - Date.now()) / 1000,
  );
}
