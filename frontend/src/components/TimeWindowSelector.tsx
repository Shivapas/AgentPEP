/** APEP-132: Time window selector — 1h / 6h / 24h / 7d / 30d. */

import { TIME_WINDOWS, type TimeWindow } from "../types/dashboard";

interface Props {
  value: TimeWindow;
  onChange: (w: TimeWindow) => void;
}

export function TimeWindowSelector({ value, onChange }: Props) {
  return (
    <div className="flex gap-1 rounded-lg border border-border bg-muted p-1">
      {TIME_WINDOWS.map((tw) => (
        <button
          key={tw.value}
          onClick={() => onChange(tw.value)}
          className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            value === tw.value
              ? "bg-primary text-primary-foreground shadow-sm"
              : "text-muted-foreground hover:text-foreground"
          }`}
        >
          {tw.value}
        </button>
      ))}
    </div>
  );
}
