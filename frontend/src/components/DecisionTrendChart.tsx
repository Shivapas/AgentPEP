/** APEP-129: Decision trend chart — ALLOW/DENY/ESCALATE rates over time (Recharts). */

import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { TrendBucket } from "../types/dashboard";
import { computeTrendTotals, formatTrendTimestamp } from "../lib/dashboard-transforms";

interface Props {
  data: TrendBucket[];
}

const COLORS = {
  allow: "#22c55e",
  deny: "#ef4444",
  escalate: "#f59e0b",
};

export function DecisionTrendChart({ data }: Props) {
  const totals = computeTrendTotals(data);
  const chartData = data.map((b) => ({
    ...b,
    time: formatTrendTimestamp(b.timestamp),
  }));

  return (
    <div>
      <div className="mb-3 flex gap-4 text-xs">
        <span className="text-green-500">Allow: {totals.totalAllow}</span>
        <span className="text-red-500">Deny: {totals.totalDeny}</span>
        <span className="text-amber-500">Escalate: {totals.totalEscalate}</span>
      </div>
      <ResponsiveContainer width="100%" height={250}>
        <AreaChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis
            dataKey="time"
            tick={{ fontSize: 11, fill: "#94a3b8" }}
            interval="preserveStartEnd"
          />
          <YAxis tick={{ fontSize: 11, fill: "#94a3b8" }} allowDecimals={false} />
          <Tooltip
            contentStyle={{
              backgroundColor: "#1e293b",
              border: "1px solid #334155",
              borderRadius: "8px",
              fontSize: 12,
            }}
          />
          <Legend wrapperStyle={{ fontSize: 12 }} />
          <Area
            type="monotone"
            dataKey="allow"
            stackId="1"
            stroke={COLORS.allow}
            fill={COLORS.allow}
            fillOpacity={0.4}
          />
          <Area
            type="monotone"
            dataKey="deny"
            stackId="1"
            stroke={COLORS.deny}
            fill={COLORS.deny}
            fillOpacity={0.4}
          />
          <Area
            type="monotone"
            dataKey="escalate"
            stackId="1"
            stroke={COLORS.escalate}
            fill={COLORS.escalate}
            fillOpacity={0.4}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
