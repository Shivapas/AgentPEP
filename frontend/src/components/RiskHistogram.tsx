/** APEP-131: Risk score distribution histogram across all decisions. */

import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { HistogramBin } from "../types/dashboard";
import { formatBinLabel, riskScoreToColor } from "../lib/dashboard-transforms";

interface Props {
  data: HistogramBin[];
}

export function RiskHistogram({ data }: Props) {
  const chartData = data.map((bin) => ({
    label: formatBinLabel(bin),
    count: bin.count,
    fill: riskScoreToColor((bin.bin_start + bin.bin_end) / 2),
  }));

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
        <XAxis
          dataKey="label"
          tick={{ fontSize: 10, fill: "#94a3b8" }}
        />
        <YAxis tick={{ fontSize: 11, fill: "#94a3b8" }} allowDecimals={false} />
        <Tooltip
          contentStyle={{
            backgroundColor: "#1e293b",
            border: "1px solid #334155",
            borderRadius: "8px",
            fontSize: 12,
          }}
          formatter={(value: number) => [value, "Decisions"]}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {chartData.map((entry, i) => (
            <rect key={i} fill={entry.fill} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
