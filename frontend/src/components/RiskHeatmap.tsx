/** APEP-128: Real-time risk heatmap — agent × tool matrix coloured by avg risk score. */

import type { HeatmapCell } from "../types/dashboard";
import { buildHeatmapGrid, riskScoreToColor } from "../lib/dashboard-transforms";

interface Props {
  data: HeatmapCell[];
}

export function RiskHeatmap({ data }: Props) {
  if (data.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center text-muted-foreground">
        No decision data available for this time window.
      </div>
    );
  }

  const grid = buildHeatmapGrid(data);

  return (
    <div className="overflow-auto">
      <table className="w-full border-collapse text-xs">
        <thead>
          <tr>
            <th className="sticky left-0 z-10 bg-card px-2 py-1 text-left text-muted-foreground">
              Agent \ Tool
            </th>
            {grid.tools.map((tool) => (
              <th
                key={tool}
                className="max-w-[100px] truncate px-2 py-1 text-center text-muted-foreground"
                title={tool}
              >
                {tool}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {grid.agents.map((agent, ai) => (
            <tr key={agent}>
              <td
                className="sticky left-0 z-10 max-w-[120px] truncate bg-card px-2 py-1 font-medium"
                title={agent}
              >
                {agent}
              </td>
              {grid.tools.map((tool, ti) => {
                const score = grid.matrix[ai]![ti]!;
                const count = grid.counts[ai]![ti];
                return (
                  <td
                    key={tool}
                    className="px-1 py-1 text-center"
                    title={
                      score !== null
                        ? `Risk: ${score.toFixed(3)} (${count} decisions)`
                        : "No data"
                    }
                  >
                    <div
                      className="mx-auto h-6 w-10 rounded"
                      style={{ backgroundColor: riskScoreToColor(score) }}
                    >
                      {score !== null && (
                        <span className="flex h-full items-center justify-center text-[10px] font-bold text-white">
                          {score.toFixed(2)}
                        </span>
                      )}
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
        <span>Low risk</span>
        <div className="flex gap-0.5">
          {[0.1, 0.3, 0.5, 0.7, 0.9].map((s) => (
            <div
              key={s}
              className="h-3 w-6 rounded-sm"
              style={{ backgroundColor: riskScoreToColor(s) }}
            />
          ))}
        </div>
        <span>High risk</span>
      </div>
    </div>
  );
}
