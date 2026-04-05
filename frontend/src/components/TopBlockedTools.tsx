/** APEP-130: Top blocked tools table — ranked by DENY count with drill-down. */

import { useState } from "react";
import type { BlockedTool } from "../types/dashboard";

interface Props {
  data: BlockedTool[];
}

export function TopBlockedTools({ data }: Props) {
  const [expanded, setExpanded] = useState<string | null>(null);

  if (data.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center text-muted-foreground">
        No blocked tools in this time window.
      </div>
    );
  }

  return (
    <div className="overflow-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border text-left text-xs text-muted-foreground">
            <th className="px-3 py-2">Tool</th>
            <th className="px-3 py-2 text-right">Denied</th>
            <th className="px-3 py-2 text-right">Escalated</th>
            <th className="px-3 py-2 text-right">Total</th>
          </tr>
        </thead>
        <tbody>
          {data.map((tool) => (
            <>
              <tr
                key={tool.tool_name}
                className="cursor-pointer border-b border-border/50 transition-colors hover:bg-muted/50"
                onClick={() =>
                  setExpanded(
                    expanded === tool.tool_name ? null : tool.tool_name,
                  )
                }
              >
                <td className="px-3 py-2 font-medium">
                  <span className="mr-1 text-xs text-muted-foreground">
                    {expanded === tool.tool_name ? "▼" : "▶"}
                  </span>
                  {tool.tool_name}
                </td>
                <td className="px-3 py-2 text-right font-mono text-red-500">
                  {tool.deny_count}
                </td>
                <td className="px-3 py-2 text-right font-mono text-amber-500">
                  {tool.escalate_count}
                </td>
                <td className="px-3 py-2 text-right font-mono">
                  {tool.deny_count + tool.escalate_count}
                </td>
              </tr>
              {expanded === tool.tool_name && (
                <tr key={`${tool.tool_name}-detail`}>
                  <td colSpan={4} className="bg-muted/30 px-6 py-2">
                    <p className="text-xs text-muted-foreground">
                      Top agents triggering blocks:
                    </p>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {tool.top_agents.map((agent) => (
                        <span
                          key={agent}
                          className="rounded-full bg-muted px-2 py-0.5 text-xs"
                        >
                          {agent}
                        </span>
                      ))}
                      {tool.top_agents.length === 0 && (
                        <span className="text-xs text-muted-foreground">
                          No agent details available
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              )}
            </>
          ))}
        </tbody>
      </table>
    </div>
  );
}
