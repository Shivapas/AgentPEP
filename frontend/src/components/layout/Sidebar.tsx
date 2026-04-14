/** Sidebar navigation (APEP-108). */

import { NavLink } from "react-router-dom";
import { useAuth } from "../../contexts/AuthContext";

const navItems = [
  { to: "/", label: "Dashboard", icon: "grid" },
  { to: "/policies", label: "Policies", icon: "shield" },
  { to: "/agents", label: "Agents", icon: "bot" },
  { to: "/plans", label: "Plans", icon: "plan" },
  { to: "/audit", label: "Audit Log", icon: "scroll" },
  { to: "/escalations", label: "Escalations", icon: "alert" },
  { to: "/risk", label: "Risk Map", icon: "chart" },
];

const iconMap: Record<string, string> = {
  grid: "⊞",
  shield: "⛨",
  bot: "⚙",
  plan: "☑",
  scroll: "☰",
  alert: "▲",
  chart: "◔",
};

export function Sidebar() {
  const { user } = useAuth();

  return (
    <aside className="flex h-full w-56 flex-col border-r border-border bg-card">
      {/* Brand */}
      <div className="border-b border-border px-4 py-4">
        <h1 className="text-lg font-bold text-foreground">AgentPEP</h1>
        <p className="text-xs text-muted-foreground">Policy Console</p>
      </div>

      {/* Nav links */}
      <nav className="flex-1 space-y-1 px-2 py-3">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === "/"}
            className={({ isActive }) =>
              `flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                isActive
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              }`
            }
          >
            <span className="w-5 text-center">{iconMap[item.icon]}</span>
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* User info at bottom */}
      {user && (
        <div className="border-t border-border px-4 py-3">
          <p className="truncate text-sm font-medium text-foreground">
            {user.username}
          </p>
          <p className="truncate text-xs text-muted-foreground">
            {user.roles.join(", ")}
          </p>
        </div>
      )}
    </aside>
  );
}
