/** Breadcrumbs from current route (APEP-108). */

import { Link, useLocation } from "react-router-dom";

const labelMap: Record<string, string> = {
  "": "Dashboard",
  policies: "Policies",
  agents: "Agents",
  audit: "Audit Log",
  escalations: "Escalations",
  risk: "Risk Map",
  settings: "Settings",
};

export function Breadcrumbs() {
  const { pathname } = useLocation();
  const segments = pathname.split("/").filter(Boolean);

  return (
    <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-sm">
      <Link
        to="/"
        className="text-muted-foreground hover:text-foreground"
      >
        Home
      </Link>
      {segments.map((seg, i) => {
        const path = "/" + segments.slice(0, i + 1).join("/");
        const label = labelMap[seg] || seg;
        const isLast = i === segments.length - 1;
        return (
          <span key={path} className="flex items-center gap-1">
            <span className="text-muted-foreground">/</span>
            {isLast ? (
              <span className="font-medium text-foreground">{label}</span>
            ) : (
              <Link
                to={path}
                className="text-muted-foreground hover:text-foreground"
              >
                {label}
              </Link>
            )}
          </span>
        );
      })}
    </nav>
  );
}
