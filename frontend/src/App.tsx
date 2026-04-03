import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import { Dashboard } from "./components/Dashboard";
import { PolicyRules } from "./components/PolicyRules";
import { AuditLog } from "./components/AuditLog";
import { AgentProfiles } from "./components/AgentProfiles";
import { UXSurvey } from "./components/UXSurvey";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard" },
  { to: "/rules", label: "Rules" },
  { to: "/audit", label: "Audit" },
  { to: "/agents", label: "Agents" },
  { to: "/ux-survey", label: "UX Survey" },
] as const;

export function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-background">
        <header className="border-b border-border px-6 py-3">
          <div className="flex items-center justify-between">
            <h1 className="text-lg font-semibold text-foreground">
              AgentPEP — Policy Console
            </h1>
            <nav className="flex gap-1">
              {NAV_ITEMS.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === "/"}
                  className={({ isActive }) =>
                    `rounded-md px-3 py-1.5 text-sm transition-colors ${
                      isActive
                        ? "bg-primary text-primary-foreground"
                        : "text-muted-foreground hover:bg-muted hover:text-foreground"
                    }`
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </nav>
          </div>
        </header>
        <main className="p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/rules" element={<PolicyRules />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/agents" element={<AgentProfiles />} />
            <Route path="/ux-survey" element={<UXSurvey />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
