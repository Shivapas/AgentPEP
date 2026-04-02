import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import { Dashboard } from "./components/Dashboard";
import { PolicyAuthoringPage } from "./components/policy/PolicyAuthoringPage";

const NAV_LINKS = [
  { to: "/", label: "Dashboard" },
  { to: "/policy", label: "Policy Authoring" },
];

export function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-background">
        <header className="border-b border-border px-6 py-4 flex items-center gap-6">
          <h1 className="text-xl font-semibold text-foreground">
            AgentPEP — Policy Console
          </h1>
          <nav className="flex gap-4">
            {NAV_LINKS.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.to === "/"}
                className={({ isActive }) =>
                  `text-sm ${isActive ? "text-foreground font-medium" : "text-muted-foreground hover:text-foreground"}`
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
        </header>
        <main className="p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/policy" element={<PolicyAuthoringPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
