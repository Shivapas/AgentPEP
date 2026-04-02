import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import { Dashboard } from "./components/Dashboard";
import { RiskDashboard } from "./components/RiskDashboard";

export function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-background">
        <header className="border-b border-border px-6 py-4">
          <div className="flex items-center justify-between">
            <h1 className="text-xl font-semibold text-foreground">
              AgentPEP — Policy Console
            </h1>
            <nav className="flex gap-4 text-sm">
              <NavLink
                to="/"
                end
                className={({ isActive }) =>
                  isActive
                    ? "font-medium text-primary"
                    : "text-muted-foreground hover:text-foreground"
                }
              >
                Overview
              </NavLink>
              <NavLink
                to="/risk"
                className={({ isActive }) =>
                  isActive
                    ? "font-medium text-primary"
                    : "text-muted-foreground hover:text-foreground"
                }
              >
                Risk Dashboard
              </NavLink>
            </nav>
          </div>
        </header>
        <main className="p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/risk" element={<RiskDashboard />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
