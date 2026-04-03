import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import { Dashboard } from "./components/Dashboard";
import { SimulationBuilder } from "./components/SimulationBuilder";
import { SimulationCompare } from "./components/SimulationCompare";

export function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-background">
        <header className="border-b border-border px-6 py-4">
          <div className="flex items-center gap-8">
            <h1 className="text-xl font-semibold text-foreground">
              AgentPEP — Policy Console
            </h1>
            <nav className="flex gap-4 text-sm">
              <NavLink
                to="/"
                end
                className={({ isActive }) =>
                  isActive
                    ? "font-medium text-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }
              >
                Dashboard
              </NavLink>
              <NavLink
                to="/simulate"
                className={({ isActive }) =>
                  isActive
                    ? "font-medium text-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }
              >
                Simulate
              </NavLink>
              <NavLink
                to="/simulate/compare"
                className={({ isActive }) =>
                  isActive
                    ? "font-medium text-foreground"
                    : "text-muted-foreground hover:text-foreground"
                }
              >
                Compare
              </NavLink>
            </nav>
          </div>
        </header>
        <main className="p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/simulate" element={<SimulationBuilder />} />
            <Route path="/simulate/compare" element={<SimulationCompare />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
