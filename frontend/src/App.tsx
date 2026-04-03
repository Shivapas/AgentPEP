import { BrowserRouter, NavLink, Routes, Route } from "react-router-dom";
import { Dashboard } from "./components/Dashboard";
import { EscalationQueue } from "./components/EscalationQueue";
import { TaintMap } from "./components/TaintMap";

function navCls({ isActive }: { isActive: boolean }) {
  return isActive
    ? "text-sm font-medium text-foreground underline underline-offset-4"
    : "text-sm text-muted-foreground hover:text-foreground";
}

export function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-background">
        <header className="border-b border-border px-6 py-4">
          <div className="flex items-center justify-between">
            <h1 className="text-xl font-semibold text-foreground">
              AgentPEP — Policy Console
            </h1>
            <nav className="flex gap-4">
              <NavLink to="/" end className={navCls}>
                Dashboard
              </NavLink>
              <NavLink to="/escalations" className={navCls}>
                Escalations
              </NavLink>
              <NavLink to="/taint-map" className={navCls}>
                Taint Map
              </NavLink>
            </nav>
          </div>
        </header>
        <main className="p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/escalations" element={<EscalationQueue />} />
            <Route path="/taint-map" element={<TaintMap />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
