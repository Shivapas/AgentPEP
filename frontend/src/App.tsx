import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import { Dashboard } from "./components/Dashboard";
import { EscalationQueue } from "./components/escalation/EscalationQueue";
import { TaintMapGraph } from "./components/taint/TaintMapGraph";

function NavItem({ to, label }: { to: string; label: string }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `text-sm px-3 py-1 rounded ${
          isActive
            ? "bg-primary text-primary-foreground"
            : "text-muted-foreground hover:text-foreground"
        }`
      }
    >
      {label}
    </NavLink>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-background">
        <header className="border-b border-border px-6 py-4 flex items-center gap-6">
          <h1 className="text-xl font-semibold text-foreground">
            AgentPEP — Policy Console
          </h1>
          <nav className="flex gap-2">
            <NavItem to="/" label="Dashboard" />
            <NavItem to="/escalations" label="Escalations" />
            <NavItem to="/taint-map" label="Taint Map" />
          </nav>
        </header>
        <main className="p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/escalations" element={<EscalationQueue />} />
            <Route path="/taint-map" element={<TaintMapGraph />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
