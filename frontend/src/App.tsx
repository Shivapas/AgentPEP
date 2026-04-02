import { BrowserRouter, Routes, Route, Link, useLocation } from "react-router-dom";
import { Dashboard } from "./components/Dashboard";
import { AuditExplorer } from "./components/AuditExplorer";
import { SessionTimeline } from "./components/SessionTimeline";
import { cn } from "./lib/utils";

function NavLink({ to, label }: { to: string; label: string }) {
  const { pathname } = useLocation();
  const active = to === "/" ? pathname === "/" : pathname.startsWith(to);
  return (
    <Link
      to={to}
      className={cn(
        "text-sm hover:text-foreground",
        active ? "font-medium text-foreground" : "text-muted-foreground",
      )}
    >
      {label}
    </Link>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-background">
        <header className="border-b border-border px-6 py-4">
          <div className="flex items-center gap-6">
            <h1 className="text-xl font-semibold text-foreground">
              AgentPEP — Policy Console
            </h1>
            <nav className="flex gap-4">
              <NavLink to="/" label="Dashboard" />
              <NavLink to="/audit" label="Audit Explorer" />
            </nav>
          </div>
        </header>
        <main className="p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/audit" element={<AuditExplorer />} />
            <Route
              path="/audit/session/:sessionId"
              element={<SessionTimeline />}
            />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
