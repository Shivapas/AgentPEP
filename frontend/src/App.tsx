import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./contexts/AuthContext";
import { ThemeProvider } from "./contexts/ThemeContext";
import { ToastProvider } from "./contexts/ToastContext";
import { ProtectedRoute } from "./components/auth/ProtectedRoute";
import { AppShell } from "./components/layout/AppShell";
import { DashboardPage } from "./components/dashboard/DashboardPage";
import { Placeholder } from "./components/common/Placeholder";
import { PolicyAuthoringPage } from "./components/policy/PolicyAuthoringPage";
import { AgentRegistryList } from "./components/agents/AgentRegistryList";
import { AgentProfileForm } from "./components/agents/AgentProfileForm";
import { AgentDetailPage } from "./components/agents/AgentDetailPage";
import { BulkRoleAssignment } from "./components/agents/BulkRoleAssignment";
import { RiskDashboard } from "./components/RiskDashboard";
import { AuditExplorer } from "./components/AuditExplorer";
import { SessionTimeline } from "./components/SessionTimeline";
import { EscalationQueue } from "./components/escalation/EscalationQueue";
import { TaintMapGraph } from "./components/taint/TaintMapGraph";
import { SimulationBuilder } from "./components/SimulationBuilder";
import { SimulationCompare } from "./components/SimulationCompare";
import { BrowserRouter, Routes, Route, Link, useLocation } from "react-router-dom";
import { Dashboard } from "./components/Dashboard";
import { ComplianceReports } from "./components/ComplianceReports";

function NavLink({ to, children }: { to: string; children: React.ReactNode }) {
  const { pathname } = useLocation();
  const active = pathname === to;
  return (
    <Link
      to={to}
      className={`text-sm font-medium ${active ? "text-foreground" : "text-muted-foreground hover:text-foreground"}`}
    >
      {children}
    </Link>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <AuthProvider>
          <ToastProvider>
            <Routes>
              {/* All console routes require authentication */}
              <Route
                element={
                  <ProtectedRoute>
                    <AppShell />
                  </ProtectedRoute>
                }
              >
                <Route path="/" element={<DashboardPage />} />
                <Route path="/policies" element={<Placeholder title="Policies" />} />
                <Route path="/policy" element={<PolicyAuthoringPage />} />
                <Route path="/agents" element={<AgentRegistryList />} />
                <Route path="/agents/new" element={<AgentProfileForm />} />
                <Route path="/agents/bulk-roles" element={<BulkRoleAssignment />} />
                <Route path="/agents/:agentId" element={<AgentDetailPage />} />
                <Route path="/agents/:agentId/edit" element={<AgentProfileForm />} />
                <Route path="/audit" element={<AuditExplorer />} />
                <Route path="/audit/session/:sessionId" element={<SessionTimeline />} />
                <Route path="/escalations" element={<EscalationQueue />} />
                <Route path="/taint-map" element={<TaintMapGraph />} />
                <Route path="/simulate" element={<SimulationBuilder />} />
                <Route path="/simulate/compare" element={<SimulationCompare />} />
                <Route path="/risk" element={<RiskDashboard />} />
              </Route>
            </Routes>
          </ToastProvider>
        </AuthProvider>
      </ThemeProvider>
      <div className="min-h-screen bg-background">
        <header className="border-b border-border px-6 py-4">
          <div className="flex items-center justify-between">
            <h1 className="text-xl font-semibold text-foreground">
              AgentPEP — Policy Console
            </h1>
            <nav className="flex gap-6">
              <NavLink to="/">Dashboard</NavLink>
              <NavLink to="/compliance">Compliance Reports</NavLink>
            </nav>
          </div>
        </header>
        <main className="p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/compliance" element={<ComplianceReports />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
