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
            <Route path="/compliance" element={<ComplianceReports />} />
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
