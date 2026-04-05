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
                <Route
                  path="/policies"
                  element={<Placeholder title="Policies" />}
                />
                <Route
                  path="/policy"
                  element={<PolicyAuthoringPage />}
                />
                <Route
                  path="/agents"
                  element={<AgentRegistryList />}
                />
                <Route path="/agents/new" element={<AgentProfileForm />} />
                <Route path="/agents/bulk-roles" element={<BulkRoleAssignment />} />
                <Route path="/agents/:agentId" element={<AgentDetailPage />} />
                <Route path="/agents/:agentId/edit" element={<AgentProfileForm />} />
                <Route
                  path="/audit"
                  element={<AuditExplorer />}
                />
                <Route
                  path="/audit/session/:sessionId"
                  element={<SessionTimeline />}
                />
                <Route
                  path="/escalations"
                  element={<EscalationQueue />}
                />
                <Route
                  path="/taint-map"
                  element={<TaintMapGraph />}
                />
                <Route
                  path="/risk"
                  element={<RiskDashboard />}
                />
              </Route>
            </Routes>
          </ToastProvider>
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  );
}
