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
import { ComplianceReports } from "./components/ComplianceReports";
import { PolicyRules } from "./components/PolicyRules";
import { AuditLog } from "./components/AuditLog";
import { AgentProfiles } from "./components/AgentProfiles";
import { UXSurvey } from "./components/UXSurvey";
import { PlanManagementList } from "./components/plans/PlanManagementList";
import { PlanIssuanceForm } from "./components/plans/PlanIssuanceForm";
import { PlanDetailPage } from "./components/plans/PlanDetailPage";
import { PlanExplorer } from "./components/plans/PlanExplorer";
import { NetworkEventsTab } from "./components/NetworkEventsTab";

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
                <Route path="/rules" element={<PolicyRules />} />
                <Route path="/agents" element={<AgentRegistryList />} />
                <Route path="/agents/new" element={<AgentProfileForm />} />
                <Route path="/agents/bulk-roles" element={<BulkRoleAssignment />} />
                <Route path="/agents/:agentId" element={<AgentDetailPage />} />
                <Route path="/agents/:agentId/edit" element={<AgentProfileForm />} />
                <Route path="/agents/profiles" element={<AgentProfiles />} />
                <Route path="/audit" element={<AuditExplorer />} />
                <Route path="/audit/log" element={<AuditLog />} />
                <Route path="/audit/session/:sessionId" element={<SessionTimeline />} />
                <Route path="/escalations" element={<EscalationQueue />} />
                <Route path="/taint-map" element={<TaintMapGraph />} />
                <Route path="/simulate" element={<SimulationBuilder />} />
                <Route path="/simulate/compare" element={<SimulationCompare />} />
                <Route path="/compliance" element={<ComplianceReports />} />
                <Route path="/plans" element={<PlanManagementList />} />
                <Route path="/plans/new" element={<PlanIssuanceForm />} />
                <Route path="/plans/:planId" element={<PlanDetailPage />} />
                <Route path="/plans/:planId/explorer" element={<PlanExplorer />} />
                <Route path="/network-events" element={<NetworkEventsTab />} />
                <Route path="/risk" element={<RiskDashboard />} />
                <Route path="/ux-survey" element={<UXSurvey />} />
              </Route>
            </Routes>
          </ToastProvider>
        </AuthProvider>
      </ThemeProvider>
    </BrowserRouter>
  );
}
