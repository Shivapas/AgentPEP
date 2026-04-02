import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import { Dashboard } from "./components/Dashboard";
import { AgentRegistryList } from "./components/agents/AgentRegistryList";
import { AgentProfileForm } from "./components/agents/AgentProfileForm";
import { AgentDetailPage } from "./components/agents/AgentDetailPage";
import { BulkRoleAssignment } from "./components/agents/BulkRoleAssignment";
import { cn } from "./lib/utils";

function NavItem({ to, children }: { to: string; children: React.ReactNode }) {
  return (
    <NavLink
      to={to}
      end
      className={({ isActive }) =>
        cn(
          "text-sm font-medium hover:text-foreground",
          isActive ? "text-foreground" : "text-muted-foreground",
        )
      }
    >
      {children}
    </NavLink>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-background">
        <header className="border-b border-border px-6 py-4">
          <div className="flex items-center gap-8">
            <h1 className="text-xl font-semibold text-foreground">
              AgentPEP — Policy Console
            </h1>
            <nav className="flex gap-4">
              <NavItem to="/">Dashboard</NavItem>
              <NavItem to="/agents">Agents</NavItem>
            </nav>
          </div>
        </header>
        <main className="p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/agents" element={<AgentRegistryList />} />
            <Route path="/agents/new" element={<AgentProfileForm />} />
            <Route path="/agents/bulk-roles" element={<BulkRoleAssignment />} />
            <Route path="/agents/:agentId" element={<AgentDetailPage />} />
            <Route path="/agents/:agentId/edit" element={<AgentProfileForm />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
