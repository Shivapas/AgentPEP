/** Protected route wrapper with RBAC (APEP-106, APEP-107). */

import type { ReactNode } from "react";
import { useAuth } from "../../contexts/AuthContext";
import type { ConsoleRole } from "../../types/auth";
import { LoginPage } from "./LoginPage";

interface Props {
  children: ReactNode;
  requiredRoles?: ConsoleRole[];
}

export function ProtectedRoute({ children, requiredRoles }: Props) {
  const { isAuthenticated, isLoading, user } = useAuth();

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  if (requiredRoles && requiredRoles.length > 0 && user) {
    const hasRole = requiredRoles.some((r) => user.roles.includes(r));
    if (!hasRole) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-background">
          <div className="rounded-lg border border-border bg-card p-8 text-center">
            <h2 className="text-lg font-semibold text-foreground">
              Access Denied
            </h2>
            <p className="mt-2 text-sm text-muted-foreground">
              You need one of these roles: {requiredRoles.join(", ")}
            </p>
          </div>
        </div>
      );
    }
  }

  return <>{children}</>;
}
