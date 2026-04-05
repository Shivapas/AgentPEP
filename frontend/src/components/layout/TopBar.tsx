/** Top bar with tenant switcher, theme toggle, user menu (APEP-108, APEP-109). */

import { useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { useTheme } from "../../contexts/ThemeContext";
import { Breadcrumbs } from "./Breadcrumbs";

export function TopBar() {
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <header className="flex items-center justify-between border-b border-border bg-card px-4 py-2">
      <Breadcrumbs />

      <div className="flex items-center gap-3">
        {/* Tenant badge */}
        {user && (
          <span className="rounded bg-secondary px-2 py-0.5 text-xs font-medium text-secondary-foreground">
            {user.tenant_id}
          </span>
        )}

        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          className="rounded-md p-1.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
          aria-label="Toggle theme"
          title={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
        >
          {theme === "light" ? "☾" : "☀"}
        </button>

        {/* User menu */}
        <div className="relative">
          <button
            onClick={() => setMenuOpen(!menuOpen)}
            className="flex items-center gap-1 rounded-md px-2 py-1 text-sm text-foreground hover:bg-accent"
          >
            {user?.username}
            <span className="text-xs">▾</span>
          </button>
          {menuOpen && (
            <div className="absolute right-0 top-full z-40 mt-1 w-40 rounded-md border border-border bg-card py-1 shadow-lg">
              <div className="px-3 py-1.5 text-xs text-muted-foreground">
                {user?.roles.join(", ")}
              </div>
              <hr className="border-border" />
              <button
                onClick={() => {
                  setMenuOpen(false);
                  logout();
                }}
                className="w-full px-3 py-1.5 text-left text-sm text-foreground hover:bg-accent"
              >
                Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
