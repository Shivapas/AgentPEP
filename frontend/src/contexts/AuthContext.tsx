/** Auth context with auto-refresh (APEP-106). */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  apiFetch,
  clearTokens,
  getAccessToken,
  loadTokens,
  login as apiLogin,
  logout as apiLogout,
  setOnAuthFailure,
} from "../lib/api";
import type { AuthState, User } from "../types/auth";

interface AuthContextValue extends AuthState {
  login: (username: string, password: string) => Promise<string | null>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const fetchMe = useCallback(async () => {
    try {
      const res = await apiFetch("/v1/console/me");
      if (res.ok) {
        setUser(await res.json());
      } else {
        setUser(null);
        clearTokens();
      }
    } catch {
      setUser(null);
    }
  }, []);

  // Bootstrap: load tokens from localStorage
  useEffect(() => {
    loadTokens();
    setOnAuthFailure(() => {
      setUser(null);
    });
    if (getAccessToken()) {
      fetchMe().finally(() => setIsLoading(false));
    } else {
      setIsLoading(false);
    }
  }, [fetchMe]);

  // Auto-refresh: refresh token 2 min before expiry
  useEffect(() => {
    if (!user) return;
    const interval = setInterval(async () => {
      try {
        const res = await apiFetch("/v1/console/me");
        if (!res.ok) setUser(null);
      } catch {
        // auto-refresh handled by apiFetch
      }
    }, 25 * 60 * 1000); // every 25 min
    return () => clearInterval(interval);
  }, [user]);

  const login = useCallback(
    async (username: string, password: string): Promise<string | null> => {
      const result = await apiLogin(username, password);
      if (result.success) {
        await fetchMe();
        return null;
      }
      return result.error || "Login failed";
    },
    [fetchMe],
  );

  const logout = useCallback(async () => {
    await apiLogout();
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({
      user,
      isAuthenticated: !!user,
      isLoading,
      login,
      logout,
    }),
    [user, isLoading, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
