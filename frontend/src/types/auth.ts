/** Auth types for Policy Console (APEP-106, APEP-107). */

export type ConsoleRole = "Admin" | "PolicyAuthor" | "Analyst" | "Approver";

export interface User {
  username: string;
  email: string;
  roles: ConsoleRole[];
  tenant_id: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}
