/**
 * AdaptiveAuth Client for JavaScript/TypeScript
 * Works with React, Node.js, Express, and any JavaScript project
 */

export interface AdaptiveAuthConfig {
  /** Base URL of the AdaptiveAuth server */
  baseURL: string;
  /** Token storage method: 'localStorage', 'sessionStorage', or 'memory' */
  tokenStorage?: 'localStorage' | 'sessionStorage' | 'memory';
  /** Callback when token expires */
  onTokenExpired?: () => void;
  /** Callback when risk alert is triggered */
  onRiskAlert?: (level: string, message: string) => void;
}

export interface RegisterData {
  email: string;
  password: string;
  full_name: string;
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AdaptiveLoginData {
  email: string;
  password: string;
  device_fingerprint?: string;
  remember_device?: boolean;
}

export interface ChallengeData {
  challenge_id: string;
  verification_code: string;
}

export interface ResetPasswordData {
  reset_token: string;
  new_password: string;
  confirm_password: string;
}

export interface RevokeSessionsData {
  session_ids?: string[];
  revoke_all?: boolean;
}

export interface ProfileData {
  [key: string]: any;
}

export interface UserData {
  id?: number;
  email: string;
  full_name?: string;
  is_active?: boolean;
  is_verified?: boolean;
  role?: string;
  created_at?: string;
  last_login?: string;
}

export interface AuthResponse {
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  user?: UserData;
  status?: string;
  message?: string;
  risk_level?: string;
}

declare class AdaptiveAuthClient {
  constructor(config: AdaptiveAuthConfig);

  // Token Management
  getToken(): string | null;
  setToken(token: string): void;
  clearToken(): void;
  isAuthenticated(): boolean;

  // Device Fingerprint
  getDeviceFingerprint(): string;

  // Authentication Methods
  register(email: string, password: string, fullName: string): Promise<AuthResponse>;
  login(email: string, password: string): Promise<AuthResponse>;
  adaptiveLogin(email: string, password: string): Promise<AuthResponse>;
  verifyStepUp(challengeId: string, code: string): Promise<AuthResponse>;
  logout(): Promise<void>;

  // Password Methods
  forgotPassword(email: string): Promise<any>;
  resetPassword(token: string, newPassword: string, confirmPassword: string): Promise<any>;

  // 2FA Methods
  enable2FA(): Promise<any>;
  verify2FA(otp: string): Promise<any>;

  // User Methods
  getProfile(): Promise<UserData>;
  updateProfile(data: ProfileData): Promise<UserData>;
  getSecuritySettings(): Promise<any>;
  getSessions(): Promise<any[]>;
  revokeSessions(sessionIds?: string[], revokeAll?: boolean): Promise<any>;

  // Adaptive/Risk Methods
  assessRisk(): Promise<any>;
  getSecurityStatus(): Promise<any>;
  verifySession(): Promise<any>;
  requestChallenge(type: string): Promise<any>;
  verifyChallenge(challengeId: string, code: string): Promise<any>;
}

export { AdaptiveAuthClient };
export default AdaptiveAuthClient;