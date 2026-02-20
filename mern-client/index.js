/**
 * AdaptiveAuth Client for JavaScript
 * Works with React, Node.js, Express, and any JavaScript project
 * 
 * MIT License - Copyright (c) 2026 SAGAR
 * FREE TO USE - No restrictions
 * 
 * Usage:
 *   const auth = new AdaptiveAuthClient({ baseURL: 'http://localhost:8000' });
 *   await auth.adaptiveLogin('user@email.com', 'password');
 */

class AdaptiveAuthClient {
  constructor(config) {
    this.baseURL = config.baseURL;
    this.tokenStorage = config.tokenStorage || 'localStorage';
    this.onTokenExpired = config.onTokenExpired;
    this.onRiskAlert = config.onRiskAlert;
    this.tokenKey = 'adaptiveauth_token';
    this._memoryToken = null;
  }

  // Token Management
  getToken() {
    if (this.tokenStorage === 'memory') return this._memoryToken;
    if (typeof localStorage !== 'undefined') {
      return this.tokenStorage === 'sessionStorage' 
        ? sessionStorage.getItem(this.tokenKey)
        : localStorage.getItem(this.tokenKey);
    }
    return this._memoryToken;
  }

  setToken(token) {
    this._memoryToken = token;
    if (typeof localStorage !== 'undefined' && this.tokenStorage !== 'memory') {
      const storage = this.tokenStorage === 'sessionStorage' ? sessionStorage : localStorage;
      storage.setItem(this.tokenKey, token);
    }
  }

  clearToken() {
    this._memoryToken = null;
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem(this.tokenKey);
      sessionStorage.removeItem(this.tokenKey);
    }
  }

  isAuthenticated() {
    return !!this.getToken();
  }

  // Device Fingerprint
  getDeviceFingerprint() {
    if (typeof navigator === 'undefined') return 'server-' + Date.now();
    const data = [
      navigator.userAgent,
      navigator.language,
      screen?.width + 'x' + screen?.height,
      new Date().getTimezoneOffset()
    ].join('|');
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      hash = ((hash << 5) - hash) + data.charCodeAt(i);
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  // HTTP Helper
  async _fetch(endpoint, options = {}) {
    const url = this.baseURL + endpoint;
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(url, {
      ...options,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    if (response.status === 401) {
      this.clearToken();
      this.onTokenExpired?.();
    }

    const data = await response.json().catch(() => ({}));
    
    if (!response.ok) {
      throw { status: response.status, ...data };
    }

    return data;
  }

  // ============ AUTHENTICATION ============

  async register(email, password, fullName) {
    return this._fetch('/auth/register', {
      method: 'POST',
      body: { email, password, full_name: fullName },
    });
  }

  async login(email, password) {
    const formData = new URLSearchParams();
    formData.append('username', email);
    formData.append('password', password);

    const response = await fetch(this.baseURL + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData,
    });

    const data = await response.json();
    if (data.access_token) {
      this.setToken(data.access_token);
    }
    return data;
  }

  async adaptiveLogin(email, password) {
    const result = await this._fetch('/auth/adaptive-login', {
      method: 'POST',
      body: {
        email,
        password,
        device_fingerprint: this.getDeviceFingerprint(),
        remember_device: true,
      },
    });

    if (result.risk_level && ['high', 'critical'].includes(result.risk_level)) {
      this.onRiskAlert?.(result.risk_level, result.message || 'Elevated risk detected');
    }

    if (result.status === 'success' && result.access_token) {
      this.setToken(result.access_token);
    }

    return result;
  }

  async verifyStepUp(challengeId, code) {
    const result = await this._fetch('/auth/step-up', {
      method: 'POST',
      body: { challenge_id: challengeId, verification_code: code },
    });
    if (result.access_token) {
      this.setToken(result.access_token);
    }
    return result;
  }

  async logout() {
    try {
      await this._fetch('/auth/logout', { method: 'POST' });
    } finally {
      this.clearToken();
    }
  }

  // ============ PASSWORD ============

  async forgotPassword(email) {
    return this._fetch('/auth/forgot-password', {
      method: 'POST',
      body: { email },
    });
  }

  async resetPassword(token, newPassword, confirmPassword) {
    return this._fetch('/auth/reset-password', {
      method: 'POST',
      body: { reset_token: token, new_password: newPassword, confirm_password: confirmPassword },
    });
  }

  // ============ 2FA ============

  async enable2FA() {
    return this._fetch('/auth/enable-2fa', { method: 'POST' });
  }

  async verify2FA(otp) {
    return this._fetch('/auth/verify-2fa', { method: 'POST', body: { otp } });
  }

  // ============ USER ============

  async getProfile() {
    return this._fetch('/user/profile');
  }

  async updateProfile(data) {
    return this._fetch('/user/profile', { method: 'PUT', body: data });
  }

  async getSecuritySettings() {
    return this._fetch('/user/security');
  }

  async getSessions() {
    return this._fetch('/user/sessions');
  }

  async revokeSessions(sessionIds, revokeAll = false) {
    return this._fetch('/user/sessions/revoke', {
      method: 'POST',
      body: { session_ids: sessionIds, revoke_all: revokeAll },
    });
  }

  // ============ ADAPTIVE / RISK ============

  async assessRisk() {
    return this._fetch('/adaptive/assess', { method: 'POST' });
  }

  async getSecurityStatus() {
    return this._fetch('/adaptive/security-status');
  }

  async verifySession() {
    return this._fetch('/adaptive/verify-session', { method: 'POST' });
  }

  async requestChallenge(type) {
    return this._fetch('/adaptive/challenge', {
      method: 'POST',
      body: { challenge_type: type },
    });
  }

  async verifyChallenge(challengeId, code) {
    return this._fetch('/adaptive/verify', {
      method: 'POST',
      body: { challenge_id: challengeId, code },
    });
  }
}

// Export for different module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { AdaptiveAuthClient, default: AdaptiveAuthClient };
}
if (typeof window !== 'undefined') {
  window.AdaptiveAuthClient = AdaptiveAuthClient;
}
