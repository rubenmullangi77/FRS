import { api } from './api';

export interface AuthUser {
  username: string;
  role: string;
}

export interface AuthSession {
  isAuthenticated: boolean;
  user: AuthUser | null;
  token: string | null;
}

const SESSION_KEY = 'forensivault_auth_session_v1';

type AuthListener = (session: AuthSession) => void;
const listeners: Set<AuthListener> = new Set();

class AuthService {
  private currentSession: AuthSession;

  constructor() {
    this.currentSession = this.loadInitialSession();
  }

  private loadInitialSession(): AuthSession {
    try {
      let raw = sessionStorage.getItem(SESSION_KEY);
      if (!raw) {
        raw = localStorage.getItem(SESSION_KEY);
      }
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && parsed.isAuthenticated && parsed.user && parsed.token) {
          return {
            isAuthenticated: true,
            user: parsed.user,
            token: parsed.token
          };
        }
      }
    } catch {
      // Ignore parse failure
    }
    return {
      isAuthenticated: false,
      user: null,
      token: null
    };
  }

  getSession(): AuthSession {
    return { ...this.currentSession };
  }

  isAuthenticated(): boolean {
    return this.currentSession.isAuthenticated;
  }

  getUser(): AuthUser | null {
    return this.currentSession.user;
  }

  getUsername(): string {
    return this.currentSession.user?.username || '';
  }

  async login(username: string, password: string, remember: boolean = false): Promise<AuthUser> {
    const res = await api.login({ username, password, remember });
    const session: AuthSession = {
      isAuthenticated: true,
      user: res.user,
      token: res.token
    };
    this.currentSession = session;

    const serialized = JSON.stringify(session);
    if (remember) {
      localStorage.setItem(SESSION_KEY, serialized);
    } else {
      sessionStorage.setItem(SESSION_KEY, serialized);
    }

    this.notifyListeners();
    return res.user;
  }

  async logout(): Promise<void> {
    const user = this.currentSession.user;
    try {
      await api.logout(user?.username);
    } catch {
      // Continue client cleanup even if network disconnect
    }

    this.currentSession = {
      isAuthenticated: false,
      user: null,
      token: null
    };

    sessionStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(SESSION_KEY);

    this.notifyListeners();
  }

  async verifyPassword(password: string, action?: string, target?: string): Promise<boolean> {
    const username = this.getUsername();
    if (!username) {
      throw new Error('No authenticated user in session.');
    }
    const res = await api.verifyPassword({
      username,
      password,
      action: action || 'CONFIRM_SENSITIVE_ACTION',
      target: target || ''
    });
    return res.verified;
  }

  subscribe(listener: AuthListener): () => void {
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }

  private notifyListeners(): void {
    const copy = { ...this.currentSession };
    listeners.forEach((fn) => fn(copy));
  }
}

export const authService = new AuthService();
