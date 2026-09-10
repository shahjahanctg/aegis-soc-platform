import { create } from 'zustand';
import type { UserSession } from '../types';

// ---------------------------------------------------------------------------
// Auth store: JWT access/refresh tokens + session user, persisted to
// localStorage so a page reload keeps you signed in. Access tokens are short
// lived (15 min); the API client transparently refreshes on 401.
// ---------------------------------------------------------------------------

const STORAGE_KEY = 'aegis.auth';

interface AuthState {
  accessToken: string | null;
  refreshToken: string | null;
  user: UserSession | null;
  setAuth: (a: { accessToken: string; refreshToken?: string | null; user: UserSession }) => void;
  setUser: (u: UserSession) => void;
  setAccessToken: (t: string) => void;
  clearAuth: () => void;
}

function readPersisted(): Pick<AuthState, 'accessToken' | 'refreshToken' | 'user'> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { accessToken: null, refreshToken: null, user: null };
    const parsed = JSON.parse(raw);
    return {
      accessToken: typeof parsed.accessToken === 'string' ? parsed.accessToken : null,
      refreshToken: typeof parsed.refreshToken === 'string' ? parsed.refreshToken : null,
      user: parsed.user ?? null,
    };
  } catch {
    return { accessToken: null, refreshToken: null, user: null };
  }
}

export const useAuthStore = create<AuthState>((set) => {
  const initial = readPersisted();
  return {
    ...initial,
    setAuth: ({ accessToken, refreshToken, user }) => {
      set((state) => {
        const next = {
          accessToken,
          refreshToken: refreshToken ?? state.refreshToken,
          user,
        };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
        return next;
      });
    },
    setUser: (user) => {
      set((state) => {
        const next = { ...state, user };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
        return next;
      });
    },
    setAccessToken: (accessToken) => {
      set((state) => {
        const next = { ...state, accessToken };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
        return next;
      });
    },
    clearAuth: () => {
      localStorage.removeItem(STORAGE_KEY);
      set({ accessToken: null, refreshToken: null, user: null });
    },
  };
});

export const getAuthState = () => useAuthStore.getState();
