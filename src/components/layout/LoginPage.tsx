import { useState, type FormEvent } from 'react';
import { ShieldCheck, Loader2, AlertTriangle, Lock, KeyRound } from 'lucide-react';
import { api } from '../../services/api';

export function LoginPage({ onLogin }: { onLogin: (user: any) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // Password-expiry recovery state (login returns code PASSWORD_EXPIRED)
  const [expired, setExpired] = useState<{ username: string; oldPassword: string } | null>(null);
  const [newPassword, setNewPassword] = useState('');
  const [newPassword2, setNewPassword2] = useState('');

  const handleLogin = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!username.trim() || !password) {
      setError('Username and password are required.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const result = await api.login(username.trim(), password);
      if (result.ok && result.user) {
        onLogin(result.user);
      } else if (result.code === 'PASSWORD_EXPIRED') {
        // Rotate in place: keep the username, ask for a new password.
        setExpired({ username: username.trim(), oldPassword: password });
        setError(null);
      } else {
        setError(result.error || 'Login failed.');
      }
    } catch {
      setError('Unable to reach authentication service.');
    } finally {
      setBusy(false);
    }
  };

  const handleExpiredRotate = async (e: FormEvent) => {
    e.preventDefault();
    if (!expired) return;
    if (newPassword !== newPassword2) {
      setError('New passwords do not match.');
      return;
    }
    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const result = await api.expiredPassword(expired.username, expired.oldPassword, newPassword);
      if (result.ok && result.user) {
        setExpired(null);
        onLogin(result.user);
      } else {
        setError(result.error || 'Failed to rotate password.');
      }
    } catch {
      setError('Unable to reach authentication service.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex items-center justify-center p-4 font-sans">
      <div className="w-full max-w-md">
        {/* Brand */}
        <div className="flex flex-col items-center mb-8">
          <div className="h-16 w-16 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-700 flex items-center justify-center shadow-[0_0_40px_rgba(6,182,212,0.4)] mb-4">
            <ShieldCheck className="h-9 w-9 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">AegisSOC Platform</h1>
          <p className="text-sm text-gray-500 mt-1 font-mono">Unified Security Operations · Training · CTF · DFIR</p>
        </div>

        {expired ? (
          /* ---- Password expired: rotation required ---- */
          <form
            onSubmit={handleExpiredRotate}
            className="rounded-2xl border border-amber-500/40 bg-gray-900/70 backdrop-blur p-6 space-y-4 shadow-2xl"
          >
            <div className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2.5 text-xs text-amber-300">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
              <span>
                Your password for <span className="font-bold text-amber-200">@{expired.username}</span> has expired.
                Set a new one to continue.
              </span>
            </div>

            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">New password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                autoComplete="new-password" minLength={8} autoFocus
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm font-mono outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/40 transition"
                placeholder="min 8 chars, upper+lower+digit+special"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">Confirm new password</label>
              <input
                type="password"
                value={newPassword2}
                onChange={(e) => setNewPassword2(e.target.value)}
                autoComplete="new-password" minLength={8}
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm font-mono outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/40 transition"
                placeholder="repeat the new password"
              />
            </div>

            {error && (
              <div className="flex items-start gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2.5 text-xs text-rose-300">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-amber-500 hover:bg-amber-400 disabled:opacity-50 disabled:cursor-not-allowed px-4 py-2.5 text-sm font-semibold text-gray-950 transition shadow-lg shadow-amber-500/20"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
              {busy ? 'Rotating…' : 'Set New Password & Sign In'}
            </button>
            <button
              type="button"
              onClick={() => { setExpired(null); setNewPassword(''); setNewPassword2(''); setError(null); }}
              className="w-full text-center text-[11px] font-mono text-gray-500 hover:text-gray-300 transition cursor-pointer"
            >
              ← Back to sign in
            </button>
          </form>
        ) : (
          /* ---- Normal login card ---- */
          <form
            onSubmit={handleLogin}
            className="rounded-2xl border border-gray-800 bg-gray-900/70 backdrop-blur p-6 space-y-4 shadow-2xl"
          >
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoFocus
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm font-mono outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/40 transition"
                placeholder="username"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm font-mono outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/40 transition"
                placeholder="••••••••••••"
              />
            </div>

            {error && (
              <div className="flex items-start gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-2.5 text-xs text-rose-300">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed px-4 py-2.5 text-sm font-semibold text-white transition shadow-lg shadow-cyan-600/20"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />}
              {busy ? 'Authenticating…' : 'Secure Sign-In'}
            </button>
          </form>
        )}

        <div className="mt-6 rounded-xl border border-gray-800/80 bg-gray-900/40 p-4">
          <p className="text-[10px] text-gray-500 font-mono leading-relaxed">
            The initial admin account is provisioned from <span className="text-cyan-400">ADMIN_USERNAME</span> /{' '}
            <span className="text-cyan-400">ADMIN_PASSWORD</span> environment variables on first boot.
            Additional role-based accounts are created by an admin from{' '}
            <span className="text-cyan-400">Settings → User Management</span> or invited via one-time setup links.
          </p>
          <p className="text-[10px] text-gray-600 mt-3 font-mono">
            RBAC enforced server-side · JWT 15 min access / 7 day refresh · password policy enforced everywhere
          </p>
        </div>
      </div>
    </div>
  );
}