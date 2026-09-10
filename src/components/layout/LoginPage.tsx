import { useState, type FormEvent } from 'react';
import { ShieldCheck, Loader2, AlertTriangle, Lock } from 'lucide-react';
import { api } from '../../services/api';

export function LoginPage({ onLogin }: { onLogin: (user: any) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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
      } else {
        setError(result.error || 'Login failed.');
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

        {/* Login card */}
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

        <div className="mt-6 rounded-xl border border-gray-800/80 bg-gray-900/40 p-4">
          <p className="text-[10px] text-gray-500 font-mono leading-relaxed">
            The initial admin account is provisioned from <span className="text-cyan-400">ADMIN_USERNAME</span> /{' '}
            <span className="text-cyan-400">ADMIN_PASSWORD</span> environment variables on first boot.
            Additional role-based accounts are created by an admin from{' '}
            <span className="text-cyan-400">Settings → User Management</span>.
          </p>
          <p className="text-[10px] text-gray-600 mt-3 font-mono">
            RBAC enforced server-side · JWT 15 min access / 7 day refresh
          </p>
        </div>
      </div>
    </div>
  );
}
