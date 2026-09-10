import { useEffect, useState, type FormEvent } from 'react';
import { ShieldCheck, Loader2, AlertTriangle, MailCheck, KeyRound } from 'lucide-react';
import { api } from '../../services/api';
import { InviteRecord } from '../../types';

export function InviteAcceptPage({ token, onAccepted }: { token: string; onAccepted: (user: any) => void }) {
  const [invite, setInvite] = useState<InviteRecord | null>(null);
  const [status, setStatus] = useState<'loading' | 'invalid' | 'ready'>('loading');
  const [username, setUsername] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [password2, setPassword2] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    (async () => {
      const res = await api.validateInvite(token);
      if (!alive) return;
      if (!res?.invite) {
        setStatus('invalid');
      } else {
        setInvite(res.invite);
        setName(res.invite.name || '');
        setStatus('ready');
      }
    })();
    return () => { alive = false; };
  }, [token]);

  const handleAccept = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (password !== password2) {
      setError('Passwords do not match.');
      return;
    }
    setBusy(true);
    try {
      const result = await api.acceptInvite(token, { username, name, password });
      if (result.ok && result.user) {
        onAccepted(result.user);
      } else {
        setError(result.error || 'Failed to accept invite.');
      }
    } catch {
      setError('Unable to reach the server.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 flex items-center justify-center p-4 font-sans">
      <div className="w-full max-w-md">
        <div className="flex flex-col items-center mb-8">
          <div className="h-16 w-16 rounded-2xl bg-gradient-to-br from-emerald-500 to-cyan-700 flex items-center justify-center shadow-[0_0_40px_rgba(16,185,129,0.35)] mb-4">
            <MailCheck className="h-9 w-9 text-white" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Account Invitation</h1>
          <p className="text-sm text-gray-500 mt-1 font-mono">One-time setup link · AegisSOC Platform</p>
        </div>

        {status === 'loading' && (
          <div className="rounded-2xl border border-gray-800 bg-gray-900/70 p-8 text-center">
            <Loader2 className="h-6 w-6 animate-spin text-cyan-400 mx-auto" />
            <p className="text-xs font-mono text-gray-400 mt-3">Validating setup link…</p>
          </div>
        )}

        {status === 'invalid' && (
          <div className="rounded-2xl border border-rose-800 bg-rose-950/30 p-6 text-center">
            <AlertTriangle className="h-8 w-8 text-rose-400 mx-auto mb-3" />
            <h3 className="font-mono text-sm font-bold text-rose-300 uppercase">Invite is invalid</h3>
            <p className="text-xs text-gray-400 mt-2">
              This setup link is invalid, has expired, or was already used. Ask an administrator to send a new invite.
            </p>
          </div>
        )}

        {status === 'ready' && invite && (
          <form onSubmit={handleAccept} className="rounded-2xl border border-emerald-800/60 bg-gray-900/70 backdrop-blur p-6 space-y-4 shadow-2xl">
            <div className="rounded-lg border border-emerald-800/50 bg-emerald-950/30 px-3 py-2.5 text-xs font-mono text-emerald-300">
              Invited for role <span className="font-bold uppercase">{invite.role}</span>
              {invite.name && <> as <span className="font-bold">{invite.name}</span></>}
            </div>

            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required minLength={2} maxLength={64} pattern="[a-zA-Z0-9_.-]+"
                autoFocus
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm font-mono outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/40 transition"
                placeholder="jsmith"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">Full name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required maxLength={120}
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm font-mono outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/40 transition"
                placeholder="Jane Smith"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required minLength={8} autoComplete="new-password"
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm font-mono outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/40 transition"
                placeholder="min 8 chars, upper+lower+digit+special"
              />
            </div>
            <div>
              <label className="block text-xs font-mono text-gray-400 mb-1.5 uppercase tracking-wider">Confirm password</label>
              <input
                type="password"
                value={password2}
                onChange={(e) => setPassword2(e.target.value)}
                required minLength={8} autoComplete="new-password"
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2.5 text-sm font-mono outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500/40 transition"
                placeholder="repeat the password"
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
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed px-4 py-2.5 text-sm font-semibold text-white transition shadow-lg shadow-emerald-600/20"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
              {busy ? 'Creating account…' : 'Create Account & Sign In'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}