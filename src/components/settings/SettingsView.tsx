import React, { useEffect, useState } from 'react';
import {
  Users, HardDrive, KeyRound, ShieldAlert, Loader2, Plus, Trash2,
  CheckCircle2, AlertTriangle, ServerCog, Save, Eye, EyeOff, KeyRound as KeyIcon, UserX, X,
} from 'lucide-react';
import { api } from '../../services/api';
import { ManagedUser, AppSettings, UserSession } from '../../types';

const ROLE_LABELS: Record<ManagedUser['role'], string> = {
  admin: 'Admin — full control',
  analyst: 'SOC Analyst — triage, CTF, AI',
  trainer: 'Trainer — LMS + CTF admin',
  viewer: 'Viewer — read-only',
};

const ROLE_STYLES: Record<ManagedUser['role'], string> = {
  admin: 'bg-rose-950 text-rose-300 border-rose-800',
  analyst: 'bg-cyan-950 text-cyan-300 border-cyan-800',
  trainer: 'bg-purple-950 text-purple-300 border-purple-800',
  viewer: 'bg-gray-900 text-gray-400 border-gray-700',
};

type Tab = 'users' | 'retention' | 'gemini';

export const SettingsView: React.FC<{ user: UserSession | null }> = ({ user }) => {
  const [tab, setTab] = useState<Tab>('users');

  // -- User management -------------------------------------------------------
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [newUser, setNewUser] = useState({ username: '', name: '', password: '', role: 'analyst' as ManagedUser['role'] });
  const [userMsg, setUserMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [resetTarget, setResetTarget] = useState<ManagedUser | null>(null);
  const [resetPassword, setResetPassword] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<ManagedUser | null>(null);

  // -- Log retention ----------------------------------------------------------
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [retentionDraft, setRetentionDraft] = useState({ alertRetention: 2000, telemetryRetention: 2000, analysisRetention: 500 });
  const [retentionMsg, setRetentionMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  // -- Gemini -----------------------------------------------------------------
  const [geminiKey, setGeminiKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [geminiMsg, setGeminiMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (user?.role !== 'admin') return;
    refreshUsers();
    refreshSettings();
  }, [user?.role]);

  const refreshUsers = async () => {
    try {
      setUsers(await api.listUsers());
    } catch (err) {
      console.error(err);
    }
  };

  const refreshSettings = async () => {
    try {
      const s = await api.getSettings();
      setSettings(s);
      setRetentionDraft({
        alertRetention: s.alertRetention,
        telemetryRetention: s.telemetryRetention,
        analysisRetention: s.analysisRetention,
      });
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setUserMsg(null);
    try {
      await api.createUser(newUser);
      setUserMsg({ kind: 'ok', text: `Account '${newUser.username}' created with role ${newUser.role}.` });
      setNewUser({ username: '', name: '', password: '', role: 'analyst' });
      await refreshUsers();
    } catch (err: any) {
      const detail = err?.message;
      setUserMsg({ kind: 'err', text: detail?.includes('Username already exists') ? 'That username is already taken.' : 'Failed to create user — check the server and input.' });
    } finally {
      setBusy(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetTarget || resetPassword.length < 8) return;
    setBusy(true);
    setUserMsg(null);
    try {
      await api.resetUserPassword(resetTarget.id, resetPassword);
      setUserMsg({ kind: 'ok', text: `Password reset for '${resetTarget.username}'.` });
      setResetTarget(null);
      setResetPassword('');
    } catch (err) {
      console.error(err);
      setUserMsg({ kind: 'err', text: 'Failed to reset password — check the server.' });
    } finally {
      setBusy(false);
    }
  };

  const handleDeleteUser = async () => {
    if (!deleteTarget) return;
    setBusy(true);
    setUserMsg(null);
    try {
      await api.deleteUser(deleteTarget.id);
      setUserMsg({ kind: 'ok', text: `Account '${deleteTarget.username}' deleted (per-user progress and solves removed).` });
      setDeleteTarget(null);
      await refreshUsers();
    } catch (err: any) {
      console.error(err);
      const msg = err?.message || '';
      setUserMsg({
        kind: 'err',
        text: msg.includes('last admin')
          ? 'Cannot delete the last admin account.'
          : msg.includes('own account')
            ? 'You cannot delete your own account.'
            : 'Failed to delete user — check the server.',
      });
    } finally {
      setBusy(false);
    }
  };

  const handleSaveRetention = async () => {
    setBusy(true);
    setRetentionMsg(null);
    try {
      const s = await api.updateSettings(retentionDraft);
      setSettings(s);
      setRetentionMsg({ kind: 'ok', text: 'Log retention settings saved.' });
    } catch (err) {
      console.error(err);
      setRetentionMsg({ kind: 'err', text: 'Failed to save retention settings.' });
    } finally {
      setBusy(false);
    }
  };

  const handleSaveGemini = async () => {
    setBusy(true);
    setGeminiMsg(null);
    try {
      const s = await api.updateSettings({ geminiApiKey: geminiKey.trim() || null });
      setSettings(s);
      setGeminiKey('');
      setGeminiMsg({
        kind: 'ok',
        text: geminiKey.trim() ? 'Gemini API key saved and active (no restart needed).' : 'Gemini API key cleared.',
      });
    } catch (err) {
      console.error(err);
      setGeminiMsg({ kind: 'err', text: 'Failed to save the Gemini API key.' });
    } finally {
      setBusy(false);
    }
  };

  if (user?.role !== 'admin') {
    return (
      <div className="rounded-2xl border border-gray-800 bg-gray-950 p-8 text-center">
        <ShieldAlert className="h-10 w-10 text-rose-400 mx-auto mb-3" />
        <h3 className="font-mono text-sm font-bold text-gray-100 uppercase">Admin access required</h3>
        <p className="text-xs text-gray-400 mt-2 max-w-md mx-auto">
          User management, log retention, and AI key configuration are restricted to the platform administrator.
        </p>
      </div>
    );
  }

  const tabs: Array<{ id: Tab; label: string; icon: any }> = [
    { id: 'users', label: 'User Management', icon: Users },
    { id: 'retention', label: 'Log Retention', icon: HardDrive },
    { id: 'gemini', label: 'Gemini API', icon: KeyRound },
  ];

  return (
    <div className="space-y-5">
      {/* Tab bar */}
      <div className="flex items-center gap-1 rounded-xl border border-gray-800 bg-gray-950 p-1 overflow-x-auto">
        {tabs.map((t) => {
          const Icon = t.icon;
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-mono whitespace-nowrap transition-all cursor-pointer ${
                active ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-900 border border-transparent'
              }`}
            >
              <Icon className={`h-4 w-4 ${active ? 'text-cyan-400' : 'text-gray-500'}`} />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Users tab */}
      {tab === 'users' && (
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">
          {/* Create user */}
          <form onSubmit={handleCreateUser} className="lg:col-span-2 rounded-2xl border border-gray-800 bg-gray-950 p-5 space-y-3 h-fit">
            <h3 className="flex items-center gap-2 font-mono text-sm font-bold text-gray-100 uppercase">
              <Plus className="h-4 w-4 text-cyan-400" /> Create Role-Based Account
            </h3>
            <p className="text-[11px] text-gray-500 font-mono">
              No demo users — every account is created explicitly by an admin with a role-scoped permission set.
            </p>

            {userMsg && (
              <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs font-mono ${userMsg.kind === 'ok' ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' : 'border-rose-800 bg-rose-950/40 text-rose-300'}`}>
                {userMsg.kind === 'ok' ? <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" /> : <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />}
                <span>{userMsg.text}</span>
              </div>
            )}

            <label className="block">
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">Username</span>
              <input
                value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                required minLength={2} maxLength={64} pattern="[a-zA-Z0-9_.-]+"
                className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-cyan-500"
                placeholder="jsmith"
              />
            </label>
            <label className="block">
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">Full name</span>
              <input
                value={newUser.name}
                onChange={(e) => setNewUser({ ...newUser, name: e.target.value })}
                required maxLength={120}
                className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-cyan-500"
                placeholder="Jane Smith"
              />
            </label>
            <label className="block">
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">Password (min 8 chars)</span>
              <input
                type="password"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                required minLength={8} maxLength={256} autoComplete="new-password"
                className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-cyan-500"
                placeholder="••••••••"
              />
            </label>
            <label className="block">
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">Role</span>
              <select
                value={newUser.role}
                onChange={(e) => setNewUser({ ...newUser, role: e.target.value as ManagedUser['role'] })}
                className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-cyan-500"
              >
                {(Object.keys(ROLE_LABELS) as ManagedUser['role'][]).map((r) => (
                  <option key={r} value={r}>{ROLE_LABELS[r]}</option>
                ))}
              </select>
            </label>

            <button
              type="submit"
              disabled={busy}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 px-4 py-2.5 text-sm font-semibold text-white transition cursor-pointer"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              Create Account
            </button>
          </form>

          {/* User list */}
          <div className="lg:col-span-3 rounded-2xl border border-gray-800 bg-gray-950 p-5">
            <h3 className="flex items-center gap-2 font-mono text-sm font-bold text-gray-100 uppercase mb-3">
              <Users className="h-4 w-4 text-cyan-400" /> Platform Accounts ({users.length})
            </h3>
            <div className="space-y-2">
              {users.length === 0 && (
                <p className="text-xs text-gray-500 font-mono">No accounts yet.</p>
              )}
              {users.map((u) => {
                const isSelf = u.id === user?.id;
                return (
                  <div key={u.id} className="flex items-center gap-3 rounded-lg border border-gray-800 bg-gray-900/50 px-3 py-2.5">
                    <div className="flex h-8 w-8 items-center justify-center rounded-full bg-cyan-950 text-cyan-400 font-mono text-[11px] font-bold border border-cyan-800 shrink-0">
                      {u.name.slice(0, 2).toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-mono text-xs font-bold text-gray-100 truncate">
                        {u.name}{isSelf && <span className="ml-1.5 text-[9px] text-cyan-400 font-mono uppercase">(you)</span>}
                      </p>
                      <p className="text-[10px] font-mono text-gray-500 truncate">@{u.username}</p>
                    </div>
                    <span className={`shrink-0 rounded border px-2 py-0.5 text-[10px] font-mono font-bold uppercase ${ROLE_STYLES[u.role]}`}>
                      {u.role}
                    </span>
                    <span className="shrink-0 rounded bg-amber-950/40 border border-amber-800/60 px-2 py-0.5 text-[10px] font-mono text-amber-300">
                      {u.score} pts
                    </span>
                    <div className="flex shrink-0 items-center gap-1.5">
                      <button
                        onClick={() => { setResetTarget(u); setResetPassword(''); setUserMsg(null); }}
                        disabled={busy}
                        className="flex items-center gap-1 rounded-md border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-mono text-cyan-400 hover:bg-gray-800 transition-all cursor-pointer disabled:opacity-50"
                        title={`Reset password for ${u.username}`}
                      >
                        <KeyIcon className="h-3 w-3" />
                        Reset PW
                      </button>
                      <button
                        onClick={() => { setDeleteTarget(u); setUserMsg(null); }}
                        disabled={busy || isSelf}
                        className="flex items-center gap-1 rounded-md border border-rose-900/60 bg-rose-950/30 px-2 py-1 text-[10px] font-mono text-rose-300 hover:bg-rose-950/60 transition-all cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                        title={isSelf ? 'You cannot delete your own account' : `Delete ${u.username} and all per-user data`}
                      >
                        <UserX className="h-3 w-3" />
                        Delete
                      </button>
                    </div>
                  </div>
                );
              })}

              {/* Inline reset-password form */}
              {resetTarget && (
                <form onSubmit={handleResetPassword} className="mt-3 rounded-lg border border-cyan-800/60 bg-cyan-950/20 p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-mono font-bold text-cyan-300 uppercase">
                      Reset password for @{resetTarget.username}
                    </span>
                    <button type="button" onClick={() => setResetTarget(null)} className="text-gray-400 hover:text-gray-200 cursor-pointer">
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                  <div className="flex gap-2">
                    <input
                      type="password"
                      value={resetPassword}
                      onChange={(e) => setResetPassword(e.target.value)}
                      minLength={8} maxLength={256} required autoComplete="new-password"
                      placeholder="New password (min 8 chars)"
                      className="flex-1 rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-cyan-500"
                    />
                    <button
                      type="submit"
                      disabled={busy || resetPassword.length < 8}
                      className="flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 px-4 py-2 text-xs font-mono font-bold text-white transition cursor-pointer"
                    >
                      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyIcon className="h-3.5 w-3.5" />}
                      Set Password
                    </button>
                  </div>
                </form>
              )}

              {/* Inline delete confirmation */}
              {deleteTarget && (
                <div className="mt-3 rounded-lg border border-rose-800/70 bg-rose-950/20 p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[11px] font-mono font-bold text-rose-300 uppercase">
                      Delete @{deleteTarget.username}?
                    </span>
                    <button type="button" onClick={() => setDeleteTarget(null)} className="text-gray-400 hover:text-gray-200 cursor-pointer">
                      <X className="h-4 w-4" />
                    </button>
                  </div>
                  <p className="text-[11px] text-gray-400 font-mono mb-3">
                    Removes the account, its CTF solves, hint unlocks, and training progress. This cannot be undone.
                  </p>
                  <div className="flex gap-2">
                    <button
                      onClick={handleDeleteUser}
                      disabled={busy}
                      className="flex items-center gap-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 px-4 py-2 text-xs font-mono font-bold text-white transition cursor-pointer"
                    >
                      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                      Confirm Delete
                    </button>
                    <button
                      onClick={() => setDeleteTarget(null)}
                      disabled={busy}
                      className="rounded-lg border border-gray-700 bg-gray-900 px-4 py-2 text-xs font-mono text-gray-300 hover:bg-gray-800 transition cursor-pointer"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Retention tab */}
      {tab === 'retention' && (
        <div className="rounded-2xl border border-gray-800 bg-gray-950 p-5 max-w-2xl space-y-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <HardDrive className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-mono text-sm font-bold text-gray-100 uppercase">Log &amp; Data Retention</h3>
              <p className="text-[11px] text-gray-500 font-mono">
                Maximum rows kept before the oldest data is pruned. Applies to real ingested data only.
              </p>
            </div>
          </div>

          {retentionMsg && (
            <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs font-mono ${retentionMsg.kind === 'ok' ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' : 'border-rose-800 bg-rose-950/40 text-rose-300'}`}>
              {retentionMsg.kind === 'ok' ? <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" /> : <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />}
              <span>{retentionMsg.text}</span>
            </div>
          )}

          {([
            ['alertRetention', 'Alerts', 'Max alert records retained'],
            ['telemetryRetention', 'Telemetry points', 'Max telemetry samples retained'],
            ['analysisRetention', 'Analysis runs', 'Max log-analysis runs retained'],
          ] as const).map(([key, label, hint]) => (
            <label key={key} className="block">
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">{label}</span>
              <input
                type="number"
                min={0} max={1000000} step={100}
                value={retentionDraft[key]}
                onChange={(e) => setRetentionDraft({ ...retentionDraft, [key]: Number(e.target.value) })}
                className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-cyan-500"
              />
              <span className="text-[10px] text-gray-600 font-mono">{hint} (0 = unlimited)</span>
            </label>
          ))}

          <button
            onClick={handleSaveRetention}
            disabled={busy}
            className="flex items-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 px-4 py-2 text-xs font-mono font-bold text-white transition cursor-pointer"
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
            Save Retention Settings
          </button>
        </div>
      )}

      {/* Gemini tab */}
      {tab === 'gemini' && (
        <div className="rounded-2xl border border-gray-800 bg-gray-950 p-5 max-w-2xl space-y-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <ServerCog className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-mono text-sm font-bold text-gray-100 uppercase">Gemini AI API Key</h3>
              <p className="text-[11px] text-gray-500 font-mono">
                Enables LLM-powered triage, chat, NL→rules, phishing analysis, and CTF hints.
                Falls back to the deterministic engines when unset.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-mono w-fit"
            style={{ borderColor: settings?.geminiConfigured ? '#059669' : '#374151', color: settings?.geminiConfigured ? '#34d399' : '#9ca3af' }}>
            <span className={`h-2 w-2 rounded-full ${settings?.geminiConfigured ? 'bg-emerald-400 animate-pulse' : 'bg-gray-600'}`} />
            {settings?.geminiConfigured ? 'Gemini API key configured and active' : 'No Gemini key — deterministic fallbacks in use'}
          </div>

          {geminiMsg && (
            <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs font-mono ${geminiMsg.kind === 'ok' ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' : 'border-rose-800 bg-rose-950/40 text-rose-300'}`}>
              {geminiMsg.kind === 'ok' ? <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" /> : <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />}
              <span>{geminiMsg.text}</span>
            </div>
          )}

          <div>
            <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">New API key (or blank to clear)</span>
            <div className="mt-1 flex gap-2">
              <input
                type={showKey ? 'text' : 'password'}
                value={geminiKey}
                onChange={(e) => setGeminiKey(e.target.value)}
                autoComplete="off" spellCheck={false} maxLength={512}
                placeholder={settings?.geminiConfigured ? '•••••••••••• (leave blank to keep current)' : 'AIza…'}
                className="flex-1 rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-cyan-500"
              />
              <button
                type="button"
                onClick={() => setShowKey(!showKey)}
                className="rounded-lg border border-gray-700 bg-gray-900 px-3 text-gray-400 hover:text-gray-200 transition cursor-pointer"
                title={showKey ? 'Hide key' : 'Show key'}
              >
                {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            <span className="text-[10px] text-gray-600 font-mono">Stored server-side; never returned to clients. Effective immediately.</span>
          </div>

          <div className="flex gap-2">
            <button
              onClick={handleSaveGemini}
              disabled={busy}
              className="flex items-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 px-4 py-2 text-xs font-mono font-bold text-white transition cursor-pointer"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              Save API Key
            </button>
            {settings?.geminiConfigured && (
              <button
                onClick={() => { setGeminiKey(''); handleSaveGemini(); }}
                disabled={busy}
                className="flex items-center gap-2 rounded-lg border border-rose-800 bg-rose-950/40 hover:bg-rose-950 px-4 py-2 text-xs font-mono font-bold text-rose-300 transition cursor-pointer"
              >
                <Trash2 className="h-4 w-4" />
                Clear Key
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};