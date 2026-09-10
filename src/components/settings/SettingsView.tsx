import React, { useEffect, useState } from 'react';
import {
  Users, HardDrive, KeyRound, ShieldAlert, Loader2, Plus, Trash2,
  CheckCircle2, AlertTriangle, ServerCog, Save, Eye, EyeOff, KeyRound as KeyIcon, UserX, X,
  Mail, Link2, Copy, Ban, ShieldCheck, ScrollText, Pencil, Check,
} from 'lucide-react';
import { api } from '../../services/api';
import { ManagedUser, AppSettings, UserSession, InviteRecord, AuditEntry } from '../../types';

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

type Tab = 'users' | 'invites' | 'retention' | 'security' | 'gemini' | 'audit';

const ACTION_LABELS: Record<string, string> = {
  'auth.login': 'Login',
  'auth.logout': 'Logout',
  'auth.changePassword': 'Password change',
  'auth.expiredPassword': 'Expired-password rotation',
  'users.create': 'User created',
  'users.updateRole': 'Role changed',
  'users.delete': 'User deleted',
  'users.resetPassword': 'Password reset',
  'invites.create': 'Invite created',
  'invites.revoke': 'Invite revoked',
  'invites.accept': 'Invite accepted',
  'settings.update': 'Settings updated',
  'alert.create': 'Alert created',
  'alert.triage': 'Alert triaged',
  'ctf.flag': 'CTF flag',
  'ctf.hint': 'CTF hint',
  'training.complete': 'Lesson completed',
  'analysis.run': 'Log analysis',
};

export const SettingsView: React.FC<{ user: UserSession | null }> = ({ user }) => {
  const [tab, setTab] = useState<Tab>('users');

  // -- User management -------------------------------------------------------
  const [users, setUsers] = useState<ManagedUser[]>([]);
  const [newUser, setNewUser] = useState({ username: '', name: '', password: '', role: 'analyst' as ManagedUser['role'] });
  const [userMsg, setUserMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [resetTarget, setResetTarget] = useState<ManagedUser | null>(null);
  const [resetPassword, setResetPassword] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<ManagedUser | null>(null);
  const [roleEditTarget, setRoleEditTarget] = useState<ManagedUser | null>(null);
  const [roleDraft, setRoleDraft] = useState<ManagedUser['role']>('viewer');

  // -- Invitations ------------------------------------------------------------
  const [invites, setInvites] = useState<InviteRecord[]>([]);
  const [inviteForm, setInviteForm] = useState({ email: '', name: '', role: 'analyst' as ManagedUser['role'] });
  const [inviteMsg, setInviteMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [inviteLink, setInviteLink] = useState<string | null>(null);

  // -- Log retention ----------------------------------------------------------
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [retentionDraft, setRetentionDraft] = useState({ alertRetention: 2000, telemetryRetention: 2000, analysisRetention: 500 });
  const [retentionMsg, setRetentionMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  // -- Password policy (Security tab) ------------------------------------------
  const [policyDraft, setPolicyDraft] = useState(90);
  const [policyMsg, setPolicyMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [changePw, setChangePw] = useState({ old: '', next: '', next2: '' });
  const [changePwMsg, setChangePwMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  // -- Audit trail --------------------------------------------------------------
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [auditMsg, setAuditMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  // -- Gemini -------------------------------------------------------------------
  const [geminiKey, setGeminiKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [geminiMsg, setGeminiMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (user?.role !== 'admin') return;
    refreshUsers();
    refreshSettings();
    refreshInvites();
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
      setPolicyDraft(s.passwordMaxAgeDays);
    } catch (err) {
      console.error(err);
    }
  };

  const refreshInvites = async () => {
    try {
      setInvites(await api.listInvites());
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

  const handleSaveRole = async () => {
    if (!roleEditTarget) return;
    setBusy(true);
    setUserMsg(null);
    try {
      await api.updateUserRole(roleEditTarget.id, roleDraft);
      setUserMsg({ kind: 'ok', text: `Role updated: @${roleEditTarget.username} is now ${roleDraft}.` });
      setRoleEditTarget(null);
      await refreshUsers();
    } catch (err: any) {
      const msg = err?.message || '';
      setUserMsg({
        kind: 'err',
        text: msg.includes('last admin')
          ? 'Cannot demote the last admin account.'
          : msg.includes('own role')
            ? 'You cannot change your own role.'
            : 'Failed to update role — check the server.',
      });
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

  const handleCreateInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setInviteMsg(null);
    setInviteLink(null);
    try {
      const { invite, setupToken } = await api.createInvite(inviteForm);
      setInviteMsg({ kind: 'ok', text: `Invite for ${invite.email} created (${invite.role}, expires ${new Date(invite.expiresAt).toLocaleDateString()}).` });
      setInviteLink(`${window.location.origin}${window.location.pathname}?invite=${setupToken}`);
      setInviteForm({ email: '', name: '', role: 'analyst' });
      await refreshInvites();
    } catch (err) {
      console.error(err);
      setInviteMsg({ kind: 'err', text: 'Failed to create invite — check the server.' });
    } finally {
      setBusy(false);
    }
  };

  const handleRevokeInvite = async (id: string) => {
    setBusy(true);
    setInviteMsg(null);
    try {
      await api.revokeInvite(id);
      setInviteMsg({ kind: 'ok', text: 'Invite revoked — the setup link no longer works.' });
      await refreshInvites();
    } catch (err) {
      console.error(err);
      setInviteMsg({ kind: 'err', text: 'Failed to revoke invite.' });
    } finally {
      setBusy(false);
    }
  };

  const copyInviteLink = async () => {
    if (!inviteLink) return;
    try {
      await navigator.clipboard.writeText(inviteLink);
      setInviteMsg({ kind: 'ok', text: 'Setup link copied to clipboard.' });
    } catch {
      setInviteMsg({ kind: 'err', text: 'Clipboard unavailable — copy the link manually.' });
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

  const handleSavePolicy = async () => {
    setBusy(true);
    setPolicyMsg(null);
    try {
      const s = await api.updateSettings({ passwordMaxAgeDays: policyDraft });
      setSettings(s);
      setPolicyMsg({ kind: 'ok', text: `Password policy saved: rotation required every ${policyDraft === 0 ? 'never (disabled)' : `${policyDraft} days`}.` });
    } catch (err) {
      console.error(err);
      setPolicyMsg({ kind: 'err', text: 'Failed to save password policy.' });
    } finally {
      setBusy(false);
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setChangePwMsg(null);
    if (changePw.next !== changePw.next2) {
      setChangePwMsg({ kind: 'err', text: 'New passwords do not match.' });
      return;
    }
    setBusy(true);
    try {
      const res = await api.changePassword(changePw.old, changePw.next);
      if (res.ok) {
        setChangePwMsg({ kind: 'ok', text: 'Password changed. New credentials are effective immediately.' });
        setChangePw({ old: '', next: '', next2: '' });
      } else {
        setChangePwMsg({ kind: 'err', text: res.error || 'Failed to change password.' });
      }
    } catch {
      setChangePwMsg({ kind: 'err', text: 'Unable to reach the server.' });
    } finally {
      setBusy(false);
    }
  };

  const loadAudit = async () => {
    setAuditMsg(null);
    try {
      setAudit(await api.getAuditLog(200));
    } catch (err) {
      console.error(err);
      setAuditMsg({ kind: 'err', text: 'Failed to load the audit trail.' });
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

  // Live audit trail: initial fetch + SSE `audit:entry` stream (server broadcasts
  // every security-relevant action; the viewer prepends new entries live).
  useEffect(() => {
    if (tab !== 'audit' || user?.role !== 'admin') return;
    loadAudit();
    const sse = api.getTelemetryEventSource();
    const onMessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'audit:entry' && data.entry) {
          setAudit(prev => [data.entry, ...prev].slice(0, 300));
        }
      } catch {
        /* ignore non-JSON frames */
      }
    };
    sse.addEventListener('audit:entry', onMessage);
    return () => {
      sse.removeEventListener('audit:entry', onMessage);
      sse.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, user?.role]);

  if (user?.role !== 'admin') {
    return (
      <div className="rounded-2xl border border-gray-800 bg-gray-950 p-8 text-center">
        <ShieldAlert className="h-10 w-10 text-rose-400 mx-auto mb-3" />
        <h3 className="font-mono text-sm font-bold text-gray-100 uppercase">Admin access required</h3>
        <p className="text-xs text-gray-400 mt-2 max-w-md mx-auto">
          User management, invitations, retention, password policy, AI key configuration, and the audit trail are restricted to the platform administrator.
        </p>
      </div>
    );
  }

  const tabs: Array<{ id: Tab; label: string; icon: any }> = [
    { id: 'users', label: 'User Management', icon: Users },
    { id: 'invites', label: 'Invitations', icon: Mail },
    { id: 'retention', label: 'Log Retention', icon: HardDrive },
    { id: 'security', label: 'Security', icon: ShieldCheck },
    { id: 'gemini', label: 'Gemini API', icon: KeyRound },
    { id: 'audit', label: 'Audit Trail', icon: ScrollText },
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
                    {roleEditTarget?.id === u.id ? (
                      <div className="flex shrink-0 items-center gap-1.5">
                        <select
                          value={roleDraft}
                          onChange={(e) => setRoleDraft(e.target.value as ManagedUser['role'])}
                          className="rounded-md border border-cyan-700 bg-gray-950 px-1.5 py-1 text-[10px] font-mono outline-none focus:border-cyan-500"
                          autoFocus
                        >
                          {(Object.keys(ROLE_LABELS) as ManagedUser['role'][]).map((r) => (
                            <option key={r} value={r}>{r}</option>
                          ))}
                        </select>
                        <button
                          onClick={handleSaveRole}
                          disabled={busy || isSelf}
                          className="flex items-center gap-1 rounded-md border border-emerald-800 bg-emerald-950/40 px-2 py-1 text-[10px] font-mono text-emerald-300 hover:bg-emerald-950/70 transition-all cursor-pointer disabled:opacity-40"
                          title="Save role"
                        >
                          <Check className="h-3 w-3" /> Save
                        </button>
                        <button
                          onClick={() => setRoleEditTarget(null)}
                          className="rounded-md border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-mono text-gray-400 hover:bg-gray-800 transition-all cursor-pointer"
                        >
                          <X className="h-3 w-3" />
                        </button>
                      </div>
                    ) : (
                      <>
                        <span className={`shrink-0 rounded border px-2 py-0.5 text-[10px] font-mono font-bold uppercase ${ROLE_STYLES[u.role]}`}>
                          {u.role}
                        </span>
                        <span className="shrink-0 rounded bg-amber-950/40 border border-amber-800/60 px-2 py-0.5 text-[10px] font-mono text-amber-300">
                          {u.score} pts
                        </span>
                        <div className="flex shrink-0 items-center gap-1.5">
                          <button
                            onClick={() => { setRoleEditTarget(u); setRoleDraft(u.role); setUserMsg(null); }}
                            disabled={busy || isSelf}
                            className="flex items-center gap-1 rounded-md border border-gray-700 bg-gray-900 px-2 py-1 text-[10px] font-mono text-gray-300 hover:bg-gray-800 transition-all cursor-pointer disabled:opacity-40 disabled:cursor-not-allowed"
                            title={isSelf ? 'You cannot change your own role' : `Change role for ${u.username}`}
                          >
                            <Pencil className="h-3 w-3" />
                            Role
                          </button>
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
                      </>
                    )}
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
                      placeholder="New password (min 8 chars, upper+lower+digit+special)"
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

      {/* Invitations tab */}
      {tab === 'invites' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <form onSubmit={handleCreateInvite} className="rounded-2xl border border-gray-800 bg-gray-950 p-5 space-y-3 h-fit">
            <h3 className="flex items-center gap-2 font-mono text-sm font-bold text-gray-100 uppercase">
              <Mail className="h-4 w-4 text-cyan-400" /> Invite by Email
            </h3>
            <p className="text-[11px] text-gray-500 font-mono">
              Creates a one-time setup link (valid 7 days). The invitee sets their own username and password;
              the token is hashed server-side and can be revoked at any time.
            </p>

            {inviteMsg && (
              <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs font-mono ${inviteMsg.kind === 'ok' ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' : 'border-rose-800 bg-rose-950/40 text-rose-300'}`}>
                {inviteMsg.kind === 'ok' ? <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" /> : <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />}
                <span>{inviteMsg.text}</span>
              </div>
            )}

            {inviteLink && (
              <div className="rounded-lg border border-cyan-800/60 bg-cyan-950/20 p-3 space-y-2">
                <div className="flex items-center gap-2 text-[11px] font-mono font-bold text-cyan-300 uppercase">
                  <Link2 className="h-3.5 w-3.5" /> One-time setup link
                </div>
                <div className="flex gap-2">
                  <input
                    readOnly value={inviteLink}
                    onFocus={(e) => e.target.select()}
                    className="flex-1 rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-[11px] font-mono text-emerald-300 outline-none"
                  />
                  <button
                    type="button"
                    onClick={copyInviteLink}
                    className="flex items-center gap-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-3 py-2 text-[11px] font-mono font-bold text-white transition cursor-pointer"
                  >
                    <Copy className="h-3.5 w-3.5" /> Copy
                  </button>
                </div>
                <p className="text-[10px] text-gray-500 font-mono">
                  Send this link to the invitee. It works once and expires after 7 days.
                </p>
              </div>
            )}

            <label className="block">
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">Email</span>
              <input
                type="email" required maxLength={254}
                value={inviteForm.email}
                onChange={(e) => setInviteForm({ ...inviteForm, email: e.target.value })}
                className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-cyan-500"
                placeholder="new.analyst@company.com"
              />
            </label>
            <label className="block">
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">Name (optional)</span>
              <input
                maxLength={120}
                value={inviteForm.name}
                onChange={(e) => setInviteForm({ ...inviteForm, name: e.target.value })}
                className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-cyan-500"
                placeholder="Jane Smith"
              />
            </label>
            <label className="block">
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">Role</span>
              <select
                value={inviteForm.role}
                onChange={(e) => setInviteForm({ ...inviteForm, role: e.target.value as ManagedUser['role'] })}
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
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Mail className="h-4 w-4" />}
              Create Invite Link
            </button>
          </form>

          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-5">
            <h3 className="flex items-center gap-2 font-mono text-sm font-bold text-gray-100 uppercase mb-3">
              <Mail className="h-4 w-4 text-cyan-400" /> Pending Invites ({invites.filter((i) => !i.consumedAt && !i.revoked).length})
            </h3>
            <div className="space-y-2">
              {invites.length === 0 && (
                <p className="text-xs text-gray-500 font-mono">No invites yet.</p>
              )}
              {invites.map((inv) => {
                const pending = !inv.consumedAt && !inv.revoked;
                const expired = pending && new Date(inv.expiresAt) < new Date();
                return (
                  <div key={inv.id} className="flex items-center gap-3 rounded-lg border border-gray-800 bg-gray-900/50 px-3 py-2.5">
                    <div className={`flex h-8 w-8 items-center justify-center rounded-full font-mono text-[11px] font-bold border shrink-0 ${pending ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : 'bg-gray-900 text-gray-500 border-gray-700'}`}>
                      {inv.email.slice(0, 2).toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-mono text-xs font-bold text-gray-100 truncate">{inv.name || inv.email}</p>
                      <p className="text-[10px] font-mono text-gray-500 truncate">
                        {inv.email} · <span className="uppercase">{inv.role}</span>
                      </p>
                    </div>
                    <span className={`shrink-0 rounded border px-2 py-0.5 text-[10px] font-mono font-bold uppercase ${
                      expired ? 'border-rose-800 bg-rose-950/40 text-rose-300'
                      : pending ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300'
                      : inv.consumedAt ? 'border-gray-700 bg-gray-900 text-gray-400' : 'border-rose-900/60 bg-rose-950/30 text-rose-300'
                    }`}>
                      {expired ? 'expired' : pending ? 'pending' : inv.consumedAt ? 'used' : 'revoked'}
                    </span>
                    <span className="shrink-0 text-[10px] font-mono text-gray-500">
                      {new Date(inv.expiresAt).toLocaleDateString()}
                    </span>
                    {pending && (
                      <button
                        onClick={() => handleRevokeInvite(inv.id)}
                        disabled={busy}
                        className="flex shrink-0 items-center gap-1 rounded-md border border-rose-900/60 bg-rose-950/30 px-2 py-1 text-[10px] font-mono text-rose-300 hover:bg-rose-950/60 transition-all cursor-pointer disabled:opacity-50"
                        title="Revoke this invite"
                      >
                        <Ban className="h-3 w-3" />
                        Revoke
                      </button>
                    )}
                  </div>
                );
              })}
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

      {/* Security tab */}
      {tab === 'security' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <div className="rounded-2xl border border-gray-800 bg-gray-950 p-5 space-y-4 h-fit">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div>
                <h3 className="font-mono text-sm font-bold text-gray-100 uppercase">Password Policy</h3>
                <p className="text-[11px] text-gray-500 font-mono">
                  Complexity rules are enforced everywhere (create, reset, self-change, invites).
                  Rotation expiry is a platform setting.
                </p>
              </div>
            </div>

            <ul className="text-[11px] font-mono text-gray-400 space-y-1.5">
              <li>• Minimum 8 characters</li>
              <li>• Requires uppercase, lowercase, digit, and special character</li>
              <li>• Must not contain the username</li>
            </ul>

            {policyMsg && (
              <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs font-mono ${policyMsg.kind === 'ok' ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' : 'border-rose-800 bg-rose-950/40 text-rose-300'}`}>
                {policyMsg.kind === 'ok' ? <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" /> : <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />}
                <span>{policyMsg.text}</span>
              </div>
            )}

            <label className="block">
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">Force rotation every (days)</span>
              <input
                type="number" min={0} max={3650} step={1}
                value={policyDraft}
                onChange={(e) => setPolicyDraft(Number(e.target.value))}
                className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-emerald-500"
              />
              <span className="text-[10px] text-gray-600 font-mono">
                0 = passwords never expire. Users with expired passwords are asked to rotate at sign-in.
              </span>
            </label>

            <button
              onClick={handleSavePolicy}
              disabled={busy}
              className="flex items-center gap-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 px-4 py-2 text-xs font-mono font-bold text-white transition cursor-pointer"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
              Save Policy
            </button>
          </div>

          <form onSubmit={handleChangePassword} className="rounded-2xl border border-gray-800 bg-gray-950 p-5 space-y-3 h-fit">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <KeyIcon className="h-5 w-5" />
              </div>
              <div>
                <h3 className="font-mono text-sm font-bold text-gray-100 uppercase">Change My Password</h3>
                <p className="text-[11px] text-gray-500 font-mono">
                  Applies immediately — your old password stops working.
                </p>
              </div>
            </div>

            {changePwMsg && (
              <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs font-mono ${changePwMsg.kind === 'ok' ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' : 'border-rose-800 bg-rose-950/40 text-rose-300'}`}>
                {changePwMsg.kind === 'ok' ? <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" /> : <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />}
                <span>{changePwMsg.text}</span>
              </div>
            )}

            <label className="block">
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">Current password</span>
              <input
                type="password" required value={changePw.old} autoComplete="current-password"
                onChange={(e) => setChangePw({ ...changePw, old: e.target.value })}
                className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-cyan-500"
              />
            </label>
            <label className="block">
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">New password</span>
              <input
                type="password" required minLength={8} value={changePw.next} autoComplete="new-password"
                onChange={(e) => setChangePw({ ...changePw, next: e.target.value })}
                className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-cyan-500"
                placeholder="min 8 chars, upper+lower+digit+special"
              />
            </label>
            <label className="block">
              <span className="text-[10px] font-mono text-gray-400 uppercase tracking-wider">Confirm new password</span>
              <input
                type="password" required minLength={8} value={changePw.next2} autoComplete="new-password"
                onChange={(e) => setChangePw({ ...changePw, next2: e.target.value })}
                className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono outline-none focus:border-cyan-500"
              />
            </label>

            <button
              type="submit"
              disabled={busy}
              className="flex items-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 px-4 py-2 text-xs font-mono font-bold text-white transition cursor-pointer"
            >
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyIcon className="h-4 w-4" />}
              Change Password
            </button>
          </form>
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

      {/* Audit trail tab */}
      {tab === 'audit' && (
        <div className="rounded-2xl border border-gray-800 bg-gray-950 p-5">
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                <ScrollText className="h-5 w-5" />
              </div>
              <div>
                <h3 className="font-mono text-sm font-bold text-gray-100 uppercase">Audit Trail</h3>
                <p className="text-[11px] text-gray-500 font-mono">
                  Append-only record of security-relevant actions, streamed live over SSE. Never mutated or deleted.
                </p>
              </div>
            </div>
            <button
              onClick={loadAudit}
              disabled={busy}
              className="flex items-center gap-1.5 rounded-lg border border-gray-700 bg-gray-900 px-3 py-1.5 text-[11px] font-mono text-cyan-400 hover:bg-gray-800 transition cursor-pointer disabled:opacity-50"
            >
              {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5" />}
              Refresh
            </button>
          </div>

          {auditMsg && (
            <div className={`flex items-start gap-2 rounded-lg border px-3 py-2 text-xs font-mono mb-3 ${auditMsg.kind === 'ok' ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' : 'border-rose-800 bg-rose-950/40 text-rose-300'}`}>
              {auditMsg.kind === 'ok' ? <CheckCircle2 className="h-4 w-4 shrink-0 mt-0.5" /> : <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />}
              <span>{auditMsg.text}</span>
            </div>
          )}

          <div className="mt-3 rounded-xl border border-gray-800 overflow-hidden">
            <table className="w-full text-left">
              <thead>
                <tr className="bg-gray-900/80 text-[10px] font-mono uppercase tracking-wider text-gray-500">
                  <th className="px-3 py-2">Time</th>
                  <th className="px-3 py-2">Actor</th>
                  <th className="px-3 py-2">Action</th>
                  <th className="px-3 py-2">Resource</th>
                  <th className="px-3 py-2">Result</th>
                  <th className="px-3 py-2">IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60">
                {audit.length === 0 && (
                  <tr>
                    <td colSpan={6} className="px-3 py-6 text-center text-xs font-mono text-gray-500">
                      No audit entries yet. Actions appear here live as they happen.
                    </td>
                  </tr>
                )}
                {audit.slice(0, 100).map((entry) => (
                  <tr key={entry.id} className="bg-gray-950/40 hover:bg-gray-900/60 transition">
                    <td className="px-3 py-2 text-[10px] font-mono text-gray-500 whitespace-nowrap">
                      {new Date(entry.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-3 py-2 text-[11px] font-mono text-gray-200 whitespace-nowrap">
                      {entry.actorName}
                      <span className="ml-1.5 text-[9px] uppercase text-gray-500">{entry.actorRole}</span>
                    </td>
                    <td className="px-3 py-2 text-[11px] font-mono text-cyan-300 whitespace-nowrap">
                      {ACTION_LABELS[entry.action] ?? entry.action}
                      {entry.detail && (
                        <span className="block text-[9px] text-gray-500 font-mono mt-0.5">{entry.detail}</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-[11px] font-mono text-gray-400">{entry.resource}</td>
                    <td className="px-3 py-2">
                      <span className={`rounded border px-1.5 py-0.5 text-[9px] font-mono font-bold uppercase ${entry.outcome === 'allowed' ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300' : 'border-rose-800 bg-rose-950/40 text-rose-300'}`}>
                        {entry.outcome}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-[10px] font-mono text-gray-500">{entry.ip}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};