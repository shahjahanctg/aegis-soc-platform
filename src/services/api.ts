import { Alert, IOC, Course, PhishingCampaign, CTFChallenge, CTFLeaderboardEntry, DFIRTimelineEvent, DFIRArtifact, TelemetryPoint, SensorStatus, UserSession, AnomalyResult, CorrelationResult, AnalysisRun, AnalysisRunSummary, AnalysisRunDetail, ManagedUser, AppSettings } from '../types';
import { useAuthStore, getAuthState } from '../stores/authStore';

// ---------------------------------------------------------------------------
// Authenticated fetch wrapper: attaches JWT, transparently refreshes expired
// access tokens once on 401, and notifies the app when the session is dead.
// ---------------------------------------------------------------------------

let refreshInFlight: Promise<boolean> | null = null;

async function tryRefresh(): Promise<boolean> {
  const { refreshToken, setAuth, clearAuth } = getAuthState();
  if (!refreshToken) return false;

  // Coalesce concurrent refresh attempts into one request
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const res = await fetch('/api/auth/refresh', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refreshToken }),
        });
        if (!res.ok) return false;
        const data = await res.json();
        setAuth({ accessToken: data.accessToken, user: data.user });
        return true;
      } catch {
        return false;
      } finally {
        setTimeout(() => { refreshInFlight = null; }, 0);
      }
    })();
  }

  const ok = await refreshInFlight;
  if (!ok) clearAuth();
  return ok;
}

async function authedFetch(path: string, init: RequestInit = {}, retried = false): Promise<Response> {
  const { accessToken } = getAuthState();
  const headers = new Headers(init.headers || {});
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');

  const res = await fetch(path, { ...init, headers });
  if (res.status === 401 && !retried && !path.startsWith('/api/auth/login')) {
    const refreshed = await tryRefresh();
    if (refreshed) return authedFetch(path, init, true);
    window.dispatchEvent(new CustomEvent('aegis:unauthorized'));
  }
  return res;
}

async function jsonOrThrow<T>(res: Response, fallback: T): Promise<T> {
  try {
    return await res.json() as T;
  } catch {
    return fallback;
  }
}

export const api = {
  // ---------------------------------------------------------------------------
  // Auth
  // ---------------------------------------------------------------------------
  async login(username: string, password: string): Promise<{ ok: boolean; error?: string; user?: UserSession }> {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const err = await jsonOrThrow<{ error?: string }>(res, {});
      return { ok: false, error: err.error || 'Login failed' };
    }
    const data = await res.json();
    useAuthStore.getState().setAuth({ accessToken: data.accessToken, refreshToken: data.refreshToken, user: data.user });
    return { ok: true, user: data.user };
  },

  async logout(): Promise<void> {
    try {
      await authedFetch('/api/auth/logout', { method: 'POST' });
    } catch {
      // best-effort; clear locally regardless
    }
    useAuthStore.getState().clearAuth();
  },

  async getCurrentUser(): Promise<{ user: UserSession }> {
    const res = await authedFetch('/api/auth/me');
    return jsonOrThrow(res, { user: getAuthState().user! });
  },

  // ---------------------------------------------------------------------------
  // Telemetry SSE (EventSource cannot send headers → token in query string)
  // ---------------------------------------------------------------------------
  getTelemetryEventSource(): EventSource {
    const { accessToken } = getAuthState();
    const url = accessToken ? `/api/telemetry/stream?token=${encodeURIComponent(accessToken)}` : '/api/telemetry/stream';
    return new EventSource(url);
  },

  // ---------------------------------------------------------------------------
  // Alerts
  // ---------------------------------------------------------------------------
  async getAlerts(params?: { severity?: string; status?: string; search?: string }): Promise<{
    alerts: Alert[];
    total: number;
    stats: { critical: number; high: number; medium: number; low: number; new: number; investigating: number; resolved: number };
  }> {
    const query = new URLSearchParams();
    if (params?.severity) query.append('severity', params.severity);
    if (params?.status) query.append('status', params.status);
    if (params?.search) query.append('search', params.search);
    const res = await authedFetch(`/api/alerts?${query.toString()}`);
    return jsonOrThrow(res, { alerts: [], total: 0, stats: { critical: 0, high: 0, medium: 0, low: 0, new: 0, investigating: 0, resolved: 0 } });
  },

  async getAlertById(id: string): Promise<Alert> {
    const res = await authedFetch(`/api/alerts/${id}`);
    return jsonOrThrow(res, {} as Alert);
  },

  async triageAlert(id: string, update: { status?: string; triage_notes?: string; analyst?: string }): Promise<Alert> {
    const res = await authedFetch(`/api/alerts/${id}/triage`, {
      method: 'PATCH',
      body: JSON.stringify(update),
    });
    return jsonOrThrow(res, {} as Alert);
  },

  async convertAlertToCTF(id: string): Promise<{ success: boolean; challenge: CTFChallenge }> {
    const res = await authedFetch(`/api/alerts/${id}/convert-to-ctf`, { method: 'POST' });
    return jsonOrThrow(res, { success: false } as any);
  },

  // ---------------------------------------------------------------------------
  // Threat Intel
  // ---------------------------------------------------------------------------
  async getIOCs(): Promise<{ iocs: IOC[]; totalCount: number; blockedCount: number }> {
    const res = await authedFetch('/api/threat-intel/iocs');
    return jsonOrThrow(res, { iocs: [], totalCount: 0, blockedCount: 0 });
  },

  async toggleBlockIOC(id: string): Promise<IOC> {
    const res = await authedFetch(`/api/threat-intel/iocs/${id}/toggle-block`, { method: 'PATCH' });
    return jsonOrThrow(res, {} as IOC);
  },

  async addIOC(data: Partial<IOC>): Promise<IOC> {
    const res = await authedFetch('/api/threat-intel/iocs/add', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return jsonOrThrow(res, {} as IOC);
  },

  // ---------------------------------------------------------------------------
  // Telemetry
  // ---------------------------------------------------------------------------
  async getTelemetry(): Promise<{ history: TelemetryPoint[]; current: TelemetryPoint; sensors: SensorStatus[] }> {
    const res = await authedFetch('/api/telemetry');
    return jsonOrThrow(res, { history: [], current: undefined as any, sensors: [] });
  },

  // Telemetry & event ingestion (machine forwarders should use x-api-key instead)
  async ingestTelemetry(payload: unknown): Promise<{ status: string; eventsReceived: number; alertGenerated: boolean; alertId?: string }> {
    const res = await authedFetch('/api/telemetry/ingest', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    return jsonOrThrow(res, { status: 'error', eventsReceived: 0, alertGenerated: false });
  },

  // ---------------------------------------------------------------------------
  // Training
  // ---------------------------------------------------------------------------
  async getCourses(): Promise<Course[]> {
    const res = await authedFetch('/api/training/courses');
    return jsonOrThrow(res, []);
  },

  async completeLesson(courseId: string, lessonId: string): Promise<{ success: boolean; courseProgress: number }> {
    const res = await authedFetch(`/api/training/courses/${courseId}/lessons/${lessonId}/complete`, { method: 'POST' });
    return jsonOrThrow(res, { success: false, courseProgress: 0 });
  },

  async getPhishingCampaigns(): Promise<PhishingCampaign[]> {
    const res = await authedFetch('/api/training/phishing/campaigns');
    return jsonOrThrow(res, []);
  },

  async launchPhishingCampaign(data: { name: string; template: string; targetCount: number }): Promise<PhishingCampaign> {
    const res = await authedFetch('/api/training/phishing/launch', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return jsonOrThrow(res, {} as PhishingCampaign);
  },

  // ---------------------------------------------------------------------------
  // CTF
  // ---------------------------------------------------------------------------
  async getCTFChallenges(): Promise<CTFChallenge[]> {
    const res = await authedFetch('/api/ctf/challenges');
    return jsonOrThrow(res, []);
  },

  async unlockHint(challengeId: string): Promise<{ hint: string; penalty: number }> {
    const res = await authedFetch(`/api/ctf/challenges/${challengeId}/unlock-hint`, { method: 'POST' });
    return jsonOrThrow(res, { hint: '', penalty: 0 });
  },

  async submitFlag(challengeId: string, flag: string, username?: string): Promise<{ success: boolean; message: string; pointsAwarded?: number; newScore?: number; challenge?: CTFChallenge }> {
    const res = await authedFetch(`/api/ctf/challenges/${challengeId}/submit`, {
      method: 'POST',
      body: JSON.stringify({ flag, username }),
    });
    return jsonOrThrow(res, { success: false, message: 'Submission failed' });
  },

  async getCTFLeaderboard(): Promise<CTFLeaderboardEntry[]> {
    const res = await authedFetch('/api/ctf/leaderboard');
    return jsonOrThrow(res, []);
  },

  async getLeaderboard(): Promise<CTFLeaderboardEntry[]> {
    return this.getCTFLeaderboard();
  },

  // ---------------------------------------------------------------------------
  // DFIR
  // ---------------------------------------------------------------------------
  async getDFIRTimeline(): Promise<DFIRTimelineEvent[]> {
    const res = await authedFetch('/api/dfir/timeline');
    return jsonOrThrow(res, []);
  },

  async getDFIRArtifacts(): Promise<DFIRArtifact[]> {
    const data = await this.getDFIRTimeline();
    return (data || []).map(d => ({
      id: d.id,
      timestamp: d.timestamp,
      source: d.source,
      eventType: `${d.artifact} - ${d.action}`,
      description: d.details,
      host: d.system,
      rawPayload: JSON.stringify(d, null, 2),
      hash: d.isMalicious ? 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' : undefined,
      isEvidence: d.isMalicious,
    }));
  },

  async addDFIREvent(event: Partial<DFIRTimelineEvent>): Promise<DFIRTimelineEvent> {
    const res = await authedFetch('/api/dfir/timeline/add', {
      method: 'POST',
      body: JSON.stringify(event),
    });
    return jsonOrThrow(res, {} as DFIRTimelineEvent);
  },

  // ---------------------------------------------------------------------------
  // AI Module
  // ---------------------------------------------------------------------------
  async sendAIChat(message: string, contextAlertId?: string): Promise<{ reply: string }> {
    const res = await authedFetch('/api/ai/chat', {
      method: 'POST',
      body: JSON.stringify({ message, contextAlertId }),
    });
    return jsonOrThrow(res, { reply: '' });
  },

  async askAICopilot(message: string, context?: any): Promise<{ reply: string }> {
    const res = await authedFetch('/api/ai/chat', {
      method: 'POST',
      body: JSON.stringify({ message, context }),
    });
    return jsonOrThrow(res, { reply: '' });
  },

  async getAITriage(alertId: string): Promise<{
    classification: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'SUSPICIOUS';
    confidence: number;
    reasoning: string;
    recommendedAction: string;
  }> {
    const res = await authedFetch('/api/ai/triage', {
      method: 'POST',
      body: JSON.stringify({ alertId }),
    });
    return jsonOrThrow(res, { classification: 'SUSPICIOUS', confidence: 0, reasoning: '', recommendedAction: '' });
  },

  async nlToRules(prompt: string, ruleFormat: 'sigma' | 'yara' | 'suricata'): Promise<{ rule: string; format: string }> {
    const res = await authedFetch('/api/ai/nl-to-rules', {
      method: 'POST',
      body: JSON.stringify({ prompt, ruleFormat }),
    });
    return jsonOrThrow(res, { rule: '', format: ruleFormat });
  },

  async analyzePhishingEmail(rawEmail: string): Promise<{
    riskScore: number;
    verdict: string;
    spfCheck: string;
    dkimCheck: string;
    dmarcCheck: string;
    indicators: string[];
    recommendedAction: string;
  }> {
    const res = await authedFetch('/api/ai/phishing-analyze', {
      method: 'POST',
      body: JSON.stringify({ rawEmail }),
    });
    return jsonOrThrow(res, { riskScore: 0, verdict: 'Analysis unavailable', spfCheck: 'NONE', dkimCheck: 'NONE', dmarcCheck: 'NONE', indicators: [], recommendedAction: '' });
  },

  async detectAnomalies(opts?: { window?: number; sensitivity?: number }): Promise<AnomalyResult> {
    const res = await authedFetch('/api/ai/anomaly', {
      method: 'POST',
      body: JSON.stringify(opts ?? {}),
    });
    return jsonOrThrow(res, {
      window: 0, analyzedPoints: 0, sensitivity: 2, baseline: {}, anomalies: [], summary: 'Anomaly analysis unavailable', riskLevel: 'low',
    } as AnomalyResult);
  },

  async correlateAlerts(opts?: { windowMinutes?: number }): Promise<CorrelationResult> {
    const res = await authedFetch('/api/ai/correlate', {
      method: 'POST',
      body: JSON.stringify(opts ?? {}),
    });
    return jsonOrThrow(res, { windowMinutes: 60, analyzedAlerts: 0, clusters: [], summary: 'Correlation unavailable' } as CorrelationResult);
  },

  async getAICtfHint(challengeId: string): Promise<{ hint: string; source: string }> {
    const res = await authedFetch('/api/ai/ctf-hint', {
      method: 'POST',
      body: JSON.stringify({ challengeId }),
    });
    return jsonOrThrow(res, { hint: '', source: 'builtin' });
  },

  // ---------------------------------------------------------------------------
  // Log & data analysis (paste / edit / upload log files)
  // ---------------------------------------------------------------------------
  async analyzeLog(content: string, opts?: { source?: string; createAlerts?: boolean }): Promise<AnalysisRun> {
    const params = new URLSearchParams();
    if (opts?.source) params.set('source', opts.source.slice(0, 200));
    params.set('createAlerts', opts?.createAlerts === false ? '0' : '1');
    const res = await authedFetch(`/api/analysis/ingest?${params.toString()}`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: content,
    });
    return jsonOrThrow(res, {} as AnalysisRun);
  },

  async getAnalysisRuns(limit = 10): Promise<{ runs: AnalysisRunSummary[] }> {
    const res = await authedFetch(`/api/analysis/runs?limit=${limit}`);
    return jsonOrThrow(res, { runs: [] });
  },

  async getAnalysisRun(id: string): Promise<AnalysisRunDetail> {
    const res = await authedFetch(`/api/analysis/runs/${encodeURIComponent(id)}`);
    return jsonOrThrow(res, {} as AnalysisRunDetail);
  },

  // ---------------------------------------------------------------------------
  // User management (admin) + platform settings
  // ---------------------------------------------------------------------------
  async listUsers(): Promise<ManagedUser[]> {
    const res = await authedFetch('/api/users');
    const data = await jsonOrThrow<{ users?: ManagedUser[] }>(res, {});
    return data.users ?? [];
  },

  async createUser(input: { username: string; name: string; password: string; role: ManagedUser['role'] }): Promise<ManagedUser> {
    const res = await authedFetch('/api/users', {
      method: 'POST',
      body: JSON.stringify(input),
    });
    return jsonOrThrow(res, {} as ManagedUser);
  },

  async getSettings(): Promise<AppSettings> {
    const res = await authedFetch('/api/settings');
    const data = await jsonOrThrow<{ settings?: AppSettings }>(res, {});
    return data.settings ?? { alertRetention: 2000, telemetryRetention: 2000, analysisRetention: 500, geminiConfigured: false };
  },

  async updateSettings(patch: Partial<AppSettings> & { geminiApiKey?: string | null }): Promise<AppSettings> {
    const res = await authedFetch('/api/settings', {
      method: 'PUT',
      body: JSON.stringify(patch),
    });
    const data = await jsonOrThrow<{ settings?: AppSettings }>(res, {});
    return data.settings ?? ({} as AppSettings);
  },
};
