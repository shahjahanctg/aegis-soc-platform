import crypto from 'crypto';
import { Pool } from 'pg';
import { addAlertBounded, MAX_ALERTS } from './alertsStore';
import type { SafeUser } from './security';
import type { AuditEntry } from './audit';
import {
  seedAlerts, seedIocs, seedCourses, seedPhishingCampaigns,
  seedCtfChallenges, seedCtfLeaderboard, seedDfirTimeline, makeSeedTelemetry,
} from './seed';
import type {
  AlertItem, IOCItem, CourseItem, CourseLesson, PhishingCampaignItem,
  CTFChallengeItem, LeaderboardEntry, DFIRTimelineEvent, TelemetryPoint,
} from './types';

// ---------------------------------------------------------------------------
// Persistence layer. createStore() returns:
//   - PostgresStore when DATABASE_URL is set (production / docker-compose)
//   - MemoryStore otherwise (zero-dependency local dev)
// Both implement the same Store interface, so route handlers are agnostic.
// ---------------------------------------------------------------------------

export interface AlertFilter {
  severity?: string;
  status?: string;
  search?: string;
}

export interface AlertStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  new: number;
  investigating: number;
  resolved: number;
}

export interface AlertListResult {
  alerts: AlertItem[];
  total: number;
  stats: AlertStats;
}

export interface TelemetrySummary {
  history: TelemetryPoint[];
  current: TelemetryPoint | null;
}

export interface FlagSubmitResult {
  success: boolean;
  message: string;
  alreadySolved?: boolean;
  pointsAwarded?: number;
  newScore?: number;
  challengeId?: string;
  challengeTitle?: string;
}

export interface Store {
  readonly kind: 'memory' | 'postgres';
  health(): Promise<boolean>;
  close(): Promise<void>;
  // users
  verifyPassword(username: string, password: string): Promise<SafeUser | null>;
  findUserById(id: string): Promise<SafeUser | null>;
  // audit
  recordAudit(entry: AuditEntry): Promise<void>;
  getAuditLog(limit: number): Promise<AuditEntry[]>;
  // alerts
  listAlerts(filter: AlertFilter): Promise<AlertListResult>;
  getAlert(id: string): Promise<AlertItem | null>;
  createAlert(alert: AlertItem): Promise<AlertItem>;
  updateAlert(id: string, patch: Partial<AlertItem>): Promise<AlertItem | null>;
  // iocs
  listIocs(): Promise<IOCItem[]>;
  addIoc(ioc: IOCItem): Promise<IOCItem>;
  toggleIocBlock(id: string): Promise<IOCItem | null>;
  // telemetry
  getTelemetry(): Promise<TelemetrySummary>;
  appendTelemetry(point: TelemetryPoint): Promise<void>;
  // training (per-user completion state)
  listCoursesForUser(userId: string): Promise<CourseItem[]>;
  completeLesson(userId: string, courseId: string, lessonId: string): Promise<{ lesson: CourseLesson; courseProgress: number } | null>;
  listCampaigns(): Promise<PhishingCampaignItem[]>;
  addCampaign(campaign: PhishingCampaignItem): Promise<PhishingCampaignItem>;
  // ctf (per-user solved / hint state; flags stay server-side)
  listChallengesForUser(userId: string): Promise<CTFChallengeItem[]>;
  getChallenge(id: string): Promise<CTFChallengeItem | null>;
  unlockHint(userId: string, challengeId: string): Promise<{ hint: string; penalty: number; alreadyUnlocked: boolean } | null>;
  submitFlag(userId: string, challengeId: string, submittedFlag: string): Promise<FlagSubmitResult | null>;
  addChallenge(challenge: CTFChallengeItem): Promise<void>;
  getLeaderboard(): Promise<LeaderboardEntry[]>;
  // dfir
  listDfirEvents(): Promise<DFIRTimelineEvent[]>;
  addDfirEvent(event: DFIRTimelineEvent): Promise<DFIRTimelineEvent>;
}

// ---------------------------------------------------------------------------
// Shared user helpers (scrypt hashing + seeded users)
// ---------------------------------------------------------------------------

interface UserRecord extends SafeUser {
  passwordSalt: string;
  passwordHash: string;
  score: number;
}

function scryptHash(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function timingSafeEqualHex(a: string, b: string): boolean {
  return a.length === b.length && crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

export function makeSeedUsers(): UserRecord[] {
  const defs: Array<{ username: string; name: string; password: string; role: SafeUser['role']; badge?: string }> = [
    { username: 'admin', name: 'Platform Administrator', password: process.env.SEED_ADMIN_PASSWORD || 'ChangeMe_Admin_2026!', role: 'admin', badge: 'Commander' },
    { username: 'analyst', name: 'Lead SOC Analyst', password: process.env.SEED_ANALYST_PASSWORD || 'ChangeMe_Analyst_2026!', role: 'analyst', badge: 'Lead Defender' },
    { username: 'trainer', name: 'Training Coordinator', password: process.env.SEED_TRAINER_PASSWORD || 'ChangeMe_Trainer_2026!', role: 'trainer', badge: 'Instructor' },
    { username: 'viewer', name: 'Read-Only Auditor', password: process.env.SEED_VIEWER_PASSWORD || 'ChangeMe_Viewer_2026!', role: 'viewer', badge: 'Observer' },
  ];
  return defs.map((u) => {
    const passwordSalt = crypto.randomBytes(16).toString('hex');
    return {
      id: `usr-${crypto.randomUUID().slice(0, 8)}`,
      username: u.username,
      name: u.name,
      role: u.role,
      badge: u.badge,
      passwordSalt,
      passwordHash: scryptHash(u.password, passwordSalt),
      score: 0,
    };
  });
}

function toSafeUser(u: UserRecord): SafeUser {
  return { id: u.id, username: u.username, name: u.name, role: u.role, badge: u.badge, score: u.score };
}

function emptyStats(): AlertStats {
  return { critical: 0, high: 0, medium: 0, low: 0, new: 0, investigating: 0, resolved: 0 };
}

// ---------------------------------------------------------------------------
// In-memory store (local dev fallback)
// ---------------------------------------------------------------------------

class MemoryStore implements Store {
  readonly kind = 'memory' as const;
  private users: UserRecord[];
  private alerts: AlertItem[];
  private iocs: IOCItem[];
  private courses: CourseItem[];
  private campaigns: PhishingCampaignItem[];
  private challenges: CTFChallengeItem[];
  private leaderboard: LeaderboardEntry[];
  private dfir: DFIRTimelineEvent[];
  private telemetry: TelemetryPoint[];
  private memoryAudit: AuditEntry[] = [];
  // Per-user state (Phase 2)
  private progressKeys = new Set<string>();      // `${userId}:${courseId}:${lessonId}`
  private solveKeys = new Set<string>();         // `${userId}:${challengeId}`
  private hintKeys = new Set<string>();          // `${userId}:${challengeId}`
  private lastSolvedAt = new Map<string, string>(); // `${userId}:${challengeId}` -> ISO timestamp

  constructor() {
    this.users = makeSeedUsers();
    this.alerts = [...seedAlerts];
    this.iocs = [...seedIocs];
    this.courses = [...seedCourses];
    this.campaigns = [...seedPhishingCampaigns];
    this.challenges = [...seedCtfChallenges];
    this.leaderboard = seedCtfLeaderboard.map((e) => ({ ...e }));
    this.dfir = [...seedDfirTimeline];
    this.telemetry = makeSeedTelemetry();
  }

  async health(): Promise<boolean> { return true; }

  async close(): Promise<void> { /* nothing to release */ }

  async verifyPassword(username: string, password: string): Promise<SafeUser | null> {
    const user = this.users.find((u) => u.username === username.toLowerCase());
    if (!user) return null;
    const candidate = scryptHash(password, user.passwordSalt);
    return timingSafeEqualHex(candidate, user.passwordHash) ? toSafeUser(user) : null;
  }

  async findUserById(id: string): Promise<SafeUser | null> {
    const user = this.users.find((u) => u.id === id);
    return user ? toSafeUser(user) : null;
  }

  async recordAudit(entry: AuditEntry): Promise<void> {
    this.memoryAudit.push(entry);
    if (this.memoryAudit.length > 5000) this.memoryAudit.splice(0, this.memoryAudit.length - 5000);
  }

  async getAuditLog(limit: number): Promise<AuditEntry[]> {
    return this.memoryAudit.slice(-Math.min(limit, 5000)).reverse();
  }

  async listAlerts(filter: AlertFilter): Promise<AlertListResult> {
    let filtered = [...this.alerts];
    if (filter.severity && filter.severity !== 'all') filtered = filtered.filter((a) => a.severity === filter.severity);
    if (filter.status && filter.status !== 'all') filtered = filtered.filter((a) => a.status === filter.status);
    if (filter.search) {
      const q = filter.search.toLowerCase();
      filtered = filtered.filter((a) =>
        a.title.toLowerCase().includes(q) ||
        a.description.toLowerCase().includes(q) ||
        a.sourceIp.includes(q) ||
        a.destIp.includes(q) ||
        a.mitreTechnique.toLowerCase().includes(q),
      );
    }
    const stats = emptyStats();
    for (const a of this.alerts) {
      if (a.severity === 'critical') stats.critical++;
      else if (a.severity === 'high') stats.high++;
      else if (a.severity === 'medium') stats.medium++;
      else stats.low++;
      if (a.status === 'new') stats.new++;
      else if (a.status === 'investigating') stats.investigating++;
      else if (a.status === 'resolved') stats.resolved++;
    }
    return { alerts: filtered, total: filtered.length, stats };
  }

  async getAlert(id: string): Promise<AlertItem | null> {
    return this.alerts.find((a) => a.id === id) ?? null;
  }

  async createAlert(alert: AlertItem): Promise<AlertItem> {
    addAlertBounded(this.alerts, alert);
    return alert;
  }

  async updateAlert(id: string, patch: Partial<AlertItem>): Promise<AlertItem | null> {
    const alert = this.alerts.find((a) => a.id === id);
    if (!alert) return null;
    Object.assign(alert, patch, { updated_at: new Date().toISOString() });
    return alert;
  }

  async listIocs(): Promise<IOCItem[]> { return [...this.iocs]; }

  async addIoc(ioc: IOCItem): Promise<IOCItem> {
    this.iocs.unshift(ioc);
    if (this.iocs.length > 500) this.iocs.length = 500;
    return ioc;
  }

  async toggleIocBlock(id: string): Promise<IOCItem | null> {
    const ioc = this.iocs.find((i) => i.id === id);
    if (!ioc) return null;
    ioc.blocked = !ioc.blocked;
    return ioc;
  }

  async getTelemetry(): Promise<TelemetrySummary> {
    const history = [...this.telemetry];
    return { history, current: history[history.length - 1] ?? null };
  }

  async appendTelemetry(point: TelemetryPoint): Promise<void> {
    this.telemetry.push(point);
    if (this.telemetry.length > 30) this.telemetry.shift();
  }

  async listCoursesForUser(userId: string): Promise<CourseItem[]> {
    return this.courses.map((c) => ({
      ...c,
      lessons: c.lessons.map((l) => ({
        ...l,
        completed: this.progressKeys.has(`${userId}:${c.id}:${l.id}`),
      })),
    }));
  }

  async completeLesson(userId: string, courseId: string, lessonId: string) {
    const course = this.courses.find((c) => c.id === courseId);
    if (!course) return null;
    const lesson = course.lessons.find((l) => l.id === lessonId);
    if (!lesson) return null;
    this.progressKeys.add(`${userId}:${courseId}:${lessonId}`);
    const completedCount = course.lessons.filter((l) => this.progressKeys.has(`${userId}:${courseId}:${l.id}`)).length;
    return { lesson: { ...lesson, completed: true }, courseProgress: Math.round((completedCount / course.lessons.length) * 100) };
  }

  async listCampaigns(): Promise<PhishingCampaignItem[]> { return [...this.campaigns]; }

  async addCampaign(campaign: PhishingCampaignItem): Promise<PhishingCampaignItem> {
    this.campaigns.unshift(campaign);
    return campaign;
  }

  async listChallengesForUser(userId: string): Promise<CTFChallengeItem[]> {
    return this.challenges.map((ch) => ({
      ...ch,
      solved: this.solveKeys.has(`${userId}:${ch.id}`),
      hintUnlocked: this.hintKeys.has(`${userId}:${ch.id}`),
    }));
  }

  async getChallenge(id: string): Promise<CTFChallengeItem | null> {
    return this.challenges.find((c) => c.id === id) ?? null;
  }

  async unlockHint(userId: string, challengeId: string) {
    const ch = this.challenges.find((c) => c.id === challengeId);
    if (!ch) return null;
    const key = `${userId}:${challengeId}`;
    const alreadyUnlocked = this.hintKeys.has(key);
    this.hintKeys.add(key);
    return { hint: ch.hint, penalty: ch.hintPenalty, alreadyUnlocked };
  }

  async submitFlag(userId: string, challengeId: string, submittedFlag: string): Promise<FlagSubmitResult | null> {
    const ch = this.challenges.find((c) => c.id === challengeId);
    if (!ch) return null;
    const key = `${userId}:${challengeId}`;

    if (submittedFlag.trim() !== ch.flag) {
      return { success: false, message: 'Incorrect flag. Check formatting (FLAG{...}) and verify extraction.', challengeId, challengeTitle: ch.title };
    }

    const netPoints = this.hintKeys.has(key) ? Math.max(10, ch.points - ch.hintPenalty) : ch.points;

    if (this.solveKeys.has(key)) {
      return {
        success: true, message: 'Flag already solved — no additional points awarded.',
        alreadySolved: true, pointsAwarded: 0, newScore: this.userScore(userId), challengeId, challengeTitle: ch.title,
      };
    }

    this.solveKeys.add(key);
    this.lastSolvedAt.set(key, new Date().toISOString());
    ch.solvesCount += 1; // global stat
    return {
      success: true, message: `Flag Correct! +${netPoints} Points Awarded.`,
      pointsAwarded: netPoints, newScore: this.userScore(userId, netPoints), challengeId, challengeTitle: ch.title,
    };
  }

  private userScore(userId: string, increment = 0): number {
    const u = this.users.find((x) => x.id === userId);
    if (!u) return 0;
    u.score += increment;
    return u.score;
  }

  async addChallenge(challenge: CTFChallengeItem): Promise<void> {
    this.challenges.unshift(challenge);
  }

  private rankEntries(entries: LeaderboardEntry[]): LeaderboardEntry[] {
    entries.sort((a, b) => b.score - a.score);
    entries.forEach((item, idx) => { item.rank = idx + 1; });
    return entries.map((e) => ({ ...e }));
  }

  async getLeaderboard(): Promise<LeaderboardEntry[]> {
    const bots = this.leaderboard
      .filter((l) => l.country !== 'LOCAL')
      .map((e) => ({ ...e, username: e.team, solvedCount: e.solves }));
    const users: LeaderboardEntry[] = this.users
      .filter((u) => u.score > 0)
      .map((u) => {
        const solves = [...this.solveKeys].filter((k) => k.startsWith(`${u.id}:`));
        const last = [...this.lastSolvedAt.entries()]
          .filter(([k]) => k.startsWith(`${u.id}:`))
          .map(([, t]) => t).sort().pop();
        return {
          rank: 0, team: u.name, username: u.name, score: u.score,
          solves: solves.length, solvedCount: solves.length,
          lastSolved: last ? new Date(last).toLocaleDateString() : undefined,
          avatar: '🛡️', country: 'ORG',
        };
      });
    return this.rankEntries([...users, ...bots]);
  }

  async listDfirEvents(): Promise<DFIRTimelineEvent[]> { return [...this.dfir]; }

  async addDfirEvent(event: DFIRTimelineEvent): Promise<DFIRTimelineEvent> {
    this.dfir.push(event);
    if (this.dfir.length > 2000) this.dfir.shift();
    return event;
  }
}

// ---------------------------------------------------------------------------
// Postgres store
// ---------------------------------------------------------------------------

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  badge TEXT,
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  severity TEXT NOT NULL,
  status TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  mitre_technique TEXT NOT NULL DEFAULT '',
  mitre_tactic TEXT NOT NULL DEFAULT '',
  source_ip TEXT NOT NULL DEFAULT '',
  dest_ip TEXT NOT NULL DEFAULT '',
  asset TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  triage_notes TEXT,
  analyst TEXT,
  ai_verdict JSONB
);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE TABLE IF NOT EXISTS iocs (id TEXT PRIMARY KEY, seq BIGSERIAL, data JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS courses (id TEXT PRIMARY KEY, seq BIGSERIAL, data JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS phishing_campaigns (id TEXT PRIMARY KEY, seq BIGSERIAL, data JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS ctf_challenges (id TEXT PRIMARY KEY, seq BIGSERIAL, data JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS ctf_leaderboard (id TEXT PRIMARY KEY, seq BIGSERIAL, data JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS dfir_timeline (id TEXT PRIMARY KEY, seq BIGSERIAL, data JSONB NOT NULL);
CREATE TABLE IF NOT EXISTS telemetry (id BIGSERIAL PRIMARY KEY, data JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  timestamp TIMESTAMPTZ NOT NULL,
  actor_id TEXT NOT NULL,
  actor_name TEXT NOT NULL,
  actor_role TEXT NOT NULL,
  action TEXT NOT NULL,
  resource TEXT NOT NULL,
  outcome TEXT NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);

-- Per-user progress (Phase 2): lesson completions, CTF solves, hint unlocks.
-- Challenges/courses themselves are shared; completion state is per user.
ALTER TABLE users ADD COLUMN IF NOT EXISTS score INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS user_progress (
  user_id TEXT NOT NULL,
  course_id TEXT NOT NULL,
  lesson_id TEXT NOT NULL,
  completed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, course_id, lesson_id)
);
CREATE TABLE IF NOT EXISTS user_solves (
  user_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  points_awarded INTEGER NOT NULL,
  solved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, challenge_id)
);
CREATE TABLE IF NOT EXISTS user_hints (
  user_id TEXT NOT NULL,
  challenge_id TEXT NOT NULL,
  unlocked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, challenge_id)
);
`;

const ALERT_RETENTION = 2000; // bound alerts table growth
const TELEMETRY_RETENTION = 2000;

interface AlertRow {
  id: string;
  severity: string;
  status: string;
  title: string;
  description: string | null;
  source: string | null;
  mitre_technique: string | null;
  mitre_tactic: string | null;
  source_ip: string | null;
  dest_ip: string | null;
  asset: string | null;
  created_at: Date;
  updated_at: Date;
  triage_notes: string | null;
  analyst: string | null;
  ai_verdict: unknown;
}

function rowToAlert(row: AlertRow): AlertItem {
  return {
    id: row.id,
    severity: row.severity as AlertItem['severity'],
    status: row.status as AlertItem['status'],
    title: row.title,
    description: row.description ?? '',
    source: row.source ?? '',
    mitreTechnique: row.mitre_technique ?? '',
    mitreTactic: row.mitre_tactic ?? '',
    sourceIp: row.source_ip ?? '',
    destIp: row.dest_ip ?? '',
    asset: row.asset ?? '',
    created_at: row.created_at.toISOString(),
    updated_at: row.updated_at.toISOString(),
    triage_notes: row.triage_notes ?? undefined,
    analyst: row.analyst ?? undefined,
    aiVerdict: row.ai_verdict as AlertItem['aiVerdict'] | undefined,
  };
}

class PostgresStore implements Store {
  readonly kind = 'postgres' as const;
  private pool: Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({
      connectionString,
      max: 10,
      connectionTimeoutMillis: 5000,
      idleTimeoutMillis: 30000,
    });
  }

  /** Connect (with retries), create schema, seed demo data on first boot. */
  async init(): Promise<void> {
    let connected = false;
    for (let attempt = 1; attempt <= 15 && !connected; attempt++) {
      try {
        await this.pool.query('SELECT 1');
        connected = true;
      } catch (err) {
        if (attempt === 15) {
          throw new Error(
            `Could not connect to PostgreSQL at ${process.env.DATABASE_URL}. ` +
            `Is it running? (docker-compose up -d starts it.) Last error: ${(err as Error)?.message}`,
          );
        }
        await new Promise((r) => setTimeout(r, 1000));
      }
    }

    await this.pool.query(SCHEMA_SQL);
    await this.seedIfEmpty();
    console.log(`[store] Postgres store ready at ${process.env.DATABASE_URL?.split('@').pop()}`);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  private async seedIfEmpty(): Promise<void> {
    const isEmpty = async (table: string) => {
      const r = await this.pool.query(`SELECT COUNT(*) AS c FROM ${table}`);
      return Number(r.rows[0].c) === 0;
    };

    if (await isEmpty('users')) {
      for (const u of makeSeedUsers()) {
        await this.pool.query(
          `INSERT INTO users (id, username, name, role, badge, password_salt, password_hash) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [u.id, u.username, u.name, u.role, u.badge ?? null, u.passwordSalt, u.passwordHash],
        );
      }
      console.log('[store] seeded 4 users (admin/analyst/trainer/viewer)');
    }

    if (await isEmpty('alerts')) {
      for (const a of seedAlerts) await this.insertAlertRow(a);
      console.log(`[store] seeded ${seedAlerts.length} alerts`);
    }

    // Generic JSONB tables. The leaderboard uses `country` as its stable id.
    const jsonTables: Array<[string, unknown[], (row: any) => string]> = [
      ['iocs', seedIocs, (r) => r.id],
      ['courses', seedCourses, (r) => r.id],
      ['phishing_campaigns', seedPhishingCampaigns, (r) => r.id],
      ['ctf_challenges', seedCtfChallenges, (r) => r.id],
      ['ctf_leaderboard', seedCtfLeaderboard, (r) => r.country],
      ['dfir_timeline', seedDfirTimeline, (r) => r.id],
    ];
    for (const [table, rows, idOf] of jsonTables) {
      if (await isEmpty(table)) {
        for (const row of rows) {
          await this.pool.query(
            `INSERT INTO ${table} (id, data) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`,
            [idOf(row), JSON.stringify(row)],
          );
        }
        console.log(`[store] seeded ${rows.length} ${table}`);
      }
    }

    if (await isEmpty('telemetry')) {
      for (const p of makeSeedTelemetry()) {
        await this.pool.query('INSERT INTO telemetry (data) VALUES ($1)', [JSON.stringify(p)]);
      }
      console.log('[store] seeded telemetry history');
    }
  }

  async health(): Promise<boolean> {
    try {
      await this.pool.query('SELECT 1');
      return true;
    } catch {
      return false;
    }
  }

  // -- users ----------------------------------------------------------------

  async verifyPassword(username: string, password: string): Promise<SafeUser | null> {
    const r = await this.pool.query(
      'SELECT id, username, name, role, badge, score, password_salt, password_hash FROM users WHERE username = $1',
      [username.toLowerCase()],
    );
    const row = r.rows[0];
    if (!row) return null;
    const candidate = scryptHash(password, row.password_salt);
    if (!timingSafeEqualHex(candidate, row.password_hash)) return null;
    return { id: row.id, username: row.username, name: row.name, role: row.role, badge: row.badge ?? undefined, score: row.score };
  }

  async findUserById(id: string): Promise<SafeUser | null> {
    const r = await this.pool.query(
      'SELECT id, username, name, role, badge, score FROM users WHERE id = $1',
      [id],
    );
    const row = r.rows[0];
    if (!row) return null;
    return { id: row.id, username: row.username, name: row.name, role: row.role, badge: row.badge ?? undefined, score: row.score };
  }

  // -- audit ----------------------------------------------------------------

  async recordAudit(entry: AuditEntry): Promise<void> {
    await this.pool.query(
      `INSERT INTO audit_log (id, timestamp, actor_id, actor_name, actor_role, action, resource, outcome, ip, detail)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [entry.id, entry.timestamp, entry.actorId, entry.actorName, entry.actorRole, entry.action, entry.resource, entry.outcome, entry.ip, entry.detail ?? null],
    );
  }

  async getAuditLog(limit: number): Promise<AuditEntry[]> {
    const r = await this.pool.query(
      'SELECT id, timestamp, actor_id, actor_name, actor_role, action, resource, outcome, ip, detail FROM audit_log ORDER BY timestamp DESC LIMIT $1',
      [Math.min(limit, 5000)],
    );
    return r.rows.map((row: any) => ({
      id: row.id,
      timestamp: row.timestamp.toISOString(),
      actorId: row.actor_id,
      actorName: row.actor_name,
      actorRole: row.actor_role,
      action: row.action,
      resource: row.resource,
      outcome: row.outcome,
      ip: row.ip,
      detail: row.detail ?? undefined,
    }));
  }

  // -- alerts ---------------------------------------------------------------

  private async insertAlertRow(a: AlertItem): Promise<void> {
    // Upsert: createAlert inserts, updateAlert (triage / aiVerdict) re-writes.
    await this.pool.query(
      `INSERT INTO alerts (id, severity, status, title, description, source, mitre_technique, mitre_tactic,
        source_ip, dest_ip, asset, created_at, updated_at, triage_notes, analyst, ai_verdict)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       ON CONFLICT (id) DO UPDATE SET
         severity = EXCLUDED.severity, status = EXCLUDED.status, title = EXCLUDED.title,
         description = EXCLUDED.description, source = EXCLUDED.source,
         mitre_technique = EXCLUDED.mitre_technique, mitre_tactic = EXCLUDED.mitre_tactic,
         source_ip = EXCLUDED.source_ip, dest_ip = EXCLUDED.dest_ip, asset = EXCLUDED.asset,
         updated_at = EXCLUDED.updated_at, triage_notes = EXCLUDED.triage_notes,
         analyst = EXCLUDED.analyst, ai_verdict = EXCLUDED.ai_verdict`,
      [
        a.id, a.severity, a.status, a.title, a.description, a.source,
        a.mitreTechnique, a.mitreTactic, a.sourceIp, a.destIp, a.asset,
        a.created_at, a.updated_at, a.triage_notes ?? null, a.analyst ?? null,
        a.aiVerdict ? JSON.stringify(a.aiVerdict) : null,
      ],
    );
  }

  private async pruneAlerts(): Promise<void> {
    await this.pool.query(
      `DELETE FROM alerts WHERE id IN (SELECT id FROM alerts ORDER BY created_at DESC OFFSET ${ALERT_RETENTION})`,
    );
  }

  async listAlerts(filter: AlertFilter): Promise<AlertListResult> {
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (filter.severity && filter.severity !== 'all') {
      params.push(filter.severity);
      clauses.push(`severity = $${params.length}`);
    }
    if (filter.status && filter.status !== 'all') {
      params.push(filter.status);
      clauses.push(`status = $${params.length}`);
    }
    if (filter.search) {
      params.push(`%${filter.search.toLowerCase()}%`);
      clauses.push(
        `(LOWER(title) LIKE $${params.length} OR LOWER(description) LIKE $${params.length}
         OR source_ip LIKE $${params.length} OR dest_ip LIKE $${params.length}
         OR LOWER(mitre_technique) LIKE $${params.length})`,
      );
    }
    const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';

    const [listR, sevR, statusR] = await Promise.all([
      this.pool.query(`SELECT * FROM alerts ${where} ORDER BY created_at DESC LIMIT 500`, params),
      this.pool.query('SELECT severity, COUNT(*) AS c FROM alerts GROUP BY severity'),
      this.pool.query('SELECT status, COUNT(*) AS c FROM alerts GROUP BY status'),
    ]);

    const stats = emptyStats();
    for (const row of sevR.rows as Array<{ severity: string; c: string }>) {
      const key = row.severity as keyof AlertStats;
      if (key in stats) (stats as unknown as Record<string, number>)[key] = Number(row.c);
    }
    for (const row of statusR.rows as Array<{ status: string; c: string }>) {
      const key = row.status === 'investigating' ? 'investigating' : row.status;
      if (key === 'new' || key === 'investigating' || key === 'resolved') {
        (stats as unknown as Record<string, number>)[key] = Number(row.c);
      }
    }

    const alerts = (listR.rows as unknown as AlertRow[]).map(rowToAlert);
    return { alerts, total: alerts.length, stats };
  }

  async getAlert(id: string): Promise<AlertItem | null> {
    const r = await this.pool.query('SELECT * FROM alerts WHERE id = $1', [id]);
    if (!r.rows[0]) return null;
    return rowToAlert(r.rows[0] as AlertRow);
  }

  async createAlert(alert: AlertItem): Promise<AlertItem> {
    await this.insertAlertRow(alert);
    await this.pruneAlerts();
    return alert;
  }

  async updateAlert(id: string, patch: Partial<AlertItem>): Promise<AlertItem | null> {
    const existing = await this.getAlert(id);
    if (!existing) return null;
    const merged: AlertItem = { ...existing, ...patch, updated_at: new Date().toISOString() };
    await this.insertAlertRow(merged);
    return merged;
  }

  // -- iocs -----------------------------------------------------------------

  async listIocs(): Promise<IOCItem[]> {
    const r = await this.pool.query('SELECT data FROM iocs ORDER BY seq DESC');
    return r.rows.map((row: any) => row.data as IOCItem);
  }

  async addIoc(ioc: IOCItem): Promise<IOCItem> {
    await this.pool.query('INSERT INTO iocs (id, data) VALUES ($1, $2)', [ioc.id, JSON.stringify(ioc)]);
    return ioc;
  }

  async toggleIocBlock(id: string): Promise<IOCItem | null> {
    const r = await this.pool.query('SELECT data FROM iocs WHERE id = $1', [id]);
    if (!r.rows[0]) return null;
    const ioc = r.rows[0].data as IOCItem;
    ioc.blocked = !ioc.blocked;
    await this.pool.query('UPDATE iocs SET data = $2 WHERE id = $1', [id, JSON.stringify(ioc)]);
    return ioc;
  }

  // -- telemetry ------------------------------------------------------------

  async getTelemetry(): Promise<TelemetrySummary> {
    const r = await this.pool.query('SELECT data FROM telemetry ORDER BY id DESC LIMIT 30');
    const history = (r.rows.map((row: any) => row.data as TelemetryPoint)).reverse();
    return { history, current: history[history.length - 1] ?? null };
  }

  async appendTelemetry(point: TelemetryPoint): Promise<void> {
    await this.pool.query('INSERT INTO telemetry (data) VALUES ($1)', [JSON.stringify(point)]);
    await this.pool.query(
      `DELETE FROM telemetry WHERE id IN (SELECT id FROM telemetry ORDER BY id DESC OFFSET ${TELEMETRY_RETENTION})`,
    );
  }

  // -- training -------------------------------------------------------------

  async listCoursesForUser(userId: string): Promise<CourseItem[]> {
    const [coursesR, progR] = await Promise.all([
      this.pool.query('SELECT data FROM courses ORDER BY seq ASC'),
      this.pool.query('SELECT course_id, lesson_id FROM user_progress WHERE user_id = $1', [userId]),
    ]);
    const done = new Set(progR.rows.map((r: any) => `${r.course_id}:${r.lesson_id}`));
    return (coursesR.rows as any[]).map((row) => {
      const course = row.data as CourseItem;
      return { ...course, lessons: course.lessons.map((l) => ({ ...l, completed: done.has(`${course.id}:${l.id}`) })) };
    });
  }

  async completeLesson(userId: string, courseId: string, lessonId: string) {
    const r = await this.pool.query('SELECT data FROM courses WHERE id = $1', [courseId]);
    if (!r.rows[0]) return null;
    const course = r.rows[0].data as CourseItem;
    const lesson = course.lessons.find((l) => l.id === lessonId);
    if (!lesson) return null;
    await this.pool.query(
      'INSERT INTO user_progress (user_id, course_id, lesson_id) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING',
      [userId, courseId, lessonId],
    );
    const doneR = await this.pool.query(
      'SELECT COUNT(*) AS c FROM user_progress WHERE user_id = $1 AND course_id = $2',
      [userId, courseId],
    );
    const completedCount = Number(doneR.rows[0].c);
    return { lesson: { ...lesson, completed: true }, courseProgress: Math.round((completedCount / course.lessons.length) * 100) };
  }

  async listCampaigns(): Promise<PhishingCampaignItem[]> {
    const r = await this.pool.query('SELECT data FROM phishing_campaigns ORDER BY seq DESC');
    return r.rows.map((row: any) => row.data as PhishingCampaignItem);
  }

  async addCampaign(campaign: PhishingCampaignItem): Promise<PhishingCampaignItem> {
    await this.pool.query('INSERT INTO phishing_campaigns (id, data) VALUES ($1, $2)', [campaign.id, JSON.stringify(campaign)]);
    return campaign;
  }

  // -- ctf ------------------------------------------------------------------

  async listChallengesForUser(userId: string): Promise<CTFChallengeItem[]> {
    const [chR, solR, hintR] = await Promise.all([
      this.pool.query('SELECT data FROM ctf_challenges ORDER BY seq ASC'),
      this.pool.query('SELECT challenge_id FROM user_solves WHERE user_id = $1', [userId]),
      this.pool.query('SELECT challenge_id FROM user_hints WHERE user_id = $1', [userId]),
    ]);
    const solved = new Set(solR.rows.map((r: any) => r.challenge_id));
    const hints = new Set(hintR.rows.map((r: any) => r.challenge_id));
    return (chR.rows as any[]).map((row) => {
      const ch = row.data as CTFChallengeItem;
      return { ...ch, solved: solved.has(ch.id), hintUnlocked: hints.has(ch.id) };
    });
  }

  async getChallenge(id: string): Promise<CTFChallengeItem | null> {
    const r = await this.pool.query('SELECT data FROM ctf_challenges WHERE id = $1', [id]);
    if (!r.rows[0]) return null;
    return r.rows[0].data as CTFChallengeItem;
  }

  async unlockHint(userId: string, challengeId: string) {
    const r = await this.pool.query('SELECT data FROM ctf_challenges WHERE id = $1', [challengeId]);
    if (!r.rows[0]) return null;
    const ch = r.rows[0].data as CTFChallengeItem;
    const before = await this.pool.query('SELECT 1 FROM user_hints WHERE user_id = $1 AND challenge_id = $2', [userId, challengeId]);
    await this.pool.query(
      'INSERT INTO user_hints (user_id, challenge_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [userId, challengeId],
    );
    return { hint: ch.hint, penalty: ch.hintPenalty, alreadyUnlocked: !!before.rows[0] };
  }

  async submitFlag(userId: string, challengeId: string, submittedFlag: string): Promise<FlagSubmitResult | null> {
    const r = await this.pool.query('SELECT data FROM ctf_challenges WHERE id = $1', [challengeId]);
    if (!r.rows[0]) return null;
    const ch = r.rows[0].data as CTFChallengeItem;

    if (submittedFlag.trim() !== ch.flag) {
      return { success: false, message: 'Incorrect flag. Check formatting (FLAG{...}) and verify extraction.', challengeId, challengeTitle: ch.title };
    }

    const hintR = await this.pool.query('SELECT 1 FROM user_hints WHERE user_id = $1 AND challenge_id = $2', [userId, challengeId]);
    const netPoints = hintR.rows[0] ? Math.max(10, ch.points - ch.hintPenalty) : ch.points;

    const solvedR = await this.pool.query(
      'INSERT INTO user_solves (user_id, challenge_id, points_awarded) VALUES ($1,$2,$3) ON CONFLICT (user_id, challenge_id) DO NOTHING RETURNING points_awarded',
      [userId, challengeId, netPoints],
    );
    if (!solvedR.rows[0]) {
      // Already solved by this user — no double award.
      const cur = await this.pool.query('SELECT score FROM users WHERE id = $1', [userId]);
      return {
        success: true, message: 'Flag already solved — no additional points awarded.',
        alreadySolved: true, pointsAwarded: 0, newScore: Number(cur.rows[0]?.score ?? 0), challengeId, challengeTitle: ch.title,
      };
    }

    const scoreR = await this.pool.query('UPDATE users SET score = score + $2 WHERE id = $1 RETURNING score', [userId, netPoints]);
    ch.solvesCount += 1; // global stat
    await this.pool.query('UPDATE ctf_challenges SET data = $2 WHERE id = $1', [challengeId, JSON.stringify(ch)]);
    return {
      success: true, message: `Flag Correct! +${netPoints} Points Awarded.`,
      pointsAwarded: netPoints, newScore: Number(scoreR.rows[0]?.score ?? 0), challengeId, challengeTitle: ch.title,
    };
  }

  async addChallenge(challenge: CTFChallengeItem): Promise<void> {
    await this.pool.query('INSERT INTO ctf_challenges (id, data) VALUES ($1, $2)', [challenge.id, JSON.stringify(challenge)]);
  }

  private sortAndRank(entries: LeaderboardEntry[]): LeaderboardEntry[] {
    entries.sort((a, b) => b.score - a.score);
    entries.forEach((item, idx) => { item.rank = idx + 1; });
    return entries.map((e) => ({ ...e }));
  }

  async getLeaderboard(): Promise<LeaderboardEntry[]> {
    // Real platform users (with at least one solve or a score) + seeded bot teams.
    const [usersR, botsR] = await Promise.all([
      this.pool.query(`
        SELECT u.name, u.score,
          (SELECT COUNT(*) FROM user_solves s WHERE s.user_id = u.id)::int AS solves,
          (SELECT MAX(solved_at) FROM user_solves s WHERE s.user_id = u.id) AS last_solved
        FROM users u
        WHERE u.score > 0 OR EXISTS (SELECT 1 FROM user_solves s WHERE s.user_id = u.id)
        ORDER BY u.score DESC, u.name
      `),
      this.pool.query('SELECT data FROM ctf_leaderboard'),
    ]);
    const users: LeaderboardEntry[] = usersR.rows.map((row: any) => ({
      rank: 0, team: row.name, username: row.name, score: row.score,
      solves: row.solves, solvedCount: row.solves,
      lastSolved: row.last_solved ? new Date(row.last_solved).toLocaleDateString() : undefined,
      avatar: '🛡️', country: 'ORG',
    }));
    const bots: LeaderboardEntry[] = (botsR.rows as any[])
      .map((r) => r.data as LeaderboardEntry)
      .filter((e) => e.country !== 'LOCAL')
      .map((e) => ({ ...e, username: e.team, solvedCount: e.solves }));
    return this.sortAndRank([...users, ...bots]);
  }

  // -- dfir -----------------------------------------------------------------

  async listDfirEvents(): Promise<DFIRTimelineEvent[]> {
    const r = await this.pool.query('SELECT data FROM dfir_timeline ORDER BY seq ASC');
    return r.rows.map((row: any) => row.data as DFIRTimelineEvent);
  }

  async addDfirEvent(event: DFIRTimelineEvent): Promise<DFIRTimelineEvent> {
    await this.pool.query('INSERT INTO dfir_timeline (id, data) VALUES ($1, $2)', [event.id, JSON.stringify(event)]);
    return event;
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export async function createStore(): Promise<Store> {
  const url = process.env.DATABASE_URL;
  if (url) {
    const store = new PostgresStore(url);
    await store.init();
    return store;
  }
  console.log('[store] DATABASE_URL not set — using in-memory store (local dev)');
  return new MemoryStore();
}

export function isMemoryStore(store: Store): store is MemoryStore {
  return store.kind === 'memory';
}