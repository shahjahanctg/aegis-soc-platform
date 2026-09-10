import crypto from 'crypto';
import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import type { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export const JWT_ACCESS_TTL_SEC = 15 * 60; // 15 minutes
export const JWT_REFRESH_TTL_SEC = 7 * 24 * 60 * 60; // 7 days
const ACCESS_AUD = 'aegis-api';
const ISSUER = 'aegis-soc';

function requiredSecret(name: string, devDefault: string): Uint8Array {
  const val = process.env[name];
  if (!val) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(`${name} must be set in production. Generate with: openssl rand -base64 48`);
    }
    return new TextEncoder().encode(devDefault);
  }
  return new TextEncoder().encode(val);
}

const ACCESS_SECRET = requiredSecret('JWT_ACCESS_SECRET', 'dev-only-access-secret-change-me');
const REFRESH_SECRET = requiredSecret('JWT_REFRESH_SECRET', 'dev-only-refresh-secret-change-me');

// ---------------------------------------------------------------------------
// Roles & permissions (RBAC)
// ---------------------------------------------------------------------------

export type Role = 'admin' | 'analyst' | 'trainer' | 'viewer';

export const ROLE_PERMISSIONS: Record<Role, string[]> = {
  admin: ['*'],
  analyst: [
    'alerts:read', 'alerts:triage', 'alerts:create',
    'intel:read', 'intel:write',
    'telemetry:read', 'telemetry:ingest',
    'training:read', 'training:write',
    'ctf:read', 'ctf:submit', 'ctf:hints',
    'dfir:read', 'dfir:write',
    'ai:chat',
  ],
  trainer: [
    'alerts:read', 'intel:read', 'telemetry:read',
    'training:read', 'training:write',
    'ctf:read', 'ctf:manage', 'dfir:read',
  ],
  viewer: ['alerts:read', 'intel:read', 'telemetry:read', 'training:read', 'ctf:read', 'dfir:read'],
};

// ---------------------------------------------------------------------------
// Users (seeded; scrypt password hashes). Replace with a user table when the
// Postgres persistence layer lands.
// ---------------------------------------------------------------------------

export interface SafeUser {
  id: string;
  username: string;
  name: string;
  role: Role;
  badge?: string;
}

interface UserRecord extends SafeUser {
  passwordHash: string;
  passwordSalt: string;
}

function scryptHash(password: string, salt: string): string {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function makeUser(u: { username: string; name: string; password: string; role: Role; badge?: string }): UserRecord {
  const passwordSalt = crypto.randomBytes(16).toString('hex');
  return { id: `usr-${crypto.randomUUID().slice(0, 8)}`, ...u, passwordSalt, passwordHash: scryptHash(u.password, passwordSalt) };
}

const users: UserRecord[] = [
  makeUser({ username: 'admin', name: 'Platform Administrator', password: process.env.SEED_ADMIN_PASSWORD || 'ChangeMe_Admin_2026!', role: 'admin', badge: 'Commander' }),
  makeUser({ username: 'analyst', name: 'Lead SOC Analyst', password: process.env.SEED_ANALYST_PASSWORD || 'ChangeMe_Analyst_2026!', role: 'analyst', badge: 'Lead Defender' }),
  makeUser({ username: 'trainer', name: 'Training Coordinator', password: process.env.SEED_TRAINER_PASSWORD || 'ChangeMe_Trainer_2026!', role: 'trainer', badge: 'Instructor' }),
  makeUser({ username: 'viewer', name: 'Read-Only Auditor', password: process.env.SEED_VIEWER_PASSWORD || 'ChangeMe_Viewer_2026!', role: 'viewer', badge: 'Observer' }),
];

export function verifyPassword(username: string, password: string): SafeUser | null {
  const user = users.find(u => u.username === username.toLowerCase());
  if (!user) return null;
  const candidate = scryptHash(password, user.passwordSalt);
  const ok = candidate.length === user.passwordHash.length &&
    crypto.timingSafeEqual(Buffer.from(candidate, 'hex'), Buffer.from(user.passwordHash, 'hex'));
  return ok ? toSafeUser(user) : null;
}

export function findUserById(id: string): SafeUser | null {
  const user = users.find(u => u.id === id);
  return user ? toSafeUser(user) : null;
}

function toSafeUser(u: UserRecord): SafeUser {
  return { id: u.id, username: u.username, name: u.name, role: u.role, badge: u.badge };
}

// ---------------------------------------------------------------------------
// JWT helpers (jose, HS256)
// ---------------------------------------------------------------------------

export async function issueAccessToken(user: SafeUser): Promise<string> {
  return new SignJWT({ sub: user.id, username: user.username, role: user.role, typ: 'access' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(ISSUER)
    .setAudience(ACCESS_AUD)
    .setIssuedAt()
    .setExpirationTime(`${JWT_ACCESS_TTL_SEC}s`)
    .sign(ACCESS_SECRET);
}

export async function issueRefreshToken(user: SafeUser): Promise<string> {
  return new SignJWT({ sub: user.id, typ: 'refresh' })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(ISSUER)
    .setAudience(ACCESS_AUD)
    .setIssuedAt()
    .setExpirationTime(`${JWT_REFRESH_TTL_SEC}s`)
    .sign(REFRESH_SECRET);
}

export async function verifyRefreshToken(token: string): Promise<JWTPayload | null> {
  const payload = await verifyToken(token, REFRESH_SECRET);
  return payload && payload.typ === 'refresh' ? payload : null;
}

/** Maps a SafeUser to the frontend UserSession shape. */
export function toSessionUser(user: SafeUser) {
  return {
    id: user.id,
    username: user.username,
    name: user.name,
    role: user.role as string,
    permissions: ROLE_PERMISSIONS[user.role] ?? [],
    badge: user.badge,
    score: 0,
  };
}

async function verifyToken(token: string, secret: Uint8Array): Promise<JWTPayload | null> {
  try {
    const { payload } = await jwtVerify(token, secret, { issuer: ISSUER, audience: ACCESS_AUD });
    return payload;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Express middleware
// ---------------------------------------------------------------------------

export interface AuthedRequest extends Request {
  user?: SafeUser;
}

function bearerToken(req: Request): string | null {
  const header = req.headers.authorization;
  return header?.startsWith('Bearer ') ? header.slice(7) : null;
}

/** Constant-time string comparison that is safe for unequal lengths (hashes both sides). */
function timingSafeStringEqual(a: string, b: string): boolean {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

/** Hard gate: requires a valid access token. Attaches req.user. */
export async function requireAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const token = bearerToken(req);
  if (!token) {
    return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
  }
  const payload = await verifyToken(token, ACCESS_SECRET);
  if (!payload || payload.typ !== 'access' || typeof payload.sub !== 'string') {
    return res.status(401).json({ error: 'Invalid or expired token', code: 'BAD_TOKEN' });
  }
  const user = findUserById(payload.sub);
  if (!user) {
    return res.status(401).json({ error: 'User no longer exists', code: 'UNKNOWN_USER' });
  }
  req.user = user;
  next();
}

/** Soft gate for SSE: accepts valid token in Authorization header or ?token= (EventSource cannot set headers). Anonymous SSE stays available only in non-production. */
export async function sseAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const token = bearerToken(req) || (typeof req.query.token === 'string' ? req.query.token : null);
  if (!token) {
    if (process.env.NODE_ENV === 'production') {
      return res.status(401).json({ error: 'Authentication required for event stream', code: 'NO_TOKEN' });
    }
    return next();
  }
  const payload = await verifyToken(token, ACCESS_SECRET);
  if (payload?.typ === 'access' && typeof payload.sub === 'string') {
    req.user = findUserById(payload.sub) || undefined;
  }
  next();
}

/** RBAC: requires req.user to hold the permission (admin '*' passes everything). Use after requireAuth. */
export function requirePermission(permission: string) {
  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
    }
    const granted = ROLE_PERMISSIONS[user.role] || [];
    if (granted.includes('*') || granted.includes(permission)) {
      return next();
    }
    return res.status(403).json({ error: `Forbidden: requires '${permission}'`, code: 'FORBIDDEN' });
  };
}

/**
 * Ingest authentication: machine forwarders authenticate with a static API key
 * (INGEST_API_KEY); authenticated platform users with telemetry:ingest may also
 * call it (used by the Syslog Ingest test view in the UI).
 */
export function requireIngestAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const apiKey = process.env.INGEST_API_KEY;
  const provided = req.header('x-api-key');
  if (apiKey && provided && timingSafeStringEqual(provided, apiKey)) {
    return next();
  }
  requireAuth(req, res, (err?: unknown) => {
    if (err) return next(err as NextFunction);
    const user = req.user;
    const granted = user ? ROLE_PERMISSIONS[user.role] || [] : [];
    if (granted.includes('*') || granted.includes('telemetry:ingest')) {
      return next();
    }
    return res.status(403).json({ error: "Forbidden: requires 'telemetry:ingest' or a valid x-api-key", code: 'FORBIDDEN' });
  });
}

// ---------------------------------------------------------------------------
// Rate limiters
// ---------------------------------------------------------------------------

const standard = (windowMs: number, max: number) =>
  rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, slow down.', code: 'RATE_LIMITED' },
  });

export const authLimiter = standard(15 * 60 * 1000, 20);        // login/refresh: 20 / 15 min / IP
export const aiLimiter = standard(60 * 1000, 20);               // AI endpoints: 20 / min / IP
export const ingestLimiter = standard(60 * 1000, 600);          // telemetry ingest: 600 / min / IP
export const mutationLimiter = standard(60 * 1000, 120);        // general mutations: 120 / min / IP
