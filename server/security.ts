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
// User storage is provided by the persistence layer (server/store.ts):
// Postgres-backed when DATABASE_URL is set, in-memory otherwise. No demo
// users exist — the admin is provisioned from env on first boot and
// additional accounts are created via POST /api/users (admin only).
// server.ts injects the lookup via setUserLookup() during startup.
// ---------------------------------------------------------------------------

export interface SafeUser {
  id: string;
  username: string;
  name: string;
  role: Role;
  badge?: string;
  score?: number;
}

export interface UserLookup {
  verifyPassword(username: string, password: string): Promise<SafeUser | null>;
  findUserById(id: string): Promise<SafeUser | null>;
}

let userLookup: UserLookup | null = null;

export function setUserLookup(lookup: UserLookup): void {
  userLookup = lookup;
}

function getLookup(): UserLookup {
  if (!userLookup) {
    throw new Error('UserLookup not configured — server startup did not create a store');
  }
  return userLookup;
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
    score: user.score ?? 0,
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
  const user = await getLookup().findUserById(payload.sub);
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
    const user = await getLookup().findUserById(payload.sub);
    req.user = user || undefined;
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
// Rate limiters. In-memory by default; server.ts injects Redis-backed stores
// (rate-limit-redis) when REDIS_URL is reachable so limits survive restarts
// and hold across multiple app replicas.
// ---------------------------------------------------------------------------

import type { Store as RateLimitStore } from 'express-rate-limit';

export interface RateLimitStores {
  auth?: RateLimitStore;
  ai?: RateLimitStore;
  ingest?: RateLimitStore;
  mutation?: RateLimitStore;
}

const standard = (windowMs: number, max: number, store?: RateLimitStore) =>
  rateLimit({
    windowMs,
    max,
    store,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, slow down.', code: 'RATE_LIMITED' },
  });

export function createLimiters(stores: RateLimitStores = {}) {
  return {
    auth: standard(15 * 60 * 1000, 20, stores.auth),        // login/refresh: 20 / 15 min / IP
    ai: standard(60 * 1000, 20, stores.ai),                 // AI endpoints: 20 / min / IP
    ingest: standard(60 * 1000, 600, stores.ingest),        // telemetry ingest: 600 / min / IP
    mutation: standard(60 * 1000, 120, stores.mutation),    // general mutations: 120 / min / IP
  };
}
