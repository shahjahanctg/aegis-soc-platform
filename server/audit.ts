import crypto from 'crypto';
import type { AuthedRequest, SafeUser } from './security';

// ---------------------------------------------------------------------------
// Append-only audit trail. Every security-relevant action is recorded with
// actor, action, resource, and outcome. Never mutated or deleted at runtime.
// Bounded to 5,000 entries in memory (oldest dropped) until the Postgres layer
// replaces it; the cap also bounds memory from unauthenticated spam.
// ---------------------------------------------------------------------------

export interface AuditEntry {
  id: string;
  timestamp: string;
  actorId: string;
  actorName: string;
  actorRole: string;
  action: string;
  resource: string;
  outcome: 'allowed' | 'denied';
  ip: string;
  detail?: string;
}

const MAX_AUDIT_ENTRIES = 5000;
const auditLog: AuditEntry[] = [];

type AuditBroadcaster = (entry: AuditEntry) => void;
let broadcaster: AuditBroadcaster | null = null;

/** Server wires its SSE fan-out here so audit events stream to live clients. */
export function setAuditBroadcaster(fn: AuditBroadcaster) {
  broadcaster = fn;
}

export function recordAudit(
  req: AuthedRequest,
  action: string,
  resource: string,
  outcome: 'allowed' | 'denied' = 'allowed',
  detail?: string,
): AuditEntry {
  const user: SafeUser | undefined = req.user;
  const entry: AuditEntry = {
    id: `AUD-${crypto.randomUUID().slice(0, 12)}`,
    timestamp: new Date().toISOString(),
    actorId: user?.id ?? 'anonymous',
    actorName: user?.name ?? 'anonymous',
    actorRole: user?.role ?? 'unauthenticated',
    action,
    resource,
    outcome,
    ip: req.ip || req.socket?.remoteAddress || 'unknown',
    detail: detail?.slice(0, 500),
  };

  auditLog.push(entry);
  if (auditLog.length > MAX_AUDIT_ENTRIES) {
    auditLog.splice(0, auditLog.length - MAX_AUDIT_ENTRIES);
  }
  broadcaster?.(entry);
  return entry;
}

export function getAuditLog(limit = 200): AuditEntry[] {
  return auditLog.slice(-Math.min(limit, MAX_AUDIT_ENTRIES)).reverse();
}
