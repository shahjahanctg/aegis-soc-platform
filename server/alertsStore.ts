import crypto from 'crypto';
import type { AlertItem } from './types';

// ---------------------------------------------------------------------------
// Alert store helpers — bounded memory + collision-free IDs.
// The alert array itself still lives in server.ts until the Postgres layer
// lands; these helpers make it safe against unbounded ingest spam.
// ---------------------------------------------------------------------------

export const MAX_ALERTS = 500;

export function makeAlertId(): string {
  return `ALT-${crypto.randomUUID().replace(/-/g, '').slice(0, 12)}`;
}

/** Adds an alert to the front, dropping the oldest beyond MAX_ALERTS. */
export function addAlertBounded(alerts: AlertItem[], alert: AlertItem): void {
  alerts.unshift(alert);
  if (alerts.length > MAX_ALERTS) {
    alerts.length = MAX_ALERTS;
  }
}
