import Redis from 'ioredis';
import { RedisStore } from 'rate-limit-redis';
import type { RateLimitStores } from './security';

// ---------------------------------------------------------------------------
// Optional Redis integration. Everything in this module degrades gracefully:
// if REDIS_URL is unset or unreachable, the app keeps working with in-process
// SSE fan-out and in-memory rate limiting. When Redis is up, SSE broadcasts
// are fanned out across app replicas via pub/sub and rate-limit counters are
// shared (survive restarts, consistent across replicas).
// ---------------------------------------------------------------------------

const SSE_CHANNEL = 'aegis:sse';

export interface SSERelay {
  publish(event: string, data: unknown): void;
  close(): void;
}

function newClient(url: string): Redis {
  return new Redis(url, {
    enableOfflineQueue: false,
    maxRetriesPerRequest: 1,
    connectTimeout: 3000,
    lazyConnect: true,
  });
}

/**
 * Creates the cross-replica SSE relay. `onRemote` is invoked with events
 * published by *other* instances (each message carries the publisher's
 * instance id; the local publisher already fanned out locally).
 */
export function createSSERelay(url: string, onRemote: (event: string, data: unknown) => void): SSERelay {
  const instanceId = cryptoRandomId();
  const pub = newClient(url);
  const sub = newClient(url);

  pub.connect().catch(() => {/* best-effort; publish() below guards errors */});
  sub.connect()
    .then(() => sub.subscribe(SSE_CHANNEL))
    .catch(() => {/* relay becomes no-op until reconnect */});

  sub.on('message', (channel, message) => {
    if (channel !== SSE_CHANNEL) return;
    try {
      const parsed = JSON.parse(message) as { from: string; event: string; data: unknown };
      if (parsed.from !== instanceId) onRemote(parsed.event, parsed.data);
    } catch {
      // ignore malformed messages
    }
  });

  return {
    publish(event: string, data: unknown) {
      pub.publish(SSE_CHANNEL, JSON.stringify({ from: instanceId, event, data })).catch(() => {
        // Redis down: local fan-out already happened; replicas miss the event.
      });
    },
    close() {
      pub.disconnect();
      sub.disconnect();
    },
  };
}

/**
 * Builds Redis-backed rate-limit stores. Returns undefined when Redis is not
 * reachable so the app falls back to in-memory limiting.
 */
export async function createRateLimitStores(url: string): Promise<RateLimitStores | undefined> {
  const client = newClient(url);
  try {
    await client.connect();
    await client.ping();
  } catch {
    client.disconnect();
    console.warn('[redis] unreachable — falling back to in-memory rate limiting');
    return undefined;
  }
  // One store instance per limiter (express-rate-limit forbids reuse across limiters).
  const makeStore = (prefix: string) => new RedisStore({
    sendCommand: (...args: string[]) => client.call(...(args as [string, ...string[]])) as Promise<any>,
    prefix: `rl:${prefix}:`,
  });
  return {
    auth: makeStore('auth'),
    ai: makeStore('ai'),
    ingest: makeStore('ingest'),
    mutation: makeStore('mutation'),
  };
}

function cryptoRandomId(): string {
  const { randomUUID } = require('crypto') as typeof import('crypto');
  return randomUUID();
}