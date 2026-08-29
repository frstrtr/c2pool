// core.transport.cache — op-level response cache with TTL.
// Conservative by default (ttlMs=0 disables per-op); individual ops
// opt in via config. ETag / If-None-Match flows through HttpTransport;
// this is for higher-level memoisation (e.g. negotiate, stats).

import type { PluginDescriptor } from '../registry.js';
import type { TransportOp } from '../transport/types.js';

export interface CacheConfig {
  /** Per-op TTL in ms. 0 or missing = do not cache. */
  ttlByOp: Partial<Record<TransportOp, number>>;
}

const DEFAULTS: CacheConfig = Object.freeze({
  ttlByOp: {
    negotiate: 60_000,  // capabilities don't change within a session
    fetchStats: 2_000,  // stats are cheap; short TTL smooths bursts
  },
});

interface Entry {
  value: unknown;
  expiresAt: number;
}

const state: { config: CacheConfig; entries: Map<string, Entry> } = {
  config: { ...DEFAULTS },
  entries: new Map(),
};

function keyFor(op: TransportOp, args: readonly unknown[]): string {
  return `${op}:${JSON.stringify(args)}`;
}

export const CacheMiddleware: PluginDescriptor = {
  id: 'core.transport.cache',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'middleware',
  middlewareOf: 'transport',
  priority: 70,  // inner of retry, outer of timeout + error-taxonomy
  defaultConfig: DEFAULTS,

  async init(_host, config) {
    state.config = { ...DEFAULTS, ...(config as Partial<CacheConfig>) };
    state.entries.clear();
  },

  async deactivate() {
    state.entries.clear();
  },

  async request(req, next) {
    const ttl = state.config.ttlByOp[req.op] ?? 0;
    if (ttl <= 0) return next(req);
    const key = keyFor(req.op, req.args);
    const cached = state.entries.get(key);
    const now = Date.now();
    if (cached && cached.expiresAt > now) return cached.value;
    const value = await next(req);
    state.entries.set(key, { value, expiresAt: now + ttl });
    return value;
  },

  capabilities: {
    'cache.transport': {
      invalidate(opOrKey?: string) {
        if (opOrKey === undefined) {
          state.entries.clear();
          return;
        }
        // Prefix match: "fetchTip" invalidates every fetchTip:*
        for (const k of state.entries.keys()) {
          if (k === opOrKey || k.startsWith(`${opOrKey}:`)) {
            state.entries.delete(k);
          }
        }
      },
      size(): number {
        return state.entries.size;
      },
    },
  },
};
