// core.transport.retry — exponential backoff with jitter per M1 D7.
// Base 1000 ms, cap 30000 ms, ×2 growth, ±30% jitter, unbounded retries
// by default. Per-Transport-instance jitter seed decorrelates multiple
// dashboards reconnecting simultaneously after a pool restart.

import type { PluginDescriptor } from '../registry.js';
import { isExplorerError } from '../errors.js';

export interface RetryConfig {
  baseMs: number;
  capMs: number;
  multiplier: number;
  jitterPct: number;        // ±pct on each delay (0.30 = ±30%)
  maxAttempts: number;      // 0 = unbounded
}

const DEFAULTS: RetryConfig = Object.freeze({
  baseMs: 1000,
  capMs: 30000,
  multiplier: 2,
  jitterPct: 0.30,
  maxAttempts: 0,
});

const state: { config: RetryConfig; seed: number } = {
  config: { ...DEFAULTS },
  seed: Math.random(),
};

function computeDelay(attempt: number, cfg: RetryConfig, seed: number): number {
  const raw = Math.min(cfg.capMs, cfg.baseMs * Math.pow(cfg.multiplier, attempt));
  // Deterministic-ish jitter seeded per Transport instance (see D7).
  const noise = Math.sin(seed + attempt * 7.91) * 0.5 + 0.5;  // [0, 1]
  const jitter = 1 - cfg.jitterPct + 2 * cfg.jitterPct * noise;  // [1-pct, 1+pct]
  return Math.round(raw * jitter);
}

function isTransient(err: unknown): boolean {
  if (!isExplorerError(err)) return false;
  if (err.type === 'transport') {
    // 5xx and network-level transport errors are transient; 4xx aren't.
    const s = err.status ?? 0;
    return s === 0 || s >= 500;
  }
  if (err.type === 'rate_limited') return true;
  return false;
}

export const RetryMiddleware: PluginDescriptor = {
  id: 'core.transport.retry',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'middleware',
  middlewareOf: 'transport',
  priority: 70,  // inner of logging+auth, outer of cache
  defaultConfig: DEFAULTS,

  async init(_host, config) {
    state.config = { ...DEFAULTS, ...(config as Partial<RetryConfig>) };
    state.seed = Math.random();
  },

  async request(req, next) {
    const cfg = state.config;
    let attempt = 0;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      try {
        return await next(req);
      } catch (err) {
        if (!isTransient(err)) throw err;
        if (cfg.maxAttempts > 0 && attempt >= cfg.maxAttempts) throw err;
        // Honour server-supplied Retry-After when present.
        let delay = computeDelay(attempt, cfg, state.seed);
        if (isExplorerError(err) && err.type === 'rate_limited' && err.retryAfterMs !== undefined) {
          delay = Math.max(delay, err.retryAfterMs);
        }
        attempt++;
        if (req.opts?.signal?.aborted) throw err;
        await sleepCancellable(delay, req.opts?.signal);
      }
    }
  },
};

function sleepCancellable(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(t);
        reject(new DOMException('aborted', 'AbortError'));
      },
      { once: true },
    );
  });
}
