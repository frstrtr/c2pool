// core.transport.timeout — per-request deadline via AbortController.
// Composes with upstream AbortSignal from the caller (destroy-fence,
// explicit cancellation) via AbortSignal.any-style merging; if the
// deadline hits first, the rejection is a structured 'transport' error
// with `cause: AbortError`. Default 30 s; opt in per-op via config.

import type { PluginDescriptor } from '../registry.js';
import type { TransportOp } from '../transport/types.js';

export interface TimeoutConfig {
  /** Default per-op timeout in ms (0 disables). */
  defaultMs: number;
  /** Per-op override; 0 disables. */
  byOp: Partial<Record<TransportOp, number>>;
}

const DEFAULTS: TimeoutConfig = Object.freeze({
  defaultMs: 30_000,
  byOp: {},
});

const state: { config: TimeoutConfig } = { config: { ...DEFAULTS } };

function mergeSignals(a?: AbortSignal, b?: AbortSignal): AbortSignal | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  const ctrl = new AbortController();
  const onAbort = () => ctrl.abort();
  if (a.aborted || b.aborted) {
    ctrl.abort();
  } else {
    a.addEventListener('abort', onAbort, { once: true });
    b.addEventListener('abort', onAbort, { once: true });
  }
  return ctrl.signal;
}

export const TimeoutMiddleware: PluginDescriptor = {
  id: 'core.transport.timeout',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'middleware',
  middlewareOf: 'transport',
  priority: 60,  // inner of cache, outer of error-taxonomy
  defaultConfig: DEFAULTS,

  async init(_host, config) {
    state.config = { ...DEFAULTS, ...(config as Partial<TimeoutConfig>) };
  },

  async request(req, next) {
    const ms = state.config.byOp[req.op] ?? state.config.defaultMs;
    if (ms <= 0) return next(req);

    const deadlineCtrl = new AbortController();
    const timer = setTimeout(() => deadlineCtrl.abort(), ms);
    const merged = mergeSignals(req.opts?.signal, deadlineCtrl.signal);
    const newReq = {
      ...req,
      opts: { ...(req.opts ?? {}), ...(merged !== undefined ? { signal: merged } : {}) },
    };
    try {
      return await next(newReq);
    } finally {
      clearTimeout(timer);
    }
  },
};
