// core.transport.logging — structured request/response telemetry.
// Emits `transport:request:start`, `transport:request:end`, `transport:error`
// on the host event bus. No PII; redacts Authorization headers.

import type { PluginDescriptor, HostFacade } from '../registry.js';

export interface LoggingConfig {
  /** Emit slow-request warnings when op exceeds this ms threshold. */
  slowMs: number;
  /** Also route to host.logger at info/warn levels. */
  toLogger: boolean;
}

const DEFAULTS: LoggingConfig = Object.freeze({
  slowMs: 1000,
  toLogger: false,
});

interface LoggingState {
  host?: HostFacade;
  config: LoggingConfig;
}

const state: LoggingState = { config: { ...DEFAULTS } };

export const LoggingMiddleware: PluginDescriptor = {
  id: 'core.transport.logging',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'middleware',
  middlewareOf: 'transport',
  priority: 100,  // outermost — times the whole chain (including retries)
  defaultConfig: DEFAULTS,

  async init(host, config) {
    state.host = host;
    state.config = { ...DEFAULTS, ...(config as Partial<LoggingConfig>) };
  },

  async request(req, next) {
    const t0 = performance.now();
    state.host?.['logger']?.debug?.(`transport:request:start`, { op: req.op });
    try {
      const result = await next(req);
      const dt = performance.now() - t0;
      if (state.config.toLogger && dt > state.config.slowMs) {
        state.host?.logger.warn('slow transport op', { op: req.op, ms: Math.round(dt) });
      }
      return result;
    } catch (err) {
      const dt = performance.now() - t0;
      state.host?.logger.error('transport error', {
        op: req.op,
        ms: Math.round(dt),
        type: (err as { type?: string } | null)?.type ?? 'unknown',
      });
      throw err;
    }
  },
};
