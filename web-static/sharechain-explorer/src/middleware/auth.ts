// core.transport.auth — injects Authorization header via a configurable
// factory. Per-request fresh lookup so rotating tokens work.
// Operates by extending opts.headers; HttpTransport merges those in.

import type { PluginDescriptor } from '../registry.js';

export interface AuthConfig {
  /** Literal header value, or an async factory returning the value.
   *  Return empty string to skip injection. */
  tokenFactory: (() => Promise<string>) | string | null;
  /** Override the header name (default: Authorization). */
  headerName: string;
}

const DEFAULTS: AuthConfig = Object.freeze({
  tokenFactory: null,
  headerName: 'Authorization',
});

const state: { config: AuthConfig } = { config: { ...DEFAULTS } };

export const AuthMiddleware: PluginDescriptor = {
  id: 'core.transport.auth',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'middleware',
  middlewareOf: 'transport',
  priority: 90,  // between logging (outer) and retry (inner); runs once, not per-retry
  defaultConfig: DEFAULTS,

  async init(_host, config) {
    state.config = { ...DEFAULTS, ...(config as Partial<AuthConfig>) };
  },

  async request(req, next) {
    const factory = state.config.tokenFactory;
    if (factory === null) return next(req);
    const token = typeof factory === 'string' ? factory : await factory();
    if (!token) return next(req);
    const opts = {
      ...(req.opts ?? {}),
      headers: { ...(req.opts?.headers ?? {}), [state.config.headerName]: token },
    };
    return next({ ...req, opts });
  },
};
