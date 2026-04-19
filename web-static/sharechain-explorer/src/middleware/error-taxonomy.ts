// core.transport.error-taxonomy — normalises thrown Transport errors
// into the structured ExplorerError shape (M1 D3, delta v1 §A.5).
// Proof-of-shape middleware for Phase A first commit; outermost in the
// default chain so every downstream middleware's errors get normalised.

import type { PluginDescriptor } from '../registry.js';
import { isExplorerError, type ExplorerError } from '../errors.js';

export const ErrorTaxonomyMiddleware: PluginDescriptor = {
  id: 'core.transport.error-taxonomy',
  version: '1.0.0',
  sdk: '^1.0',
  kind: 'middleware',
  middlewareOf: 'transport',
  priority: 100,  // outermost

  async request(req, next) {
    try {
      return await next(req);
    } catch (err) {
      if (isExplorerError(err)) throw err;
      // AbortError is a legitimate cancellation, not a transport fault
      if (isAbortError(err)) {
        const mapped: ExplorerError = {
          type: 'transport',
          message: 'request aborted',
          cause: err,
        };
        throw mapped;
      }
      // HTTP-shaped error with status?
      if (err && typeof err === 'object' && 'status' in err) {
        const status = Number((err as { status: unknown }).status);
        if (status === 429) {
          const retryAfter = (err as { retryAfter?: number }).retryAfter;
          const mapped: ExplorerError = retryAfter !== undefined
            ? { type: 'rate_limited', message: `rate limited on ${req.op}`, retryAfterMs: retryAfter }
            : { type: 'rate_limited', message: `rate limited on ${req.op}` };
          throw mapped;
        }
        const mapped: ExplorerError = {
          type: 'transport',
          message: `HTTP ${status} on ${req.op}`,
          status,
          cause: err,
        };
        throw mapped;
      }
      const mapped: ExplorerError = {
        type: 'transport',
        message: `${req.op} failed`,
        cause: err,
      };
      throw mapped;
    }
  },
};

function isAbortError(err: unknown): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'name' in err &&
    (err as { name: unknown }).name === 'AbortError'
  );
}
