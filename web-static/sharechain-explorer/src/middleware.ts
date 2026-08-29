// Transport middleware chain (plugin-arch §7).
// Express-style: each middleware wraps the next. Resolved once at init
// into a static call chain; no dynamic dispatch at request time.

import type { RequestOptions, Transport, TransportOp } from './transport/types.js';

export interface MiddlewareRequest {
  op: TransportOp;
  args: readonly unknown[];
  opts?: RequestOptions | undefined;
}

export type Next = (req: MiddlewareRequest) => Promise<unknown>;

export interface TransportMiddleware {
  readonly id: string;
  request(req: MiddlewareRequest, next: Next): Promise<unknown>;
}

/**
 * Build a static call chain: outer → ... → inner → transport.
 * Middleware are applied in declared order; the first registered is
 * the OUTERMOST (sees request first, sees response last).
 */
export function buildChain(transport: Transport, middleware: TransportMiddleware[]): Next {
  const terminal: Next = async (req) => {
    const method = (transport as unknown as Record<string, unknown>)[req.op];
    if (typeof method !== 'function') {
      throw new Error(`Transport missing op: ${req.op}`);
    }
    return (method as (...a: unknown[]) => Promise<unknown>).apply(transport, [
      ...req.args,
      req.opts,
    ]);
  };

  // Apply from innermost to outermost so outer middleware is called first.
  let chain: Next = terminal;
  for (let i = middleware.length - 1; i >= 0; i--) {
    const mw = middleware[i];
    if (!mw) continue;
    const downstream = chain;
    chain = (req) => mw.request(req, downstream);
  }
  return chain;
}

/**
 * Wrap a Transport so calls go through the middleware chain.
 * Returned value implements the Transport interface.
 */
export function applyMiddleware(
  transport: Transport,
  middleware: TransportMiddleware[],
): Transport {
  const chain = buildChain(transport, middleware);
  const call = (op: TransportOp, args: readonly unknown[], opts?: RequestOptions) =>
    chain({ op, args, opts });

  return {
    kind: transport.kind,
    fetchWindow: (o) => call('fetchWindow', [], o),
    fetchTip: (o) => call('fetchTip', [], o),
    fetchDelta: (since, o) => call('fetchDelta', [since], o),
    fetchStats: (o) => call('fetchStats', [], o),
    fetchShareDetail: (h, o) => call('fetchShareDetail', [h], o),
    negotiate: (o) => call('negotiate', [], o) as Promise<{ apiVersion: string }>,
    fetchCurrentPayouts: (o) => call('fetchCurrentPayouts', [], o),
    fetchMinerDetail: (a, o) => call('fetchMinerDetail', [a], o),
    subscribeStream: transport.subscribeStream.bind(transport),
  };
}
