// Unit tests for baseline Transport middleware.
//   - auth (header injection)
//   - retry (backoff + transient detection; short base ms for tests)
//   - cache (TTL-based op response cache)
//   - timeout (deadline-driven abort)
// error-taxonomy is covered in smoke.test.ts.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Host,
  AuthMiddleware,
  RetryMiddleware,
  CacheMiddleware,
  TimeoutMiddleware,
  ErrorTaxonomyMiddleware,
  type Transport,
} from '../../src/index.js';

function baseTransport(overrides: Partial<Transport> = {}): Transport {
  return {
    kind: 'demo',
    fetchWindow:         async () => ({ shares: [] }),
    fetchTip:            async () => ({ hash: 'a'.repeat(16), height: 1 }),
    fetchDelta:          async () => ({ shares: [], count: 0 }),
    fetchStats:          async () => ({ chain_height: 1 }),
    fetchShareDetail:    async () => ({}),
    negotiate:           async () => ({ apiVersion: '1.0' }),
    fetchCurrentPayouts: async () => ({ miners: [] }),
    fetchMinerDetail:    async () => ({}),
    subscribeStream:     () => ({ unsubscribe: () => {} }),
    ...overrides,
  };
}

// ── auth ─────────────────────────────────────────────────────────
test('AuthMiddleware: injects header via factory', async () => {
  let seenAuth: string | undefined;
  const transport = baseTransport({
    fetchTip: async (opts) => {
      seenAuth = opts?.headers?.['Authorization'];
      return { hash: 'b'.repeat(16), height: 1 };
    },
  });

  const host = new Host('shared-core');
  host.registry.register(AuthMiddleware);
  await host.init({
    kind: 'shared-core',
    transport,
    plugins: { 'core.transport.auth': { tokenFactory: 'Bearer xyz' } },
  });
  await host.transport!.fetchTip();
  assert.equal(seenAuth, 'Bearer xyz');
  await host.destroy();
});

test('AuthMiddleware: null factory leaves headers alone', async () => {
  let seenAuth: string | undefined;
  const transport = baseTransport({
    fetchTip: async (opts) => {
      seenAuth = opts?.headers?.['Authorization'];
      return { hash: 'c'.repeat(16), height: 1 };
    },
  });
  const host = new Host('shared-core');
  host.registry.register(AuthMiddleware);
  await host.init({ kind: 'shared-core', transport });
  await host.transport!.fetchTip();
  assert.equal(seenAuth, undefined);
  await host.destroy();
});

// ── retry ────────────────────────────────────────────────────────
test('RetryMiddleware: retries transient then succeeds', async () => {
  let attempts = 0;
  const transport = baseTransport({
    fetchTip: async () => {
      attempts++;
      if (attempts < 3) throw { status: 503, message: 'boom' };
      return { hash: 'd'.repeat(16), height: 1 };
    },
  });
  const host = new Host('shared-core');
  host.registry.register(RetryMiddleware);
  host.registry.register(ErrorTaxonomyMiddleware);  // needed to tag as transport
  await host.init({
    kind: 'shared-core',
    transport,
    plugins: { 'core.transport.retry': { baseMs: 1, capMs: 5, multiplier: 2, jitterPct: 0, maxAttempts: 0 } },
  });
  const r = await host.transport!.fetchTip();
  assert.equal(attempts, 3);
  assert.ok(r);
  await host.destroy();
});

test('RetryMiddleware: does not retry 4xx', async () => {
  let attempts = 0;
  const transport = baseTransport({
    fetchTip: async () => {
      attempts++;
      throw { status: 404, message: 'nope' };
    },
  });
  const host = new Host('shared-core');
  host.registry.register(RetryMiddleware);
  host.registry.register(ErrorTaxonomyMiddleware);
  await host.init({
    kind: 'shared-core',
    transport,
    plugins: { 'core.transport.retry': { baseMs: 1, capMs: 5, multiplier: 2, jitterPct: 0, maxAttempts: 5 } },
  });
  await assert.rejects(async () => { await host.transport!.fetchTip(); });
  assert.equal(attempts, 1);
  await host.destroy();
});

test('RetryMiddleware: respects maxAttempts', async () => {
  let attempts = 0;
  const transport = baseTransport({
    fetchTip: async () => {
      attempts++;
      throw { status: 503, message: 'boom' };
    },
  });
  const host = new Host('shared-core');
  host.registry.register(RetryMiddleware);
  host.registry.register(ErrorTaxonomyMiddleware);
  await host.init({
    kind: 'shared-core',
    transport,
    plugins: { 'core.transport.retry': { baseMs: 1, capMs: 5, multiplier: 2, jitterPct: 0, maxAttempts: 3 } },
  });
  await assert.rejects(async () => { await host.transport!.fetchTip(); });
  assert.equal(attempts, 4);  // initial + 3 retries
  await host.destroy();
});

// ── cache ────────────────────────────────────────────────────────
test('CacheMiddleware: hits within TTL', async () => {
  let calls = 0;
  const transport = baseTransport({
    fetchStats: async () => {
      calls++;
      return { chain_height: calls };
    },
  });
  const host = new Host('shared-core');
  host.registry.register(CacheMiddleware);
  await host.init({
    kind: 'shared-core',
    transport,
    plugins: { 'core.transport.cache': { ttlByOp: { fetchStats: 1000 } } },
  });
  const a = await host.transport!.fetchStats() as { chain_height: number };
  const b = await host.transport!.fetchStats() as { chain_height: number };
  assert.equal(calls, 1);
  assert.equal(a.chain_height, 1);
  assert.equal(b.chain_height, 1);
  await host.destroy();
});

test('CacheMiddleware: 0 TTL disables per-op', async () => {
  let calls = 0;
  const transport = baseTransport({
    fetchTip: async () => {
      calls++;
      return { hash: 'e'.repeat(16), height: calls };
    },
  });
  const host = new Host('shared-core');
  host.registry.register(CacheMiddleware);
  await host.init({ kind: 'shared-core', transport });
  await host.transport!.fetchTip();
  await host.transport!.fetchTip();
  assert.equal(calls, 2);  // no caching for fetchTip by default
  await host.destroy();
});

// ── timeout ──────────────────────────────────────────────────────
test('TimeoutMiddleware: aborts slow request', async () => {
  const transport = baseTransport({
    fetchWindow: async (opts) =>
      new Promise((resolve, reject) => {
        const t = setTimeout(() => resolve({ shares: [] }), 1000);
        opts?.signal?.addEventListener('abort', () => {
          clearTimeout(t);
          reject(new DOMException('aborted', 'AbortError'));
        });
      }),
  });
  const host = new Host('shared-core');
  host.registry.register(TimeoutMiddleware);
  host.registry.register(ErrorTaxonomyMiddleware);
  await host.init({
    kind: 'shared-core',
    transport,
    plugins: { 'core.transport.timeout': { defaultMs: 10, byOp: {} } },
  });
  await assert.rejects(
    async () => { await host.transport!.fetchWindow(); },
    (err: unknown) => (err as { type?: string } | null)?.type === 'transport',
  );
  await host.destroy();
});

test('TimeoutMiddleware: 0 disables', async () => {
  const transport = baseTransport();
  const host = new Host('shared-core');
  host.registry.register(TimeoutMiddleware);
  await host.init({
    kind: 'shared-core',
    transport,
    plugins: { 'core.transport.timeout': { defaultMs: 0, byOp: {} } },
  });
  const r = await host.transport!.fetchWindow();
  assert.ok(r);
  await host.destroy();
});

// ── chain composition (priority ordering) ───────────────────────
test('Middleware chain: priority orders outer to inner', async () => {
  const order: string[] = [];

  const transport = baseTransport({
    fetchTip: async () => {
      order.push('terminal');
      return { hash: 'f'.repeat(16), height: 1 };
    },
  });

  // Two custom middlewares with explicit priorities.
  const outer = {
    id: 'test.outer',
    version: '1',
    sdk: '^1.0',
    kind: 'middleware' as const,
    middlewareOf: 'transport' as const,
    priority: 100,
    async request(req: unknown, next: (r: unknown) => Promise<unknown>) {
      order.push('outer-before');
      const r = await next(req);
      order.push('outer-after');
      return r;
    },
  };
  const inner = {
    id: 'test.inner',
    version: '1',
    sdk: '^1.0',
    kind: 'middleware' as const,
    middlewareOf: 'transport' as const,
    priority: 50,
    async request(req: unknown, next: (r: unknown) => Promise<unknown>) {
      order.push('inner-before');
      const r = await next(req);
      order.push('inner-after');
      return r;
    },
  };

  const host = new Host('shared-core');
  // register inner first to prove order follows priority, not registration
  host.registry.register(inner);
  host.registry.register(outer);
  await host.init({ kind: 'shared-core', transport });
  await host.transport!.fetchTip();
  await host.destroy();

  assert.deepEqual(order, [
    'outer-before', 'inner-before', 'terminal', 'inner-after', 'outer-after',
  ]);
});
