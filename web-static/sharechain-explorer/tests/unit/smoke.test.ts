// Smoke test covering the Phase A contract:
//   register → init → emit → transport-via-middleware → destroy fence.
// Runs under `node --test --import tsx`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Host,
  registerBaseline,
  validate,
  satisfiesSdk,
  resolveOrder,
  applyMiddleware,
  SDK_VERSION,
  type PluginDescriptor,
  type Transport,
} from '../../src/index.js';

function mockTransport(): Transport {
  return {
    kind: 'demo',
    fetchWindow:         async () => ({ shares: [] }),
    fetchTip:            async () => ({ hash: 'aaaaaaaaaaaaaaaa', height: 1 }),
    fetchDelta:          async () => ({ shares: [], count: 0 }),
    fetchStats:          async () => ({ chain_height: 1 }),
    fetchShareDetail:    async () => ({}),
    negotiate:           async () => ({ apiVersion: '1.0' }),
    fetchCurrentPayouts: async () => ({ miners: [] }),
    fetchMinerDetail:    async () => ({}),
    subscribeStream:     () => ({ unsubscribe: () => {} }),
  };
}

test('SDK version exposed', () => {
  assert.equal(typeof SDK_VERSION, 'string');
  assert.match(SDK_VERSION, /^\d+\.\d+\.\d+$/);
});

test('satisfiesSdk: caret range', () => {
  assert.equal(satisfiesSdk('^1.0', '1.0.0'), true);
  assert.equal(satisfiesSdk('^1.0', '1.2.3'), true);
  assert.equal(satisfiesSdk('^1.0', '2.0.0'), false);
  assert.equal(satisfiesSdk('^1.0', '0.9.0'), false);
});

test('resolveOrder: topological sort', () => {
  const a: PluginDescriptor = { id: 'a', version: '1', sdk: '^1.0', kind: 'util', dependencies: ['b'] };
  const b: PluginDescriptor = { id: 'b', version: '1', sdk: '^1.0', kind: 'util' };
  const order = resolveOrder([a, b]);
  assert.equal(order[0]?.id, 'b');
  assert.equal(order[1]?.id, 'a');
});

test('resolveOrder: missing hard dep throws', () => {
  const a: PluginDescriptor = { id: 'a', version: '1', sdk: '^1.0', kind: 'util', dependencies: ['missing'] };
  assert.throws(() => resolveOrder([a]), /missing dep/);
});

test('resolveOrder: circular dep throws', () => {
  const a: PluginDescriptor = { id: 'a', version: '1', sdk: '^1.0', kind: 'util', dependencies: ['b'] };
  const b: PluginDescriptor = { id: 'b', version: '1', sdk: '^1.0', kind: 'util', dependencies: ['a'] };
  assert.throws(() => resolveOrder([a, b]), /circular/);
});

test('schema validator: happy path', () => {
  const r = validate(
    { h: 'abc', p: 0, v: 1 },
    { type: 'object', required: ['h', 'p', 'v'],
      properties: { h: { type: 'string' }, p: { type: 'integer' }, v: { type: 'integer' } } },
  );
  assert.equal(r.valid, true);
  assert.deepEqual(r.errors, []);
});

test('schema validator: missing required key', () => {
  const r = validate(
    { h: 'abc' },
    { type: 'object', required: ['h', 'p'], properties: {} },
  );
  assert.equal(r.valid, false);
  assert.equal(r.errors[0]?.type, 'schema');
  assert.match(r.errors[0]?.message ?? '', /required key missing/);
});

test('schema validator: type mismatch', () => {
  const r = validate({ n: 'not a number' }, { type: 'object', properties: { n: { type: 'integer' } } });
  assert.equal(r.valid, false);
  assert.equal(r.errors[0]?.type, 'schema');
});

test('Host init → destroy lifecycle', async () => {
  const host = new Host('shared-core');
  registerBaseline(host);
  const events: string[] = [];
  host.events.on('host:init:complete', () => events.push('init'));
  host.events.on('host:destroy:complete', () => events.push('destroy'));

  await host.init({ kind: 'shared-core', transport: mockTransport() });
  assert.equal(host.destroyed, false);
  assert.equal(events.includes('init'), true);
  assert.notEqual(host.transport, undefined);

  await host.destroy();
  assert.equal(host.destroyed, true);
  assert.equal(events.includes('destroy'), true);
});

test('Host: capability resolution explicit wins over priority', async () => {
  const host = new Host('shared-core');
  host.registry.register({
    id: 'theme.a', version: '1', sdk: '^1.0', kind: 'theme',
    provides: ['theme.descriptor'], priority: 10,
  });
  host.registry.register({
    id: 'theme.b', version: '1', sdk: '^1.0', kind: 'theme',
    provides: ['theme.descriptor'], priority: 5,
  });

  await host.init({ kind: 'shared-core' });
  assert.equal(host.resolveCapability('theme.descriptor')?.id, 'theme.a');
  await host.destroy();

  const host2 = new Host('shared-core');
  host2.registry.register({
    id: 'theme.a', version: '1', sdk: '^1.0', kind: 'theme',
    provides: ['theme.descriptor'], priority: 10,
  });
  host2.registry.register({
    id: 'theme.b', version: '1', sdk: '^1.0', kind: 'theme',
    provides: ['theme.descriptor'], priority: 5,
  });
  await host2.init({ kind: 'shared-core', capabilities: { 'theme.descriptor': 'theme.b' } });
  assert.equal(host2.resolveCapability('theme.descriptor')?.id, 'theme.b');
  await host2.destroy();
});

test('Middleware chain: error-taxonomy normalises thrown errors', async () => {
  const host = new Host('shared-core');
  registerBaseline(host);
  const angryTransport: Transport = {
    ...mockTransport(),
    fetchWindow: async () => { throw { status: 429, retryAfter: 2000 }; },
  };
  await host.init({ kind: 'shared-core', transport: angryTransport });
  const wrapped = host.transport!;
  await assert.rejects(
    async () => { await wrapped.fetchWindow(); },
    (err: unknown) => {
      if (typeof err !== 'object' || err === null) return false;
      const e = err as { type?: unknown; retryAfterMs?: unknown };
      return e.type === 'rate_limited' && e.retryAfterMs === 2000;
    },
  );
  await host.destroy();
});

test('destroy fence: second call is a no-op', async () => {
  const host = new Host('shared-core');
  await host.init({ kind: 'shared-core' });
  await host.destroy();
  await host.destroy();  // must not throw
  assert.equal(host.destroyed, true);
});
