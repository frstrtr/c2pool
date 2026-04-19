// Tests for Phase B #10 stat panel emission — RealtimeState.stats.
// Verifies counting branches match the inline dashboard.html
// computations and that metadata from /sharechain/window +
// /sharechain/delta passes through cleanly.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  RealtimeOrchestrator,
  type ShareForClassify,
  type Transport,
  type TipEvent,
  type ExplorerError,
} from '../../src/explorer/index.js';

interface MockTransport extends Transport {
  fireTip(ev: TipEvent): void;
}

function sh(h: string, over: Partial<ShareForClassify> = {}): ShareForClassify {
  return { s: 0, v: 1, V: 36, dv: 36, m: 'Xother', ...over, h } as unknown as ShareForClassify;
}

function makeTransport(payload: Record<string, unknown>): MockTransport {
  const subs: Array<{ onTip: (ev: TipEvent) => void; onRec?: () => void }> = [];
  return {
    kind: 'demo',
    fetchWindow: async () => payload,
    fetchTip: async () => ({ hash: 'xxxxxxxxxxxxxxxx', height: 1 }),
    fetchDelta: async () => ({ shares: [] }),
    fetchStats: async () => ({}),
    fetchShareDetail: async () => ({}),
    negotiate: async () => ({ apiVersion: '1.0' }),
    fetchCurrentPayouts: async () => ({ miners: [] }),
    fetchMinerDetail: async () => ({}),
    subscribeStream(onTip, _onErr?: (err: ExplorerError) => void, onRec?: () => void) {
      const entry: typeof subs[number] = { onTip };
      if (onRec !== undefined) entry.onRec = onRec;
      subs.push(entry);
      return { unsubscribe() { subs.splice(subs.indexOf(entry), 1); } };
    },
    fireTip(ev) { for (const s of subs) s.onTip(ev); },
  };
}

const CTX = { myAddress: 'Xme', shareVersion: 36 };
const CW = () => 1000;

// ── Counting branches ────────────────────────────────────────────

test('stats: empty window → all zeros', async () => {
  const t = makeTransport({ shares: [] });
  const o = new RealtimeOrchestrator({ transport: t, userContext: CTX, containerWidth: CW });
  await o.start();
  const s = o.getState().stats;
  assert.equal(s.shares, 0);
  assert.equal(s.verified, 0);
  assert.equal(s.mine, 0);
  assert.equal(s.stale, 0);
  assert.equal(s.dead, 0);
  assert.equal(s.fee, 0);
  assert.equal(s.v36native, 0);
  assert.equal(s.v36signaling, 0);
  assert.equal(s.chainLength, null);
  assert.equal(s.primaryBlocks, 0);
  assert.equal(s.dogeBlocks, 0);
  await o.stop();
});

test('stats: classification priority (dead/stale/unverified/fee)', async () => {
  const t = makeTransport({
    shares: [
      sh('a', { s: 2 }),             // dead
      sh('b', { s: 1 }),             // stale
      sh('c', { v: 0 }),             // unverified
      sh('d', { fee: 1 }),           // fee
      sh('e'),                       // plain verified native
    ],
  });
  const o = new RealtimeOrchestrator({ transport: t, userContext: CTX, containerWidth: CW });
  await o.start();
  const s = o.getState().stats;
  assert.equal(s.shares, 5);
  assert.equal(s.dead, 1);
  assert.equal(s.stale, 1);
  // Note: dashboard's verified counts `share.v` directly, independent
  // of stale/dead. Dead+stale in our test have v=1 default, so verified
  // should be 4 (a, b, d, e — c has v=0).
  assert.equal(s.verified, 4);
  assert.equal(s.fee, 1);
  await o.stop();
});

test('stats: mine counts myAddress match only', async () => {
  const t = makeTransport({
    shares: [
      sh('a', { m: 'Xme' }),
      sh('b', { m: 'Xme' }),
      sh('c', { m: 'Xother' }),
    ],
  });
  const o = new RealtimeOrchestrator({ transport: t, userContext: CTX, containerWidth: CW });
  await o.start();
  const s = o.getState().stats;
  assert.equal(s.mine, 2);
  await o.stop();
});

test('stats: mine with empty myAddress is always 0', async () => {
  const t = makeTransport({ shares: [sh('a', { m: '' }), sh('b', { m: 'anything' })] });
  const o = new RealtimeOrchestrator({
    transport: t,
    userContext: { myAddress: '', shareVersion: 36 },
    containerWidth: CW,
  });
  await o.start();
  assert.equal(o.getState().stats.mine, 0);
  await o.stop();
});

test('stats: v36native and v36signaling', async () => {
  const t = makeTransport({
    shares: [
      sh('a', { V: 36, dv: 36 }),   // native
      sh('b', { V: 35, dv: 36 }),   // signaling
      sh('c', { V: 35, dv: 35 }),   // legacy only
      sh('d', { V: 37, dv: 37 }),   // still native (>=36)
    ],
  });
  const o = new RealtimeOrchestrator({ transport: t, userContext: CTX, containerWidth: CW });
  await o.start();
  const s = o.getState().stats;
  assert.equal(s.v36native, 2);
  assert.equal(s.v36signaling, 1);
  await o.stop();
});

test('stats: threshold adapts to different coin shareVersion', async () => {
  const t = makeTransport({
    shares: [
      sh('a', { V: 16, dv: 16 }),   // Dash V16 native
      sh('b', { V: 15, dv: 16 }),   // Dash signaling
      sh('c', { V: 15, dv: 15 }),   // Dash legacy
    ],
  });
  const o = new RealtimeOrchestrator({
    transport: t,
    userContext: { shareVersion: 16 },
    containerWidth: CW,
  });
  await o.start();
  const s = o.getState().stats;
  assert.equal(s.v36native, 1);
  assert.equal(s.v36signaling, 1);
  await o.stop();
});

// ── Metadata passthrough ─────────────────────────────────────────

test('stats: chainLength from /sharechain/window', async () => {
  const t = makeTransport({
    shares: [sh('a'), sh('b'), sh('c')],
    chain_length: 8640,
  });
  const o = new RealtimeOrchestrator({ transport: t, userContext: CTX, containerWidth: CW });
  await o.start();
  assert.equal(o.getState().stats.chainLength, 8640);
  await o.stop();
});

test('stats: primaryBlocks + dogeBlocks from /sharechain/window', async () => {
  const t = makeTransport({
    shares: [sh('a'), sh('b')],
    blocks: ['block-a'],
    doge_blocks: ['dog-a', 'dog-b'],
  });
  const o = new RealtimeOrchestrator({ transport: t, userContext: CTX, containerWidth: CW });
  await o.start();
  const s = o.getState().stats;
  assert.equal(s.primaryBlocks, 1);
  assert.equal(s.dogeBlocks, 2);
  await o.stop();
});

// ── Cache invalidation ───────────────────────────────────────────

test('stats: cached within same tip (object identity)', async () => {
  const t = makeTransport({ shares: [sh('a')] });
  const o = new RealtimeOrchestrator({ transport: t, userContext: CTX, containerWidth: CW });
  await o.start();
  const s1 = o.getState().stats;
  const s2 = o.getState().stats;
  assert.strictEqual(s1, s2);  // same object reference — cache hit
  await o.stop();
});

test('stats: recomputed after delta merge', async () => {
  const t = makeTransport({
    shares: [sh('a', { V: 35, dv: 35 })],  // legacy
  });
  // Override delta response to add a V36 native.
  t.fetchDelta = async () => ({ shares: [sh('n', { V: 36, dv: 36 })] });
  const o = new RealtimeOrchestrator({ transport: t, userContext: CTX, containerWidth: CW });
  await o.start();
  const before = o.getState().stats;
  assert.equal(before.v36native, 0);
  assert.equal(before.shares, 1);
  t.fireTip({ hash: 'n', height: 2 });
  for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
  const after = o.getState().stats;
  assert.equal(after.v36native, 1);
  assert.equal(after.shares, 2);
  assert.notStrictEqual(before, after);  // distinct cache entries
  await o.stop();
});
